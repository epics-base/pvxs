#include <iostream>
#include <thread>
#include <string>
#include <cstring>
#include <unordered_map>
#include <mutex>
#include <condition_variable>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <functional>
#include <vector>
#include <sys/socket.h>
#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

// Thread safety
std::mutex mtx;
std::condition_variable cv;
std::string data_value = "Initial Value"; // Initial value to be displayed

size_t write_callback(void *contents, size_t size, size_t nmemb, std::string *s) {
    size_t new_length = size * nmemb;
    try {
        s->append((char *)contents, new_length);
    } catch (std::bad_alloc &e) {
        return 0;
    }
    return new_length;
}

// Helper function to extract POST data from the request
std::unordered_map<std::string, std::string> parse_post_data(const std::string &request) {
    std::unordered_map<std::string, std::string> post_data;
    auto pos = request.find("\r\n\r\n");
    if (pos != std::string::npos) {
        std::string body = request.substr(pos + 4);
        std::istringstream body_stream(body);
        std::string kv;
        while (std::getline(body_stream, kv, '&')) {
            auto delimiter_pos = kv.find('=');
            if (delimiter_pos != std::string::npos) {
                std::string key = kv.substr(0, delimiter_pos);
                std::string value = kv.substr(delimiter_pos + 1);
                post_data[key] = value;
            }
        }
    }
    return post_data;
}

// Helper function to extract cookies from the request
std::unordered_map<std::string, std::string> parse_cookies(const std::string &request) {
    std::unordered_map<std::string, std::string> cookies;
    auto pos = request.find("Cookie: ");
    if (pos != std::string::npos) {
        std::string cookie_str = request.substr(pos + 8);
        cookie_str = cookie_str.substr(0, cookie_str.find("\r\n"));
        std::istringstream cookie_stream(cookie_str);
        std::string kv;
        while (std::getline(cookie_stream, kv, ';')) {
            auto delimiter_pos = kv.find('=');
            if (delimiter_pos != std::string::npos) {
                std::string key = kv.substr(0, delimiter_pos);
                std::string value = kv.substr(delimiter_pos + 1);
                cookies[key] = value;
            }
        }
    }
    return cookies;
}

std::string base64_encode(const std::string &in) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;

    b64 = BIO_new(BIO_f_base64());    // Create a base64 filter
    bio = BIO_new(BIO_s_mem());       // Create a memory BIO
    BIO_push(b64, bio);               // Chain them
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  // No newline breaks
    BIO_write(b64, in.data(), in.size());        // Write the input string
    BIO_flush(b64);                    // Ensure all data is written
    BIO_get_mem_ptr(b64, &buffer_ptr); // Get the output buffer

    std::string out(buffer_ptr->data, buffer_ptr->length);  // Create a string from the buffer

    BIO_free_all(b64);   // Free the BIOs

    return out;
}

// Function to send the new token to another process
void send_token_to_another_process(const std::string &token) {
    CURL *curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        std::ostringstream post_fields;
        post_fields << "token=" << curl_easy_escape(curl, token.c_str(), token.length());

        curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8080/token");
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields.str().c_str());

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            std::cerr << "Token update failed: " << curl_easy_strerror(res) << std::endl;
        }

        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
}

// Function to perform a POST request to login and retrieve the token
std::string retrieve_token(const std::string &username, const std::string &password) {
    std::string token;
    CURL *curl;
    CURLcode res;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        std::string read_buffer;
        std::string encoded_password = base64_encode(password);
        std::string url = "http://127.0.0.1:5000/?user=" + username + "&pass=" + encoded_password;

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &read_buffer);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        } else {
            std::size_t pos = read_buffer.find("\"token\":\"");
            if (pos != std::string::npos) {
                pos += 9; // move past "token":"
                std::size_t end_pos = read_buffer.find("\"", pos);
                if (end_pos != std::string::npos) {
                    token = read_buffer.substr(pos, end_pos - pos);
                }
            }
        }
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();

    // Send the new token to the other process
    if (!token.empty()) {
        send_token_to_another_process(token);
    }

    return token;
}

// Function to validate the token by performing a GET request
bool validate_token(const std::string &token) {
    CURL *curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    bool is_valid = false;

    if (curl) {
        struct curl_slist *chunk = nullptr;
        std::string header = "Authorization: Bearer " + token;
        chunk = curl_slist_append(chunk, header.c_str());

        curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:5000/validate");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

        res = curl_easy_perform(curl);

        if (res == CURLE_OK) {
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

            if (http_code == 200) {
                is_valid = true;
            }
        } else {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        }
        curl_easy_cleanup(curl);
        curl_slist_free_all(chunk);
    }
    curl_global_cleanup();

    return is_valid;
}

// HTTP Response builder
std::string build_http_response(const std::string &body, const std::string &content_type = "text/html") {
    std::ostringstream oss;
    oss << "HTTP/1.1 200 OK\r\n";
    oss << "Content-Type: " << content_type << "\r\n";
    oss << "Content-Length: " << body.size() << "\r\n";
    oss << "Connection: close\r\n";
    oss << "\r\n";
    oss << body;
    return oss.str();
}

// Function to present the main page
void present_main_page(int port) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    while (true) {
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            close(server_fd);
            exit(EXIT_FAILURE);
        }

        char buffer[30000] = {0};
        read(new_socket, buffer, 30000);
        std::string request(buffer);

        if (request.find("GET /favicon.ico") != std::string::npos) {
            std::string response = build_http_response("", "image/x-icon");
            send(new_socket, response.c_str(), response.size(), 0);
            close(new_socket);
            continue;
        }

        if (request.find("GET / ") != std::string::npos) {
            // Present the main page based on the token validity
            std::string response_body;
            auto cookies = parse_cookies(request);
            std::string token = cookies["token"];

            if (!token.empty() && validate_token(token)) {
                response_body = R"(
                    <html>
                    <body>
                        <h1>Authenticated Page</h1>
                        <p>Value: <span id="valueField">)" + std::to_string(42) /* Example value, replace with actual dynamic value */ + R"(</span></p>
                        <script>
                            function fetchData() {
                                fetch("/")
                                .then(response => response.text())
                                .then(data => document.getElementById('valueField').innerText = data);
                            }
                            setInterval(fetchData, 5000);
                        </script>
                    </body>
                    </html>
                )";
            } else {
                // Token is invalid or not found, show login form
                response_body = R"(
                    <html>
                    <body>
                        <form action="/" method="post">
                            Username: <input type="text" name="username"><br>
                            Password: <input type="password" name="password"><br>
                            <input type="submit" value="Login">
                        </form>
                    </body>
                    </html>
                )";
            }

            std::string response = build_http_response(response_body);
            send(new_socket, response.c_str(), response.size(), 0);
        }
        else if (request.find("POST / ") != std::string::npos) {
            // Parse form data
            auto post_data = parse_post_data(request);
            std::string username = post_data["username"];
            std::string password = post_data["password"];

            // Process login and get token
            std::string token = retrieve_token(username, password);

            std::string response_body;
            if (!token.empty()) {
                response_body = R"(
                    <html>
                    <body>
                        <script>
                            document.cookie = 'token=)" + token + R"('; path=/';
                            window.location.reload();
                        </script>
                            <form action="/" method="post">
                                DATA: <input type="text" name="data" value="1020102" disabled><br>
                            </form>
                    </body>
                    </html>
                )";
            } else {
                response_body = "Login failed!";
            }

            std::string response = build_http_response(response_body);
            send(new_socket, response.c_str(), response.size(), 0);
        }
        else {
            std::string response = build_http_response("Unhandled request type");
            send(new_socket, response.c_str(), response.size(), 0);
        }

        close(new_socket);
    }
}

int main() {
    try {
        std::thread main_server_thread([]() { present_main_page(8081); });
        main_server_thread.join();
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
