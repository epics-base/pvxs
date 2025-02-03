/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "authnjwt.h"

#include <iostream>
#include <string>
#include <thread>
#include <cstring>
#include <netinet/in.h>
#include <unistd.h>

#include <pvxs/log.h>

#include "authregistry.h"

DEFINE_LOGGER(auth, "pvxs.auth.jwt");

namespace pvxs {
namespace certs {

struct AuthNJwtRegistrar {
    AuthNJwtRegistrar() { // NOLINT(*-use-equals-default)
        AuthRegistry::instance().registerAuth(PVXS_JWT_AUTH_TYPE, std::unique_ptr<Auth>(new AuthNJwt()));
    }
    // ReSharper disable once CppDeclaratorNeverUsed
} auth_n_jwt_registrar;

void handle_request(int client_socket) {
    char buffer[1024] = {0};
    read(client_socket, buffer, 1024);

    std::string request(buffer);
    log_info_printf(auth, "Received Request: %s\n", request.c_str());

    // Parse request to find the token
    std::string method = request.substr(0, request.find(" "));
    std::string uri = request.substr(request.find(" "), request.find("HTTP/1.1") - request.find(" "));

    if (method == "POST" && uri.find(TOKEN_ENDPOINT) != std::string::npos) {
        size_t token_pos = request.find("token=");
        if (token_pos != std::string::npos) {
            std::string token = request.substr(token_pos + 6); // Length of 'token=' is 6
            token = token.substr(0, token.find("&"));
            log_info_printf(auth, "Received Token: %s\n", token.c_str());

            std::string response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nToken received";
            send(client_socket, response.c_str(), response.size(), 0);
        } else {
            std::string response = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nMissing 'token' parameter";
            send(client_socket, response.c_str(), response.size(), 0);
        }
    } else {
        std::string response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nNot Found";
        send(client_socket, response.c_str(), response.size(), 0);
    }

    close(client_socket);
}

}  // namespace certs
}  // namespace pvxs

int main() {
    pvxs::ossl::SSLContext::sslInit();
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        log_err_printf(auth, "Socket Error: %s\n", "");
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port 8080
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        log_err_printf(auth, "Setsockopt Error: %s\n", "");
        perror("setsockopt");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(pvxs::certs::PORT);

    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        log_err_printf(auth, "Bind failure: %s\n", "");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        log_err_printf(auth, "Listen failure: %s\n", "");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    log_info_printf(auth, "Server listening on port: %d\n", pvxs::certs::PORT);

    while (true) {
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
            log_err_printf(auth, "Accept failure: %s\n", "");
            close(server_fd);
            exit(EXIT_FAILURE);
        }

        std::thread(pvxs::certs::handle_request, new_socket).detach();
    }

    return 0;
}
