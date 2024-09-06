/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
/**
 * The PVAccess Certificate Management Service.
 *
 *   pvacms
 *
 */

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <list>
#include <memory>
#include <thread>

#include <epicsGetopt.h>
#include <epicsThread.h>
#include <epicsTime.h>
#include <epicsVersion.h>

#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <pvxs/client.h>
#include <pvxs/config.h>
#include <pvxs/log.h>
#include <pvxs/nt.h>

#include "ownedptr.h"
#include "p12filefactory.h"
#include "pvacms.h"

using namespace pvxs;

#define DEFAULT_PORT "8080"

namespace {

typedef std::shared_ptr<client::Config> ConfigPtr;  // aliasing for simplicity.

// A function that returns shared_ptr<Config> instance.
ConfigPtr clientConfig(client::Config *inital_ptr = nullptr) {
    static ConfigPtr config_ptr(inital_ptr);
    return config_ptr;
}

/**
 * @brief Prints the usage message for the program.
 *
 * This function prints the usage message for the program, including
 * the available command line options and their descriptions.
 *
 * @param argv0 The name of the program (usually argv[0]).
 */
void usage(const char *argv0) {
    std::cerr << "Usage: " << argv0
              << " <opts> \n"
                 "\n"
                 "  -h                  Show this message.\n"
                 "  -V                  Print version and exit.\n"
                 "  -v                  Make more noise.\n"
                 "  -p <port>           Specify port to listen on\n";
}

/**
 * @brief Reads command line options and sets corresponding variables.
 *
 * This function reads the command line options provided by the user and
 * sets the corresponding variables. The options include verbose mode,
 * and port.
 *
 * @param argc The number of command line arguments.
 * @param argv The array of command line arguments.
 * @param verbose Reference to a boolean variable to enable verbose mode.
 * @param port The string variable to store the P12 file location.
 * @return 0 if successful, 1 if successful but need to exit immediately on
 * return, >1 if there is any error.
 */
int readOptions(int argc, char *argv[], bool &verbose, std::string &port) {
    int opt;
    while ((opt = getopt(argc, argv, "hVvp:")) != -1) {
        switch (opt) {
            case 'h':
                usage(argv[0]);
                return 1;
            case 'V':
                std::cout << version_information;
                return 1;
            case 'v':
                verbose = true;
                break;
            case 'p':
                port = optarg;
                break;
            default:
                usage(argv[0]);
                std::cerr << "\nUnknown argument: " << char(opt) << std::endl;
                return 2;
        }
    }
    return 0;
}

bool getCertificateStatus(client::Context &pva_client, const uint64_t serial, CertStatus &status) {
    std::string pvacms_uri = GET_CERT_STATUS;
    std::size_t pos = pvacms_uri.find('*');

    if (pos != std::string::npos) {
        std::string str_serial = std::to_string(serial);
        pvacms_uri.replace(pos, 1, str_serial);
    }

    // Build and start network operation
    auto operation = pva_client.get(pvacms_uri).exec();

    // wait for it to complete, for up to 5 seconds.
    Value result = operation->wait(3.0);

    status = result["value"].as<CertStatus>();
    return true;
}

int ocspService(client::Context &pva_client, std::string &port, bool verbose) {
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_ciphers();

    auto config = clientConfig().get();
    auto cert_filename = config->tls_cert_filename;
    auto cert_password = config->tls_cert_password;

    auto key_chain_data = security::KeychainFactory::getKeychainDataFromKeychainFile(cert_filename, cert_password);
    const ossl_ptr<EVP_PKEY> ca_pkey(std::move(key_chain_data.pkey));
    const ossl_ptr<X509> ca_cert(std::move(key_chain_data.cert));
    const ossl_ptr<EVP_PKEY> ca_pub_key(X509_get_pubkey(ca_cert.get()));
    const ossl_shared_ptr<STACK_OF(X509)> ca_chain(key_chain_data.ca);

    ossl_ptr<SSL_CTX> ctx(SSL_CTX_new(TLS_server_method()));

    // Listen on port
    ossl_ptr_all<BIO> bio_acc(BIO_new_accept(port.c_str()));
    if (BIO_do_accept(bio_acc.get()) <= 0) {
        throw std::runtime_error(SB() << "Error setting up accept BIO for OCSP");
    }

    while (true) {
        if (BIO_do_accept(bio_acc.get()) <= 0) {
            std::cerr << "Error accepting connection" << std::endl;
            continue;
        }

        BIO *bio = BIO_pop(bio_acc.get());
        ossl_ptr<SSL> ssl(SSL_new(ctx.get()));
        SSL_set_bio(ssl.get(), bio, bio);

        if (SSL_accept(ssl.get()) <= 0) {
            std::cerr << "Error accepting SSL connection" << std::endl;
            ssl.release();
            continue;
        }

        ossl_ptr<OCSP_REQUEST> ocsp_req(d2i_OCSP_REQUEST_bio(SSL_get_rbio(ssl.get()), nullptr));
        if (ocsp_req == nullptr) {
            std::cerr << "Error reading OCSP request" << std::endl;
            ssl.release();
            continue;
        }

        ossl_ptr<OCSP_RESPONSE> ocsp_resp(OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, nullptr));
        ossl_ptr<OCSP_BASICRESP> basic_resp(OCSP_BASICRESP_new());

        for (auto i = 0; i < OCSP_request_onereq_count(ocsp_req.get()); i++) {
            OCSP_ONEREQ *one_req = OCSP_request_onereq_get0(ocsp_req.get(), i);
            OCSP_CERTID *cert_id = OCSP_onereq_get0_id(one_req);
            ASN1_INTEGER *asn1_serial = nullptr;
            OCSP_id_get0_info(nullptr, nullptr, nullptr, &asn1_serial, cert_id);
            BIGNUM *big_number = ASN1_INTEGER_to_BN(asn1_serial, nullptr);
            ossl_ptr<char> hex_serial(BN_bn2hex(big_number));
            uint64_t serial = std::strtoull(hex_serial.get(), nullptr, 16);
            BN_free(big_number);

            CertStatus status;
            if (getCertificateStatus(pva_client, serial, status)) {
                int ocsp_status;
                switch (status) {
                    case VALID:
                        ocsp_status = V_OCSP_CERTSTATUS_GOOD;
                        break;
                    case EXPIRED:
                    case REVOKED:
                        ocsp_status = V_OCSP_CERTSTATUS_REVOKED;
                        break;
                    default:
                        ocsp_status = V_OCSP_CERTSTATUS_UNKNOWN;
                        break;
                }

                ASN1_TIME *revocation_time = ASN1_TIME_new();
                X509_gmtime_adj(revocation_time, 0);

                OCSP_basic_add1_status(basic_resp.get(), cert_id, ocsp_status, OCSP_REVOKED_STATUS_NOSTATUS, revocation_time, nullptr, nullptr);
                ASN1_TIME_free(revocation_time);
            }

            OCSP_copy_nonce(basic_resp.get(), ocsp_req.get());
            OCSP_basic_sign(basic_resp.get(), ca_cert.get(), ca_pkey.get(), EVP_sha256(), ca_chain.get(), 0);
            ocsp_resp.reset(OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic_resp.get()));

            BIO *bio_resp = BIO_new(BIO_s_mem());
            i2d_OCSP_RESPONSE_bio(bio_resp, ocsp_resp.get());
            int len = BIO_pending(bio_resp);
            char *resp_data = new char[len];
            BIO_read(bio_resp, resp_data, len);

            SSL_write(ssl.get(), resp_data, len);

            delete[] resp_data;
            SSL_shutdown(ssl.get());
        }
    }
    return 0;
}

}  // namespace

int main(int argc, char *argv[]) {
    try {
        logger_config_env();  // Logger config from environment
        bool verbose = false;
        std::string port = DEFAULT_PORT;

        // Read commandline options
        int exit_status;
        if ((exit_status = readOptions(argc, argv, verbose, port))) {
            return exit_status - 1;
        }

        auto pva_client(client::Context::fromEnv());
        auto config = pva_client.config();
        config.config_target = client::Config::OCSPPVA;
        clientConfig(&config);

        if (verbose) std::cout << "Effective config\n" << config;
        std::cout << "\nPVA OCSP Server Ready\n";

        ocspService(pva_client, port, verbose);

        std::cout << "Done\n";

        return 0;
    } catch (std::exception &e) {
        std::cerr << "OCSP-PVA Error: " << e.what() << "\n";
        return 1;
    }
}
