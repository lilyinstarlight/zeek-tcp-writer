// See the file "COPYING" for copyright.
//
// Log writer for writing to TCP

#include <string>

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "TCP.h"

using namespace logging;
using namespace writer;

TCP::TCP(WriterFrontend * frontend) : WriterBackend(frontend), host((const char *)BifConst::LogTCP::host->Bytes(), BifConst::LogTCP::host->Len()), tcpport(BifConst::LogTCP::tcpport), tls(BifConst::LogTCP::tls), cert((const char *)BifConst::LogTCP::cert->Bytes(), BifConst::LogTCP::cert->Len()) {
    if (tls) {
        // add tls
        SSL_load_error_strings();
        SSL_library_init();
        OpenSSL_add_all_algorithms();
    }
}

TCP::~TCP() {
    if (tls) {
        // free tls
        ERR_free_strings();
        EVP_cleanup();
    }
}

string TCP::GetConfigValue(const WriterInfo & info, const string name) const {
    // find config value and return it or an empty string
    map<const char *, const char *>::const_iterator it = info.config.find(name.c_str());
    if (it == info.config.end())
        return string();
    else
        return it->second;
}

bool TCP::DoInit(const WriterInfo & info, int num_fields, const threading::Field * const * fields) {
    // error value
    int ret;
    long lret;

    // get configuration value
    string cfg_host = GetConfigValue(info, "host");
    string cfg_tcpport = GetConfigValue(info, "tcpport");
    string cfg_tls = GetConfigValue(info, "tls");
    string cfg_cert = GetConfigValue(info, "cert");

    // fill in non-empty values
    if (!cfg_host.empty())
        host = cfg_host;
    if (!cfg_tcpport.empty())
        tcpport = stoi(cfg_tcpport);
    if (!cfg_tls.empty())
        tls = cfg_tls == "T";
    if (!cfg_cert.empty())
        cert = cfg_cert;

    // prepare json formatter
    formatter = new threading::formatter::JSON(this, threading::formatter::JSON::TS_EPOCH);

    Info(Fmt("Sending JSON to TCP %s:%d%s", host.c_str(), tcpport, tls ? " (with TLS)" : ""));

    // get address info
    struct addrinfo * addr;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));

    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;

    ret = getaddrinfo(host.c_str(), std::to_string(tcpport).c_str(), &hints, &addr);
    if (ret > 0) {
        Error(Fmt("Error resolving %s", host.c_str()));

        // clean up
        freeaddrinfo(addr);
        return false;
    }

    sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (sock < 0) {
        Error(Fmt("Error opening socket"));

        // clean up
        freeaddrinfo(addr);
        return false;
    }

    ret = connect(sock, addr->ai_addr, addr->ai_addrlen);
    if (ret > 0) {
        char addrstr[INET6_ADDRSTRLEN];
        inet_ntop(addr->ai_family, addr->ai_addr->sa_family == AF_INET ? &(((struct sockaddr_in *)addr->ai_addr)->sin_addr) : (struct in_addr *)&(((struct sockaddr_in6 *)addr->ai_addr)->sin6_addr), addrstr, sizeof(addrstr));
        Error(Fmt("Error connecting to %s", addrstr));

        // clean up
        freeaddrinfo(addr);
        close(sock);
        return false;
    }

    // clean up
    freeaddrinfo(addr);

    if (tls) {
        // create context for tls
        ctx = SSL_CTX_new(SSLv23_client_method());
        if (ctx == nullptr) {
            Error(Fmt("Error setting up TLS context: %s", ERR_reason_error_string(ERR_get_error())));

            // clean up
            close(sock);
            return false;
        }

        if (!cert.empty()) {
            // add certificate to context
            ret = SSL_CTX_load_verify_locations(ctx, cert.c_str(), NULL);
            if (ret <= 0) {
                Error(Fmt("Error using TLS certificate: %s", ERR_reason_error_string(ERR_get_error())));

                // clean up
                SSL_CTX_free(ctx);
                close(sock);
                return false;
            }
        }

        // setup tls connection
        ssl = SSL_new(ctx);
        if (ssl == nullptr) {
            Error(Fmt("Error setting up TLS structure: %s", ERR_reason_error_string(ERR_get_error())));

            // clean up
            SSL_CTX_free(ctx);
            close(sock);
            return false;
        }

        // set tls hostname
        ret = SSL_set_tlsext_host_name(ssl, host.c_str());
        if (!ret) {
            Error(Fmt("Error setting TLS descriptor: %s", ERR_reason_error_string(ERR_get_error())));

            // clean up
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sock);
            return false;
        }

        // set underlying file descriptor
        ret = SSL_set_fd(ssl, sock);
        if (!ret) {
            Error(Fmt("Error setting TLS descriptor: %s", ERR_reason_error_string(ERR_get_error())));

            // clean up
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sock);
            return false;
        }

        // do handshake
        ret = SSL_connect(ssl);
        if (!ret) {
            Error(Fmt("Error completing TLS handshake: %s", ERR_reason_error_string(ERR_get_error())));

            // clean up
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sock);
            return false;
        }

        // get peer certificate
        X509 * peer = SSL_get_peer_certificate(ssl);
        if (peer == nullptr) {
            Error(Fmt("Error getting TLS certificate: %s", ERR_reason_error_string(ERR_get_error())));

            // clean up
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sock);
            return false;
        }

        // verify peer certificate
        lret = SSL_get_verify_result(ssl);
        if (lret != X509_V_OK) {
            Error(Fmt("Error verifying TLS certificate: %s", ERR_reason_error_string(ERR_get_error())));

            // clean up
            X509_free(peer);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sock);
            return false;
        }

        // clean up
        X509_free(peer);
    }

    return true;
}

bool TCP::DoFinish(double network_time) {
    if (tls) {
        // stop tls
        SSL_shutdown(ssl);
        SSL_free(ssl);

        // free context
        SSL_CTX_free(ctx);
    }

    // close socket
    close(sock);

    // free json formatter
    delete formatter;

    return true;
}

bool TCP::DoWrite(int num_fields, const threading::Field * const * fields, threading::Value ** vals) {
    int ret;

    buffer.Clear();

    formatter->Describe(&buffer, num_fields, fields, vals);

    buffer.AddRaw("\n", 1);

    const char * msg = (const char *)buffer.Bytes();
    size_t len = buffer.Len();

    if (tls) {
        ret = SSL_write(ssl, msg, len);
        if (ret < 0) {
            Error(Fmt("Error sending over TLS socket: %s", ERR_reason_error_string(ERR_get_error())));
            return false;
        }
    }
    else {
        ret = send(sock, msg, len, 0);
        if (ret < 0) {
            Error(Fmt("Error sending over socket: %s", strerror(errno)));
            return false;
        }
    }

    return true;
}

bool TCP::DoSetBuf(bool enabled) {
    return true;
}

bool TCP::DoFlush(double network_time) {
    return true;
}

bool TCP::DoRotate(const char * rotated_path, double open, double close, bool terminating) {
    // No log rotation needed
    return FinishedRotation();
}

bool TCP::DoHeartbeat(double network_time, double current_time) {
    return true;
}
