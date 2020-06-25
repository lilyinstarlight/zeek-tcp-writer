// See the file "COPYING" for copyright.
//
// Log writer for writing to TCP

#pragma once

#include <string>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "logging/WriterBackend.h"
#include "threading/formatters/JSON.h"
#include "threading/formatters/Ascii.h"
#include "Desc.h"

#include "tcpwriter.bif.h"

namespace logging {
namespace writer {

class TCP : public WriterBackend {

public:
    TCP(WriterFrontend * frontend);
    ~TCP();

    static WriterBackend * Instantiate(WriterFrontend * frontend) {
        return new TCP(frontend);
    }

protected:
    virtual bool DoInit(const WriterBackend::WriterInfo & info, int num_fields, const threading::Field * const * fields);
    virtual bool DoWrite(int num_fields, const threading::Field * const * fields, threading::Value ** vals);
    virtual bool DoSetBuf(bool enabled);
    virtual bool DoRotate(const char * rotated_path, double open, double close, bool terminating);
    virtual bool DoFlush(double network_time);
    virtual bool DoFinish(double network_time);
    virtual bool DoHeartbeat(double network_time, double current_time);

private:
    bool DoLoad(bool is_retry = false);
    bool DoUnload();
    std::string GetConfigValue(const WriterInfo & info, const std::string name) const;

    bool ssl_init;
    int sock;
    SSL_CTX * ctx;
    SSL * ssl;

    threading::formatter::JSON * formatter;
    ODesc buffer;

    std::string host;
    int tcpport;
    bool retry;
    bool tls;
    std::string cert;
    std::string key;
};

}
}
