// See the file "COPYING" for copyright.
//
// Log writer for writing to TCP

#include "TCP.h"

using namespace logging;
using namespace writer;

TCP::TCP(WriterFrontend * frontend) : WriterBackend(frontend), host((const char *)BifConst::LogTCP::host->Bytes(), BifConst::LogTCP::host->Len()), tcpport(BifConst::LogTCP::tcpport), ssl(BifConst::LogTCP::ssl) {
}

TCP::~TCP() {
}

string TCP::GetConfigValue(const WriterInfo & info, const string name) const {
    map<const char *, const char *>::const_iterator it = info.config.find(name.c_str());
    if (it == info.config.end())
        return string();
    else
        return it->second;
}

bool TCP::DoInit(const WriterInfo & info, int num_fields, const threading::Field * const * fields) {
    string cfg_host = GetConfigValue(info, "host");
    string cfg_tcpport = GetConfigValue(info, "tcpport");
    string cfg_ssl = GetConfigValue(info, "ssl");

    if (!cfg_host.empty())
        host = cfg_host;
    if (!cfg_tcpport.empty())
        tcpport = stoi(cfg_tcpport);
    if (!cfg_ssl.empty())
        ssl = cfg_ssl == "T";

    formatter = new threading::formatter::JSON(this, threading::formatter::JSON::TS_EPOCH);

    Error(Fmt("%s %d %d", host.c_str(), tcpport, ssl));

    return true;
}

bool TCP::DoFinish(double network_time) {
    delete formatter;

    return true;
}

bool TCP::DoWrite(int num_fields, const threading::Field * const * fields, threading::Value ** vals) {
    buffer.Clear();

    formatter->Describe(&buffer, num_fields, fields, vals);

    buffer.AddRaw("\n", 1);

    const char * msg = (const char *)buffer.Bytes();

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
