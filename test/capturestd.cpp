/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <memory>

#include "capturestd.h"

#include <epicsUnitTest.h>
#include <epicsStdio.h>

static
std::string readFile(const std::string& filename)
{
    std::ifstream t(filename.c_str());
    std::stringstream buffer;

    if (!t.is_open()) {
        throw std::invalid_argument("Could not open filename " + filename);
    }

    buffer << t.rdbuf();
    return buffer.str();
}

CaptureStd::CaptureStd(const std::function<void ()> &fn) {
    std::shared_ptr<FILE>
        out(fopen("testiocsh.out", "w+b"),
            [](FILE* fp){
                (void)fclose(fp);
            }),
        err(fopen("testiocsh.err", "w+b"),
            [](FILE* fp){
                (void)fclose(fp);
            });

    if(!out || !err)
        testAbort("Unable to open/create testiocsh.out / .err");
    epicsSetThreadStdout(out.get());
    epicsSetThreadStderr(err.get());

    try {
        fn();
    }catch(...){
        epicsSetThreadStdout(nullptr);
        epicsSetThreadStderr(nullptr);
        throw;
    }
    out.reset();
    err.reset();

    m_out = readFile("testiocsh.out");
    m_err = readFile("testiocsh.err");
}
