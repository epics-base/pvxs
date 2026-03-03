/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef CAPTURESTD_H
#define CAPTURESTD_H

#include <string>
#include <functional>

struct CaptureStd
{
    std::string m_out, m_err;

    CaptureStd(const std::function<void()>& fn);

    const std::string& out() const {
        return m_out;
    }
    const std::string& err() const {
        return m_err;
    }
};


#endif // CAPTURESTD_H
