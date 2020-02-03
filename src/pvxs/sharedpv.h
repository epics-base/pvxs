/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_SHAREDPV_H
#define PVXS_SHAREDPV_H

#include <functional>
#include <memory>

#include <pvxs/version.h>

namespace pvxs {
class Value;

namespace server {

struct ChannelControl;
struct ExecOp;
struct Source;

struct PVXS_API SharedPV
{
    static SharedPV buildMailbox();
    static SharedPV buildReadonly();

    ~SharedPV();

    inline explicit operator bool() const { return !!impl; }

    // call from Source::onCreate()
    void attach(std::unique_ptr<ChannelControl>&& op);

    void onFirstConnect(std::function<void()>&& fn);
    void onLastDisconnect(std::function<void()>&& fn);
    void onPut(std::function<void(SharedPV&, std::unique_ptr<ExecOp>&&, Value&&)>&& fn);
    void onRPC(std::function<void(SharedPV&, std::unique_ptr<ExecOp>&&, Value&&)>&& fn);

    void open(const Value& prototype);
    bool isOpen() const;
    void close();

    void post(Value&& val);
    void fetch(Value& val);

    struct Impl;
private:
    std::shared_ptr<Impl> impl;
};

struct PVXS_API StaticSource
{
    static StaticSource build();

    ~StaticSource();

    inline explicit operator bool() const { return !!impl; }

    std::shared_ptr<Source> source() const;

    StaticSource& add(const std::string& name, const SharedPV& pv);
    StaticSource& remove(const std::string& name);

    struct Impl;
private:
    std::shared_ptr<Impl> impl;
};

} // namespace server
} // namespace pvxs

#endif // PVXS_SHAREDPV_H
