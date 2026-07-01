/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <vector>
#include <functional>

#include <initHooks.h>

#include "sitehooks.h"

namespace pvxs {
namespace ioc {
namespace site {

namespace {
// Function-local statics avoid init-order issues with site-specific registrars.
std::vector<std::function<void()>>& hooksAtBeginning() {
    static std::vector<std::function<void()>> v;
    return v;
}
std::vector<std::function<void()>>& hooksAfterIocBuilt() {
    static std::vector<std::function<void()>> v;
    return v;
}
std::vector<std::function<void(dbCommon*, Value&)>>& nodePostProcessors() {
    static std::vector<std::function<void(dbCommon*, Value&)>> v;
    return v;
}
void siteHookDispatch(initHookState state) noexcept
{
    if (state == initHookAtBeginning)
        for (auto& fn : hooksAtBeginning()) fn();
    else if (state == initHookAfterIocBuilt)
        for (auto& fn : hooksAfterIocBuilt()) fn();
}
} // namespace

void registerHooks()
{
    registerSiteExtensions();
    initHookRegister(siteHookDispatch);
}

/**
 * Add a callback to be invoked at EPICS initHookAtBeginning.
 * Multiple callbacks may be registered; they are fired in registration order.
 * Use this phase to iterate the loaded database and pre-compute per-record data
 * before SingleSource is constructed.
 *
 * @param fn callback to invoke
 */
void addInitHookAtBeginning(std::function<void()> fn)
{
    hooksAtBeginning().push_back(std::move(fn));
}

/**
 * Add a callback to be invoked at EPICS initHookAfterIocBuilt.
 * Multiple callbacks may be registered; they are fired in registration order.
 *
 * @param fn callback to invoke
 */
void addInitHookAfterIocBuilt(std::function<void()> fn)
{
    hooksAfterIocBuilt().push_back(std::move(fn));
}

/**
 * Add a node post-processor, called at the end of every IOCSource::get()
 * after all standard fields have been populated.
 * Multiple processors may be registered; they are fired in registration order.
 * The record is locked for the duration of each call.
 *
 * @param fn callback receiving the record pointer and the mutable PVA value node
 */
void addNodePostProcessor(std::function<void(dbCommon*, Value&)> fn)
{
    nodePostProcessors().push_back(std::move(fn));
}

/**
 * Invoke all registered node post-processors in registration order.
 * Called by IOCSource::get() after all standard fields have been written to node.
 *
 * @param prec pointer to the EPICS record (locked by the caller)
 * @param node the PVA value node to be returned to the client
 */
void postProcessNode(dbCommon* prec, Value& node)
{
    for (auto& fn : nodePostProcessors())
        fn(prec, node);
}

} // site
} // ioc
} // pvxs
