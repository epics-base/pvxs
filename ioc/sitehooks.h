/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_SITEHOOKS_H
#define PVXS_SITEHOOKS_H

#include <functional>
#include <epicsTypes.h>
#include <dbCommon.h>

#include <pvxs/data.h>
#include <pvxs/iochooks.h>

namespace pvxs {
namespace ioc {
namespace site {

// --- Registration (called by site-specific code) ---

// Multiple callbacks may be registered; all are fired in registration order.
PVXS_IOC_API void addInitHookAtBeginning(std::function<void()> fn);
PVXS_IOC_API void addInitHookAfterIocBuilt(std::function<void()> fn);

// Multiple callbacks may be registered; all are fired in registration order.
// Called at the end of IOCSource::get() with the record locked; may modify any field in node.
PVXS_IOC_API void addNodePostProcessor(std::function<void(dbCommon*, Value&)> fn);

// --- Called once from pvxsBaseRegistrar ---
void registerHooks();

// Defined in the generated siteregister.cpp; calls every registerXxx()
// function discovered by site/gen_siteregister.py at build time.
void registerSiteExtensions();

// --- Dispatch (called by core ioc/ code) ---

void postProcessNode(dbCommon* prec, Value& node);

} // site
} // ioc
} // pvxs

#endif // PVXS_SITEHOOKS_H
