# Site-Specific PVXS Extensions

This directory contains optional, site-local extensions to PVXS IOC behaviour.
Any `.cpp` file placed here is automatically compiled into `libpvxsIoc` by the
build system - no Makefile editing required.  Removing a file reverts to the
default behaviour.

## How it works

Each source file defines a `registerXxx()` function in the
`pvxs::ioc::site` namespace, where `Xxx` is the CamelCase basename of the
file (e.g. `myextension.cpp` -> `registerMyextension()`).  At build time,
`gen_siteregister.py` scans the directory, collects every such function,
and generates `siteregister.cpp` which calls them all from
`registerSiteExtensions()`.  `registerSiteExtensions()` is invoked from
`pvxsBaseRegistrar()`, before `iocInit()` is called.

The registration API is in `ioc/sitehooks.h` and lives in the
`pvxs::ioc::site` namespace.

### Available hooks

| Function | When called | Typical use |
|---|---|---|
| `addInitHookAtBeginning(fn)` | Fires at EPICS `initHookAtBeginning` -- after `dbLoadRecords()`, before `iocBuild()` | Reset per-IOC state; scan info fields |
| `addInitHookAfterIocBuilt(fn)` | Fires at EPICS `initHookAfterIocBuilt` -- after all `init_record()` calls | Read field values or links that require full initialisation |
| `addNodePostProcessor(fn)` | Fires at the end of every `IOCSource::get()`; multiple may be added | Override or augment fields in the PVA response (e.g. `alarm.message`) |

### Choosing between the two init-hook phases

**`addInitHookAtBeginning`** fires after `dbLoadRecords()` but before
`iocBuild()`.  At this point record structures (`dbCommon*`) exist in memory
and info fields are readable (they are static config loaded from `.db` files),
but field values are at defaults, database links are not resolved, and autosave
has not restored saved values.

**`addInitHookAfterIocBuilt`** fires after `iocBuild()` completes -- all
`init_record()` calls done, links resolved, autosave restored.  Use this phase
when the data you need is only valid after full initialisation.

Extensions that only read info fields can do everything in a single
`atBeginning` callback.  Extensions that need `init_record()` to have run
separate the two steps: clear at `atBeginning`, populate at `afterIocBuilt`
(see `timetag.cpp`).

If a cache of info fields, or for other purposes, has been setup then **a cache clear must happen at `atBeginning`**, not `afterIocBuilt`.  When an IOC
is rebuilt in the same process -- as happens under `TestIOC` in the test suite
-- record structures from the previous run are freed before `dbLoadRecords()`
runs for the new IOC.  Any cache that holds `dbCommon*` pointers therefore
contains dangling pointers at that moment.  The `atBeginning` hook fires
immediately after the new database is loaded and before `iocBuild()` allocates
new record structures, making it the correct place to invalidate stale state.
Deferring the clear to `afterIocBuilt` would leave dangling pointers live
throughout the entire `iocBuild()` phase.

### Modifying PVA responses

`addNodePostProcessor` adds a `void(dbCommon*, Value&)` callback
that is called at the end of `IOCSource::get()` after all standard fields have
been populated.  Multiple callbacks may be added; they are fired in
registration order.  The callback may read any field from the node and overwrite
it.  The record is locked for the duration of the call, so `prec->stat` and
other record fields are safe to read.

## Adding a new extension

1. Create a `.cpp` file in this directory.
2. Include `"sitehooks.h"`.
3. Define a `registerXxx()` function in the `pvxs::ioc::site` namespace
   (where `Xxx` is the CamelCase basename of your file) and call the relevant
   registration functions inside it.  Do not use namespace-scope static objects
   -- they produce GCC static-constructor symbols (`_GLOBAL__sub_I_*`) that
   fail the EPICS CDT check.  Use function-local statics (Meyers singletons)
   instead: declare `static` inside a function body so they are initialised
   lazily on first call via `__cxa_guard_acquire`.  All state-holding statics
   in the bundled extensions use this pattern.
4. Build - `gen_siteregister.py` discovers the function automatically and
   wires it into `registerSiteExtensions()`.

Template (file named `myextension.cpp`):

```cpp
#include <unordered_set>
#include <string>

#include "sitehooks.h"

namespace {

// Function-local static (Meyers singleton) -- avoids CDT-check failure.
std::unordered_set<std::string>& mySet()
{
    static std::unordered_set<std::string> s;
    return s;
}

void onBeginning()
{
    mySet().clear();  // must clear here; see "Choosing between phases" above
    // populate from info fields here if that is sufficient
}

void onIocBuilt()
{
    // populate here if init_record()/links/autosave are needed (see timetag.cpp)
    // omit this function and addInitHookAfterIocBuilt below if onBeginning() suffices
}

} // namespace

namespace pvxs { namespace ioc { namespace site {
void registerMyextension() {
    addInitHookAtBeginning(onBeginning);
    addInitHookAfterIocBuilt(onIocBuilt);
}
}}} // pvxs::ioc::site
```

## Tests

Unit tests for site extensions live in `test/`.  Follow the naming convention
to have the build system wire them up automatically: for each `<name>.cpp` in
`site/`, if `test/test<name>.cpp` exists a `test<name>` binary is built from
those two files plus the standard IOC driver registration stub.  If
`test/test<name>.db` also exists it is added to `TESTFILES` automatically.
Extensions that need extra source files or a non-standard binary name must be
added manually in `test/Makefile` below the auto-discovery block.

Each test binary links against `libpvxsIoc` and exercises the extension
through the full hook registration path, the same as a real IOC.  Tests use
`TestIOC` with `dbUnitTest.h` and therefore require EPICS Base >= 3.15.  See
`test/testtimetag.cpp` for an example.
