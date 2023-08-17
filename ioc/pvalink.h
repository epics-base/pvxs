/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVALINK_H
#define PVALINK_H

#include <set>
#include <map>

#define EPICS_DBCA_PRIVATE_API
#include <epicsGuard.h>
#include <dbAccess.h>
#include <dbCommon.h>
#include <dbLink.h>
#include <dbScan.h>
#include <errlog.h>
#include <initHooks.h>
#include <alarm.h>
#include <epicsExit.h>
#include <epicsAtomic.h>
#include <link.h>
#include <dbJLink.h>
#include <errlog.h>
#include <epicsThread.h>
#include <epicsMutex.h>
#include <epicsEvent.h>
#include <dbChannel.h>
#include <dbStaticLib.h>
#include <dbLock.h>
#include <dbEvent.h>
#include <epicsVersion.h>

#include <pvxs/client.h>
#include "dbmanylocker.h"

extern "C" {
    extern int pvaLinkDebug;
    extern int pvaLinkIsolate;
    extern int pvaLinkNWorkers;
}

namespace pvxlink {
using namespace pvxs;

typedef epicsGuard<epicsMutex> Guard;
typedef epicsGuardRelease<epicsMutex> UnGuard;

struct pvaLink;
struct pvaLinkChannel;

extern lset pva_lset;
extern jlif lsetPVA;

struct pvaLinkConfig : public jlink
{
    // configuration, output of jlif parsing
    //! Channel (aka PV) name string
    std::string channelName;
    //! sub-field within addressed PVStructure
    std::string fieldName;

    size_t queueSize = 4;

    enum pp_t {
        NPP,
        Default, // for put() only.  For monitor, treated as NPP
        PP,      // for put() only,  For monitor, treated as NPP
        CP,      // for monitor only, put treats as pp
        CPP,     // for monitor only, put treats as pp
    } pp = Default;
    enum ms_t {
        NMS,
        MS,
        MSI,
    } ms = NMS;

    bool defer = false;
    bool pipeline = false;
    bool time = false;
    bool retry = false;
    bool local = false;
    bool always = false;
    int monorder = 0;

    // internals used by jlif parsing
    std::string jkey;

    virtual ~pvaLinkConfig();
};

struct pvaGlobal_t : private epicsThreadRunable {
    client::Context provider_remote;

    MPMCFIFO<std::weak_ptr<epicsThreadRunable>> queue;

    epicsMutex lock;

    bool running; // set after dbEvent is initialized and safe to use

    // a tuple of channel name and printed pvRequest (or Monitor)
    typedef std::pair<std::string, std::string> channels_key_t;
    // pvaLinkChannel dtor prunes dead entires
    typedef std::map<channels_key_t, std::weak_ptr<pvaLinkChannel> > channels_t;
    // Cache of active Channels (really about caching Monitor)
    channels_t channels;

private:
    epicsThread worker;
    bool workerStop = false;
    virtual void run() override final;
public:

    pvaGlobal_t();
    virtual ~pvaGlobal_t();
};
extern pvaGlobal_t *pvaGlobal;

struct pvaLinkChannel : public epicsThreadRunable
        ,public std::enable_shared_from_this<pvaLinkChannel>
{
    const pvaGlobal_t::channels_key_t key; // tuple of (channelName, pvRequest key)
    const Value pvRequest; // used with monitor

    static size_t num_instances;

    epicsMutex lock;
    epicsEvent run_done; // used by testing code

//    std::shared_ptr<client::Connect> chan;
    std::shared_ptr<client::Subscription> op_mon;
    std::shared_ptr<client::Operation> op_put;
    Value root;

    std::string providerName;
    size_t num_disconnect = 0u, num_type_change = 0u;
    enum state_t {
        Disconnected,
        Connecting,
        Connected,
    } state = Disconnected,
      state_latched = Disconnected;

    bool isatomic = false;
    bool queued = false; // added to WorkQueue
    bool debug = false; // set if any jlink::debug is set
    typedef std::set<dbCommon*> after_put_t;
    after_put_t after_put;

    struct LinkSort {
        bool operator()(const pvaLink *L, const pvaLink *R) const;
    };

    typedef std::set<pvaLink*, LinkSort> links_t;

    // list of currently attached links.  maintained by pvaLink ctor/dtor
    // TODO: sort by PHAS
    links_t links;

    // set when 'links' is modified to trigger re-compute of record scan list
    bool links_changed = false;

    pvaLinkChannel(const pvaGlobal_t::channels_key_t& key, const Value &pvRequest);
    virtual ~pvaLinkChannel();

    void open();
    void put(bool force=false); // begin Put op.

    struct AfterPut : public epicsThreadRunable {
        std::weak_ptr<pvaLinkChannel> lc;
        virtual ~AfterPut() {}
        virtual void run() override final;
    };
    std::shared_ptr<AfterPut> AP;
private:
    virtual void run() override final;
    void run_dbProcess(size_t idx); // idx is index in scan_records

    // ==== Treat remaining as local to run()

    std::vector<dbCommon*> scan_records;
    std::vector<bool> scan_check_passive;

    ioc::DBManyLock atomic_lock;
};

struct pvaLink final : public pvaLinkConfig
{
    static size_t num_instances;

    bool alive = true; // attempt to catch some use after free
    dbfType type = (dbfType)-1;

    DBLINK * plink = nullptr;

    std::shared_ptr<pvaLinkChannel> lchan;

    bool used_scratch = false;
    bool used_queue = false;
    shared_array<const void> put_scratch, put_queue;

    // cached fields from channel op_mon
    // updated in onTypeChange()
    Value fld_value;
    Value fld_severity,
          fld_seconds,
          fld_nanoseconds;
    Value fld_display,
          fld_control,
          fld_valueAlarm;

    // cached snapshot of alarm and  timestamp
    // captured in pvaGetValue().
    // we choose not to ensure consistency with display/control meta-data
    epicsTimeStamp snap_time = {};
    short snap_severity = INVALID_ALARM;

    pvaLink();
    virtual ~pvaLink();

    // returns pvRequest to be used with monitor
    Value makeRequest();

    bool valid() const;

    // fetch a sub-sub-field of the top monitored field.
    Value getSubField(const char *name);

    void onDisconnect();
    void onTypeChange();
};


} // namespace pvalink

#endif // PVALINK_H
