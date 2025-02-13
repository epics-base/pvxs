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
#include "utilpvt.h"
#include "dbmanylocker.h"


#if EPICS_VERSION_INT<VERSION_INT(7,0,6,0)
typedef epicsUInt64     epicsUTag;
#endif

#ifndef DBR_AMSG
#  define recGblSetSevrMsg(PREC, STAT, SEVR, ...) recGblSetSevr(PREC, STAT, SEVR)
#endif

extern "C" {
    extern int pvaLinkNWorkers;
}

namespace pvxs {
namespace ioc {

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
    } proc = Default;
    enum ms_t {
        NMS,
        MS,
        MSI,
    } sevr = NMS;

    bool defer = false;
    bool pipeline = false;
    bool time = false;
    bool retry = false;
    bool local = false;
    bool always = false;
    bool atomic = false;
    int monorder = 0;

    // internals used by jlif parsing
    std::string jkey;

    pvaLinkConfig() = default;
    pvaLinkConfig(const pvaLinkConfig&) = delete;
    pvaLinkConfig& operator=(const pvaLinkConfig&) = delete;
    virtual ~pvaLinkConfig();
};

struct linkGlobal_t final : private epicsThreadRunable {
    client::Context provider_remote;

    MPMCFIFO<std::weak_ptr<epicsThreadRunable>> queue;

    epicsMutex lock;

    bool running; // set after dbEvent is initialized and safe to use

    // a tuple of channel name and printed pvRequest (or Monitor)
    typedef std::pair<std::string, std::string> channels_key_t;
    // pvaLinkChannel dtor prunes dead entries
    typedef std::map<channels_key_t, std::weak_ptr<pvaLinkChannel> > channels_t;
    // Cache of active Channels (really about caching Monitor)
    channels_t channels;

    // pvRequest used with PUT
    const Value putReq;

private:
    epicsThread worker;
    bool workerStop = false;
    virtual void run() override final;
public:

    linkGlobal_t();
    linkGlobal_t(const linkGlobal_t&) = delete;
    linkGlobal_t& operator=(const linkGlobal_t&) = delete;
    virtual ~linkGlobal_t();
    void close();

    // IOC lifecycle hooks
    static void alloc();
    static void init();
    static void deinit();
    static void dtor();
};
extern linkGlobal_t *linkGlobal;

struct pvaLinkChannel final : public epicsThreadRunable
        ,public std::enable_shared_from_this<pvaLinkChannel>
{
    const linkGlobal_t::channels_key_t key; // tuple of (channelName, pvRequest key)
    const Value pvRequest; // used with monitor

    INST_COUNTER(pvaLinkChannel);

    // locker order: record lock(s) -> channel lock
    epicsMutex lock;
    epicsEvent update_evt; // used by testing code

    std::shared_ptr<client::Subscription> op_mon;
    std::shared_ptr<client::Operation> op_put;
    Value root;

    size_t num_disconnect = 0u, num_type_change = 0u;

    bool connected = false;
    bool debug = false; // set if any jlink::debug is set

    unsigned update_seq = 0u; // used by testing code

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

    pvaLinkChannel(const linkGlobal_t::channels_key_t& key, const Value &pvRequest);
    virtual ~pvaLinkChannel();

    void open();
    void put(bool force=false); // begin Put op.

    struct AfterPut final : public epicsThreadRunable {
        std::weak_ptr<pvaLinkChannel> lc;
        AfterPut() = default;
        AfterPut(const AfterPut&) = delete;
        AfterPut& operator=(const AfterPut&) = delete;
        virtual ~AfterPut() = default;
        virtual void run() override final;
    };
    const std::shared_ptr<AfterPut> AP;
private:
    virtual void run() override final;

    // ==== Treat remaining as local to run()

    struct ScanTrack {
        dbCommon *prec = nullptr;
        // if true, only scan if prec->scan==0
        bool check_passive = false;

        ScanTrack() = default;
        ScanTrack(dbCommon *prec, bool check_passive) :prec(prec), check_passive(check_passive) {}
        void scan();
    };
    std::vector<ScanTrack> nonatomic_records,
                           atomic_records;

    ioc::DBManyLock atomic_lock;
};

struct pvaLink final : public pvaLinkConfig
{
    INST_COUNTER(pvaLink);

    bool alive = true; // attempt to catch some use after free
    dbfType type = (dbfType)-1;

    DBLINK * plink = nullptr;
    const char *pfieldname = nullptr;

    std::shared_ptr<pvaLinkChannel> lchan;

    bool used_scratch = false;
    bool used_queue = false;
    shared_array<const void> put_scratch, put_queue;

    // cached fields from channel op_mon
    // updated in onTypeChange()
    Value fld_value,
          fld_severity,
          fld_message,
          fld_seconds,
          fld_nanoseconds,
          fld_usertag,
          fld_meta;

    // cached snapshot of alarm and  timestamp
    // captured in pvaGetValue().
    // we choose not to ensure consistency with display/control meta-data
    epicsTimeStamp snap_time = {};
    epicsUTag snap_tag = 0;
    short snap_severity = INVALID_ALARM;
    std::string snap_message;

    pvaLink();
    virtual ~pvaLink();

    // returns pvRequest to be used with monitor
    Value makeRequest();

    bool valid() const;

    void onDisconnect();
    void onTypeChange();
    enum scanOnUpdate_t {
        scanOnUpdateNo = -1,
        scanOnUpdatePassive = 0,
        scanOnUpdateYes = 1,
    };
    scanOnUpdate_t scanOnUpdate() const;
};


}} // namespace pvxs::ioc

#endif // PVALINK_H
