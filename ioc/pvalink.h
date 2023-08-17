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

#include <pv/status.h>
#include <pv/bitSet.h>
#include <pv/pvData.h>

#include <pva/client.h>
#include <pv/anyscalar.h>
#include <pv/thread.h>
#include <pv/lock.h>
#include <pv/iocshelper.h>

#include <pv/sharedPtr.h>

#include "helper.h"
#include "pvif.h"
#include "tpool.h"

extern "C" {
    QSRV_API extern int pvaLinkDebug;
    QSRV_API extern int pvaLinkIsolate;
    QSRV_API extern int pvaLinkNWorkers;
}

#if 0
#  define TRACE(X) std::cerr<<"PVAL "<<__func__<<" " X <<"\n"
#else
#  define TRACE(X) do {} while(0)
#endif

// pvaLink and pvaLinkChannel have ->debug
#define DEBUG(OBJ, X) do{ if((OBJ)->debug) std::cout X<<"\n"; }while(0)

namespace pvalink {

namespace pvd = epics::pvData;
namespace pva = epics::pvAccess;

typedef epicsGuard<pvd::Mutex> Guard;
typedef epicsGuardRelease<pvd::Mutex> UnGuard;

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

    size_t queueSize;

    enum pp_t {
        NPP,
        Default, // for put() only.  For monitor, treated as NPP
        PP,      // for put() only,  For monitor, treated as NPP
        CP,      // for monitor only, put treats as pp
        CPP,     // for monitor only, put treats as pp
    } pp;
    enum ms_t {
        NMS,
        MS,
        MSI,
    } ms;

    bool defer, pipeline, time, retry, local, always;
    int monorder;

    // internals used by jlif parsing
    std::string jkey;

    pvaLinkConfig();
    virtual ~pvaLinkConfig();
};

struct pvaGlobal_t {
    pvac::ClientProvider provider_local,
                         provider_remote;

    const pvd::PVDataCreatePtr create;

    WorkQueue queue;

    pvd::Mutex lock;

    bool running; // set after dbEvent is initialized and safe to use

    // a tuple of channel name and printed pvRequest (or Monitor)
    typedef std::pair<std::string, std::string> channels_key_t;
    // pvaLinkChannel dtor prunes dead entires
    typedef std::map<channels_key_t, std::tr1::weak_ptr<pvaLinkChannel> > channels_t;
    // Cache of active Channels (really about caching Monitor)
    channels_t channels;

    pvaGlobal_t();
    ~pvaGlobal_t();
};
extern pvaGlobal_t *pvaGlobal;

struct pvaLinkChannel : public pvac::ClientChannel::MonitorCallback,
                        public pvac::ClientChannel::PutCallback,
                        public epicsThreadRunable,
                        public std::tr1::enable_shared_from_this<pvaLinkChannel>
{
    const pvaGlobal_t::channels_key_t key; // tuple of (channelName, pvRequest key)
    const pvd::PVStructure::const_shared_pointer pvRequest; // used with monitor

    static size_t num_instances;

    pvd::Mutex lock;
    epicsEvent run_done; // used by testing code

    pvac::ClientChannel chan;
    pvac::Monitor op_mon;
    pvac::Operation op_put;

    std::string providerName;
    size_t num_disconnect, num_type_change;
    bool connected;
    bool connected_latched; // connection status at the run()
    bool isatomic;
    bool queued; // added to WorkQueue
    bool debug; // set if any jlink::debug is set
    std::tr1::shared_ptr<const void> previous_root;
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
    bool links_changed;

    pvaLinkChannel(const pvaGlobal_t::channels_key_t& key, const epics::pvData::PVStructure::const_shared_pointer &pvRequest);
    virtual ~pvaLinkChannel();

    void open();
    void put(bool force=false); // begin Put op.

    // pvac::ClientChanel::MonitorCallback
    virtual void monitorEvent(const pvac::MonitorEvent& evt) OVERRIDE FINAL;

    // pvac::ClientChanel::PutCallback
    virtual void putBuild(const epics::pvData::StructureConstPtr& build, pvac::ClientChannel::PutCallback::Args& args) OVERRIDE FINAL;
    virtual void putDone(const pvac::PutEvent& evt) OVERRIDE FINAL;
    struct AfterPut : public epicsThreadRunable {
        std::tr1::weak_ptr<pvaLinkChannel> lc;
        virtual ~AfterPut() {}
        virtual void run() OVERRIDE FINAL;
    };
    std::tr1::shared_ptr<AfterPut> AP;
private:
    virtual void run() OVERRIDE FINAL;
    void run_dbProcess(size_t idx); // idx is index in scan_records

    // ==== Treat remaining as local to run()

    std::vector<dbCommon*> scan_records;
    std::vector<bool> scan_check_passive;
    std::vector<epics::pvData::BitSet> scan_changed;

    DBManyLock atomic_lock;
};

struct pvaLink : public pvaLinkConfig
{
    static size_t num_instances;

    bool alive; // attempt to catch some use after free
    dbfType type;

    DBLINK * plink; // may be NULL

    std::tr1::shared_ptr<pvaLinkChannel> lchan;

    bool used_scratch, used_queue;
    pvd::shared_vector<const void> put_scratch, put_queue;

    // cached fields from channel op_mon
    // updated in onTypeChange()
    epics::pvData::PVField::const_shared_pointer fld_value;
    epics::pvData::PVScalar::const_shared_pointer fld_severity,
                                                  fld_seconds,
                                                  fld_nanoseconds;
    epics::pvData::PVStructure::const_shared_pointer fld_display,
                                                     fld_control,
                                                     fld_valueAlarm;
    epics::pvData::BitSet proc_changed;

    // cached snapshot of alarm and  timestamp
    // captured in pvaGetValue().
    // we choose not to ensure consistency with display/control meta-data
    epicsTimeStamp snap_time;
    short snap_severity;

    pvaLink();
    virtual ~pvaLink();

    // returns pvRequest to be used with monitor
    pvd::PVStructurePtr makeRequest();

    bool valid() const;

    // fetch a sub-sub-field of the top monitored field.
    pvd::PVField::const_shared_pointer getSubField(const char *name);

    void onDisconnect();
    void onTypeChange();
};


} // namespace pvalink

#endif // PVALINK_H
