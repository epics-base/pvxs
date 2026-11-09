/* Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <memory>
#include <map>
#include <stdexcept>
#include <string>
#include <typeinfo>
#include <vector>

#include <ctype.h>
#include <string.h>

#include <dbStaticLib.h>
#include <epicsMutex.h>
#include <initHooks.h>
#include <epicsExit.h>

#include <pvxs/log.h>
#include <pvxs/data.h>
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/iochooks.h>

#include "dbentry.h"
#include "dblocker.h"
#include "qsrvpvt.h"
#include "utilpvt.h"

DEFINE_LOGGER(_log, "pvxs.ioc.qfield");

namespace pvxs {
namespace ioc {

namespace {

struct QShadowField;
struct QShadowRecord;

struct QShadowGlobal {
    // lookaside tables.
    // static after iocInit
    //   by record instance field address (like db_post_events())
    std::map<Value*, QShadowField*> byaddr;
    //   by record instance name
    std::map<std::string, std::unique_ptr<QShadowRecord> > byrec;

    server::StaticSource src;

    QShadowGlobal()
        :src((server::StaticSource::build()))
    {}
} *qGbl = nullptr;

struct QShadowRecord {
    dbCommon* const prec;
    // by field name UPPER case
    std::map<std::string, std::unique_ptr<QShadowField>> qfields;

    explicit
    QShadowRecord(dbCommon* prec) :prec(prec) {}
};

struct QShadowField {
    QShadowRecord& qrec;
    const dbFldDes& flddes;
    Value *pfld;
    server::SharedPV spv;

    QShadowField(QShadowRecord& qsr, dbFldDes* pflddes);
};

QShadowField::QShadowField(QShadowRecord &qsr, dbFldDes *pflddes)
    :qrec(qsr)
    ,flddes(*pflddes)
    ,pfld(reinterpret_cast<Value*>(flddes.offset + reinterpret_cast<char*>(qsr.prec)))
    ,spv(server::SharedPV::buildReadonly())
{
    spv.onPut([this](server::SharedPV& pv, std::unique_ptr<server::ExecOp>&& op, Value&& top) {
        try {
            DBLocker L(qrec.prec);
            if(auto val = top["value"].ifMarked()) {
                (*pfld)["value"] = val["value"]; // TODO: delegate decision to rset?
            }
            if(flddes.process_passive) { // TODO: record._options.block
                (void)dbProcess(qrec.prec);
            }
            op->reply();
        } catch(std::exception& e) {
            op->error(e.what());
        }
    });
}

// field qfields
void qfieldSearch()
{
    auto& qsg = *qGbl;
    DBEntry dbEntry;
    // for each record type
    for (long status = dbFirstRecordType(dbEntry); !status; status = dbNextRecordType(dbEntry)) {
        std::vector<short> vindicies;

        // for each field type (not associated instance)
        for (status = dbFirstField(dbEntry, 0); !status; status = dbNextField(dbEntry, 0)) {
            auto& flddes = *dbEntry->pflddes;
            if(flddes.field_type!=DBR_NOACCESS || !flddes.extra)
                continue;

            static const char qtype[] = "::pvxs::Value ";

            if(strncmp(flddes.extra, qtype, sizeof(qtype)-1)==0) {
                vindicies.push_back(flddes.indRecordType);
                log_debug_printf(_log, "Found QField %u %s.%s\n", flddes.indRecordType,
                                 dbEntry->precordType->name, flddes.name);
            }
        }

        if(vindicies.empty())
            continue; // boring...

        // for each instance of record type
        for (long status = dbFirstRecord(dbEntry); !status; status = dbNextRecord(dbEntry)) {
            if(dbIsAlias(dbEntry))
                continue;

            std::unique_ptr<QShadowRecord> qrec(new QShadowRecord((dbCommon*)dbEntry->precnode->precord));

            // for each instance field
            for(auto ind : vindicies) {
                auto flddes = *dbEntry->precordType->papFldDes[ind];
                std::string fname(flddes.name);
                for(auto& c : fname) {
                    c = toupper(c);
                }
                std::string pvname(SB()<<qrec->prec->name<<'.'<<fname); // "record.FLD"

                std::unique_ptr<QShadowField> qfld(new QShadowField(*qrec, &flddes));

                auto it = qrec->qfields.emplace(std::move(fname), std::move(qfld));
                qsg.byaddr.emplace(it.first->second->pfld, it.first->second.get());

                qsg.src.add(pvname, it.first->second->spv);
                log_debug_printf(_log, "Claim: %s\n", pvname.c_str());
                if(flddes.pdbRecordType->indvalFlddes==ind) { // is VAL
                    qsg.src.add(qrec->prec->name, it.first->second->spv);
                    log_debug_printf(_log, "Claim: %s\n", qrec->prec->name);
                }
            }

            qsg.byrec.emplace(dbEntry->precnode->recordname, std::move(qrec));
        }
    }
}

void qFieldSetup()
{
    auto& qsg = *qGbl;

    for(auto it : qsg.byaddr) {
        auto& fld = *it.first;
        auto& qfld = *it.second;

        Value initial;
        {
            DBLocker L(qfld.qrec.prec);
            initial = fld.clone();
        }

        try {
            qfld.spv.open(initial);
        } catch(std::exception& e){
            log_err_printf(_log, "Unable to open %s.%s: %s\n", qfld.qrec.prec->name, qfld.flddes.name, e.what());
        }
    }

    if(!qsg.byaddr.empty()) {
        server().addSource("__qfield", qsg.src.source(), -1);
        log_debug_printf(_log, "Install QField source%s", "\n");
    }
}

void qfieldCleanup(void*) noexcept
{
    try {
        // IOC server already stopped
        for(auto it : qGbl->byaddr) {
            *it.first = Value(); // drop reference
        }
        delete qGbl;
        qGbl = nullptr;

    } catch(std::exception& e) {
        log_exc_printf(_log, "%s: Unhandled %s : %s\n", __func__, typeid(e).name(), e.what());
    }
}

void qfieldHook(initHookState state) noexcept
{
    try {
        if(state==initHookAtBeginning) {
#ifndef USE_DEINIT_HOOKS
            {
                static bool installed = false;
                if(!installed) {
                    epicsAtExit(&qfieldCleanup, nullptr);
                    installed = true;
                }
            }
#endif
            qGbl = new QShadowGlobal;
            qfieldSearch();

        } else if(state==initHookAfterCaServerInit) {
            qFieldSetup();
        }
#ifdef USE_DEINIT_HOOKS
        else if(state==initHookBeforeFree) {
            qfieldCleanup(nullptr);
        }
#endif
    } catch(std::exception& e) {
        log_exc_printf(_log, "%s: Unhandled %s : %s\n", __func__, typeid(e).name(), e.what());
    }
}

} // namespace

void qfield_post(Value* fldaddr)
{
    if(!qGbl)
        throw std::logic_error("Lifecycle");

    auto& qsg = *qGbl;

    auto it(qsg.byaddr.find(fldaddr));
    if(it==qsg.byaddr.end())
        throw std::logic_error("Invalid");

    it->second->spv.post(*fldaddr);
}

void qfield_enable() {
    initHookRegister(qfieldHook);
}

}} // pvxs::ioc
