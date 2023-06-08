/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include <string>

#include <dbAccess.h>

#include "channel.h"
#include "dbentry.h"
#include "utilpvt.h"

#ifndef PVLINK_STRINGSZ
#  define PVLINK_STRINGSZ 1024
#endif

namespace pvxs {
namespace ioc {
/**
 * Construct a group channel from a given db channel name
 *
 * @param name the db channel name
 */
Channel::Channel(const char* name)
        :chan(std::shared_ptr<dbChannel>(std::shared_ptr<dbChannel>(dbChannelCreate(name),
        [](dbChannel* ch) {
            if (ch) {
                dbChannelDelete(ch);
            }
        })))
{
    if(!*this)
        throw std::runtime_error(SB()<<"Invalid PV: "<<name);
    {
        if( dbIsValueField(dbChannelFldDes(chan))) {
            // info() hint only applies to VAL
            DBEntry ent(dbChannelRecord(chan));
            form = ent.info("Q:form", "Default");

        } else {
            form = "Default";
        }

        /* ~duplicate '$' handling logic in dbChannelCreate()
         * when no '$' is present.
         *
         * situation circa Base 7.0.7
         * At this point dbChannelCreate() has initialized chan->addr.
         * SPC_DBADDR fields have been mangled by record support code.
         * filter have been parsed, but not opened.
         */

        auto field_type(dbChannelFieldType(chan));
        if(field_type==DBF_STRING && dbChannelElements(chan)==1
                && dbChannelFieldSize(chan)>MAX_STRING_SIZE+1)
        {
            // scalar string field with extra capacity
            chan->addr.no_elements = chan->addr.field_size;
            chan->addr.field_size = 1;
            chan->addr.field_type = DBF_CHAR;
            chan->addr.dbr_field_type = DBR_CHAR;
            form = "String";

        } else if(field_type >= DBF_INLINK && field_type <= DBF_FWDLINK) {
            chan->addr.no_elements = PVLINK_STRINGSZ;
            chan->addr.field_size = 1;
            chan->addr.dbr_field_type = DBR_CHAR;
            form = "String";
        }
    }
    if (dbChannelOpen(chan.get()))
        throw std::invalid_argument(SB() << "Failed dbChannelOpen(\"" << dbChannelName(chan) <<"\")");
}

} // pvxs
} // ioc
