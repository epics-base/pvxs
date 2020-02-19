/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <pvxs/log.h>
#include <pvxs/nt.h>
#include "serverconn.h"

namespace pvxs {
namespace impl {

DEFINE_LOGGER(srvsrc, "pvxs.server.src");

ServerSource::ServerSource(server::Server::Pvt* serv)
    :name("server")
    ,serv(serv)
    ,info(TypeDef(TypeCode::Struct, {
                      Member(TypeCode::String, "implLang"),
                      Member(TypeCode::String, "version"),
                  }).create())
{}

void ServerSource::onSearch(Search &op)
{
    // nothing.  our "server" PV is not advertised
}

void ServerSource::onCreate(std::unique_ptr<server::ChannelControl> &&op)
{
    if(op->name()!=name)
        return;

    auto handle = std::move(op); // claim

    handle->onRPC([this](std::unique_ptr<server::ExecOp>&& eop, Value&& raw) {
        log_debug_printf(srvsrc, "Client %s calls %s\n", eop->peerName().c_str(),
                   std::string(SB()<<raw).c_str());

        auto args = std::move(raw);

        if(auto Q = args["query"]) // NTURI
            args = Q;

        if(args["help"].valid()) {
            auto ret = nt::NTScalar{TypeCode::String}.create();
            ret["value"] = "Help, I really should write some help";

            eop->reply(ret);
        }

        auto op = args["op"].as<std::string>();

        if(op=="channels") {

            std::set<std::string> names;
            {
                auto L(serv->sourcesLock.lockReader());

                for(auto& pair : serv->sources) {
                    auto list = pair.second->onList();
                    if(list.names) {
                        for(auto& name : *list.names) {
                            names.insert(name);
                        }
                    }
                }
            }

            shared_array<std::string> lnames(names.size());
            size_t i=0;
            for(auto& name : names) {
                lnames[i++] = name;
            }

            auto ret = nt::NTScalar{TypeCode::StringA}.create();
            ret["value"] = lnames.freeze().castTo<const void>();

            eop->reply(ret);
            return;

        } else if(op=="info") {
            auto ret = info.cloneEmpty();

            ret["implLang"] = "cpp";
            ret["version"] = version_str();

            eop->reply(ret);
            return;
        }

        eop->error("Not implemented");
    });
}


} // namespace impl
} // namespace pvxs
