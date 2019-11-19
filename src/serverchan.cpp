/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <stdexcept>
#include <cassert>

#include "pvxs/log.h"
#include "serverconn.h"

namespace pvxsimpl {

// message related to client state and errors
DEFINE_LOGGER(connsetup, "tcp.setup");
// related to low level send/recv
DEFINE_LOGGER(connio, "tcp.io");

ServerChan::ServerChan(const std::shared_ptr<ServerConn> &conn,
                       uint32_t sid,
                       uint32_t cid,
                       const std::string &name)
    :conn(conn)
    ,sid(sid)
    ,cid(cid)
    ,name(name)
    ,state(Creating)
{}

ServerChan::~ServerChan() {}

ServerChannelControl::ServerChannelControl(const std::shared_ptr<ServerConn> &conn, const std::shared_ptr<ServerChan>& channel)
    :server::ChannelControl(conn->peerName, conn->iface->name, channel->name)
    ,server(conn->iface->server->internal_self)
    ,chan(channel)
{}

ServerChannelControl::~ServerChannelControl() {}

std::shared_ptr<server::Handler> ServerChannelControl::setHandler(const std::shared_ptr<server::Handler> &h)
{
    std::shared_ptr<server::Handler> ret(h);
    std::shared_ptr<server::Server::Pvt> serv(server);

    serv->acceptor_loop.call([this, &ret](){
        std::shared_ptr<ServerChan> ch(chan);

        ch->handler.swap(ret);
    });

    return ret;
}

void ServerChannelControl::close()
{
    // fail soft if server stopped, or channel/connection already closed
    auto serv = server.lock();
    if(!serv)
        return;

    serv->acceptor_loop.call([this](){
        auto ch = chan.lock();
        if(!ch)
            return;
        auto conn = ch->conn.lock();
        if(conn) {
            if(ch->state==ServerChan::Active) {
                // Send unsolicited Channel Destroy

                auto tx = bufferevent_get_output(conn->bev.get());
                constexpr bool be = EPICS_BYTE_ORDER==EPICS_ENDIAN_BIG;
                EvOutBuf R(be, tx);
                to_wire(R, Header{pva_app_msg::DestroyChan, pva_flags::Server, 8});
                to_wire(R, ch->sid);
                to_wire(R, ch->cid);
            }
            ch->state = ServerChan::Destroy;
        }
    });
}

void ServerConn::handle_CreateChan()
{
    const bool be = EPICS_BYTE_ORDER==EPICS_ENDIAN_BIG;
    const auto self = shared_from_this();

    EvInBuf M(peerBE, segBuf.get(), 16);

    auto G(iface->server->sourcesLock.lockReader());

    // one channel create request contains main channel names.
    // each of which will received a seperate reply.

    uint16_t count = 0;
    from_wire(M, count);
    for(auto i : range(count)) {
        (void)i;
        uint32_t cid = -1, sid = -1;
        std::string name;
        from_wire(M, cid);
        from_wire(M, name);

        if(!M.good() || name.empty())
            break;

        Status sts{Status::Ok};

        bool claimed = false;

        if(chanByCID.size()==0xffffffff || chanBySID.size()==0xffffffff) {
            sts.code = Status::Error;
            sts.msg = "Too many Server channels";
            sts.trace = "pvx:serv:chanidoverflow:";

        } else if(chanByCID.find(cid)!=chanByCID.end()) {
            sts.code = Status::Fatal;
            sts.msg = "Client reuses existing CID";
            sts.trace = "pvx:serv:dupcid:";

        } else {
            do {
                sid = nextSID++;
            } while(chanBySID.find(sid)!=chanBySID.end());

            std::shared_ptr<ServerChan> chan(new ServerChan(self, sid, cid, name));
            std::unique_ptr<server::ChannelControl> op(new ServerChannelControl(self, chan));

            for(auto& pair : iface->server->sources) {
                try {
                    pair.second->onCreate(std::move(op));
                    if(!op || chan->handler || chan->state!=ServerChan::Creating) {
                        claimed = chan->state==ServerChan::Creating;
                        log_printf(connsetup, PLVL_DEBUG, "Client %s %s channel to %s through %s\n", peerName.c_str(),
                                   claimed?"accepted":"rejected", name.c_str(), pair.first.second.c_str());
                        break;
                    }
                }catch(std::exception& e){
                    log_printf(connsetup, PLVL_ERR, "Client %s Unhandled error in onCreate %s,%d %s : %s\n", peerName.c_str(),
                               pair.first.second.c_str(), pair.first.first,
                               typeid(&e).name(), e.what());
                }
            }

            if(claimed && chan->state==ServerChan::Creating) {
                chanByCID[cid] = chan;
                chanBySID[sid] = chan;
                chan->state = ServerChan::Active;

            } else {
                sts.code = Status::Fatal;
                sts.msg = "Refused to create Channel";
                sts.trace = "pvx:serv:refusechan:";

                sid = -1;
            }

            // ServerChannelControl destroyed it not saved by claiming Source
        }


        {
            (void)evbuffer_drain(txBody.get(), evbuffer_get_length(txBody.get()));

            EvOutBuf R(be, txBody.get());
            to_wire(R, cid);
            to_wire(R, sid);
            to_wire(R, sts);
            // "spec" calls for uint16_t Access Rights here, but pvAccessCPP don't include this (it's useless anyway)
            if(!R.good()) {
                M.fault();
                log_printf(connio, PLVL_ERR, "Client %s Encode error in CreateChan\n", peerName.c_str());
                break;
            }
        }

        auto tx = bufferevent_get_output(bev.get());
        to_evbuf(tx, Header{pva_app_msg::CreateChan,
                            pva_flags::Server,
                            uint32_t(evbuffer_get_length(txBody.get()))},
                 be);
        auto err = evbuffer_add_buffer(tx, txBody.get());
        assert(!err);
    }

    if(!M.good()) {
        log_printf(connio, PLVL_ERR, "Client %s Decode error in CreateChan\n", peerName.c_str());
        bev.reset();
    }
}

void ServerConn::handle_DestroyChan()
{
    EvInBuf M(peerBE, segBuf.get(), 16);

    uint32_t sid=-1, cid=-1;

    from_wire(M, sid);
    from_wire(M, cid);

    auto it = chanBySID.find(sid);
    if(M.good() && it!=chanBySID.end()) {
        {
            auto& chan = it->second;
            if(chan->cid!=cid) {
                log_printf(connsetup, PLVL_DEBUG, "Client %s provides incorrect CID with DestroyChan sid=%d cid=%d!=%d '%s'\n", peerName.c_str(),
                           unsigned(sid), unsigned(chan->cid), unsigned(cid), chan->name.c_str());
            }
        }

        auto n = chanByCID.erase(cid);
        assert(n==1);

        chanBySID.erase(it);
        assert(it->second.use_count()==1); // we only take transient refs on this thread
        // ServerChannel is delete'd

        {
            auto tx = bufferevent_get_output(bev.get());
            constexpr bool be = EPICS_BYTE_ORDER==EPICS_ENDIAN_BIG;
            EvOutBuf R(be, tx);
            to_wire(R, Header{pva_app_msg::DestroyChan, pva_flags::Server, 8});
            to_wire(R, sid);
            to_wire(R, cid);
        }

    } else {
        log_printf(connsetup, PLVL_DEBUG, "Client %s DestroyChan non-existant sid=%d cid=%d\n", peerName.c_str(),
                   unsigned(sid), unsigned(cid));
    }

    if(!M.good())
        bev.reset();
}

} // namespace pvxsimpl
