/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <iostream>
#include <fstream>

#include <epicsTime.h>
#include <epicsGetopt.h>

#include <pvxs/server.h>
#include <pvxs/source.h>
#include <pvxs/data.h>
#include <pvxs/nt.h>
#include <pvxs/log.h>

namespace {
using namespace pvxs;

DEFINE_LOGGER(app, "mcat");

auto def = nt::NTScalar{TypeCode::String}.build();

struct FileSource : public server::Source
{
    std::string name;
    std::string fname;

    virtual void onSearch(Search &search) override final
    {
        for(auto& op : search) {
            if(op.name()==name) {
                log_info_printf(app, "Claiming '%s'\n", op.name());
                op.claim();
            } else {
                log_debug_printf(app, "Ignoring '%s'\n", op.name());
            }
        }
    }
    virtual void onCreate(std::unique_ptr<server::ChannelControl> &&op) override final
    {
        if(op->name()!=name)
            return;

        std::shared_ptr<server::ChannelControl> chan(std::move(op));

        log_info_printf(app, "Create chan '%s'\n", chan->name().c_str());

        chan->onSubscribe([this, chan](std::unique_ptr<server::MonitorSetupOp>&& setup) {

            log_info_printf(app, "Create mon '%s'\n", chan->name().c_str());

            auto fstrm = std::make_shared<std::ifstream>(fname);
            if(!fstrm->is_open()) {
                setup->error("Unable to open file");
                return;
            }

            std::shared_ptr<server::MonitorControlOp> op(setup->connect(def.create())); // unique_ptr becomes shared_ptr

            server::MonitorStat stats;
            op->stats(stats);
            log_info_printf(app, "Queue size %u\n", unsigned(stats.limitQueue));

            op->setWatermarks(0, 0);

            auto refill = [op, fstrm](){
                log_info_printf(app, "fill mon '%s'\n", op->name().c_str());

                std::string line;
                while(std::getline(*fstrm, line)) {
                    auto val = def.create();
                    val["value"] = line;
                    val["alarm.severity"] = 0;

                    log_info_printf(app, "push line '%s'\n", line.c_str());
                    if(!op->forcePost(std::move(val)))
                        return;
                }

                log_info_printf(app, "finished %s\n", fstrm->eof() ? "EOF" : "");
                if(!fstrm->eof()) {
                    auto val = def.create();
                    val["value"] = "";
                    val["alarm.severity"] = 3;
                    op->forcePost(std::move(val));
                }

                op->finish();
            };

            op->onHighMark([refill, op](){
                log_info_printf(app, "mon now '%s'\n", op->name().c_str());
                refill();
            });

            // initial fill
            refill();
        });

        // return a dummy value for info/get
        chan->onOp([](std::unique_ptr<server::ConnectOp>&& conn) {
            conn->connect(def.create());

            conn->onGet([](std::unique_ptr<server::ExecOp>&& op){
                auto val = def.create();
                val["value"] = "No current value to get";
                val["alarm.severity"] = 3;
                op->reply(val);
            });
        });
    }

    virtual List onList() override final
    {
        auto names(std::make_shared<std::set<std::string>>());
        names->insert(name);
        return List{names};
    }
};

void usage(const char *argv0)
{
    std::cerr<<"Usage: "<<argv0<<" <pvname> <filename>\n";
}

} // namespace

int main(int argc, char* argv[])
{
    int opt;
    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
        case 'h':               /* Print usage */
            usage(argv[0]);
            return 0;
        }
    }

    if(argc - optind !=2 ) {
        usage(argv[0]);
        std::cerr<<"\nError incorrect number of positional arguments\n";
        return 1;
    }

    logger_level_set(app.name, pvxs::Level::Info);
    logger_config_env();

    auto src = std::make_shared<FileSource>();
    src->name = argv[optind];
    src->fname = argv[optind+1];

    auto serv = server::Config::from_env()
            .build()
            .addSource("mcat", src);

    std::cout<<"Effective config\n"<<serv.config();

    log_info_printf(app, "Running\n%s", "");
    serv.run();

    return 0;
}
