/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include <vector>

#include <string.h>

#include <epicsExport.h>
#include <epicsString.h>
#include <iocsh.h>

#include <initHooks.h>
#include <iocInit.h>
#include <dbAccess.h>

#include <pvxs/source.h>
#include <pvxs/iochooks.h>

#include "qsrvpvt.h"
#include "groupsource.h"
#include "groupconfigprocessor.h"
#include "iocshcommand.h"

#if EPICS_VERSION_INT < VERSION_INT(7, 0, 3, 1)
#  define iocshSetError(ret) do { (void)ret; }while(0)
#endif
#ifndef ERL_ERROR
#  define ERL_ERROR "ERROR"
#endif

// include last to avoid clash of #define printf with other headers
#include <epicsStdio.h>
namespace pvxs {
namespace ioc {

/**
 * IOC command wrapper for dbLoadGroup function
 *
 * @param jsonFileName
 */
static
void dbLoadGroupCmd(const char* jsonFileName, const char *macros) {
    iocshSetError(!!dbLoadGroup(jsonFileName, macros));
}

/**
 * List group db record/field names that are registered with the pvxs IOC server.
 * With no arguments this will list all the group record names.
 *
 * @param level optional depth to show details for
 * @param pattern optionally only show records matching the regex pattern
 */
static
void pvxsgl(int level, const char* pattern) {
    // Default pattern to match everything
    if (!pattern) {
        pattern = "";
    }

    {
        auto& config(IOCGroupConfig::instance());
        epicsGuard<epicsMutex> G(config.groupMapMutex);

        // For each group
        for (auto& mapEntry: config.groupMap) {
            auto& groupName = mapEntry.first;
            auto& group = mapEntry.second;
            // if no pattern specified or the pattern matches
            if (!pattern[0] || !!epicsStrGlobMatch(groupName.c_str(), pattern)) {
                // Print the group name
                printf("%s\n", groupName.c_str());
                // print sub-levels if required
                if (level > 0) {
                    group.show(level);
                }
            }
        }
    }
}

static
const auto dbLoadGroupMsg =
        "dbLoadGroup(\"file.json\")\n"
        "dbLoadGroup(\"file.json\", \"MAC=value,...\")\n"
        "\n"
        "Load additional DB group definitions from file.\n"
        "\n"
        "dbLoadGroup(\"-*\")\n"
        "dbLoadGroup(\"-file.json\")\n"
        "dbLoadGroup(\"-file.json\", \"MAC=value,...\")\n"
        "\n"
        "Remove all, or one, previously added group definitions.\n"
        ;

long dbLoadGroup(const char* jsonFilename, const char* macros) {
    try {
        /* getIocState() introduced to the 3.15 branch in R3.15.8
         *                                 7.0 branch in R7.0.4
         */
#if EPICS_VERSION_INT >= VERSION_INT(7, 0, 4, 0) \
    || (EPICS_VERSION_INT < VERSION_INT(7, 0, 0, 0) && EPICS_VERSION_INT >= VERSION_INT(3, 15, 8, 0))
        if(getIocState() != iocVoid)
        {
            fprintf(stderr,
                    ERL_ERROR " dbLoadGroup() not allowed in current IOC state (%d).\n"
                    "              Hint: Move before iocInit()\n",
                    getIocState()
                    );
            return 1;
        }
#else
        if(interruptAccept)
        {
            fprintf(stderr,
                    ERL_ERROR " dbLoadGroup() not allowed in current IOC state.\n"
                    "              Hint: Move before iocInit()\n");
            return 1;
        }
#endif

        if (!jsonFilename || !jsonFilename[0]) {
            fprintf(stderr, "%s\n"
                            "Error: Missing required JSON filename\n", dbLoadGroupMsg);
            return 1;
        }
        if(!macros)
            macros = "";

        bool remove = jsonFilename[0] == '-';
        if(remove)
            jsonFilename++;

        auto& config(IOCGroupConfig::instance());
        auto& gCF = config.groupConfigFiles;

        if(strcmp(jsonFilename, "*")==0) {
            gCF.clear();
            return 0;
        }

        decltype(IOCGroupConfig::JFile::jf) jfile;
        decltype(IOCGroupConfig::JFile::handle) macs;
        if(!remove) {
            jfile.reset(new std::ifstream(jsonFilename));
            if (!jfile->is_open()) {
                fprintf(stderr, "Error opening \"%s\"\n", jsonFilename);
                return 1;
            }

            if(macros[0]!='\0') {
                MAC_HANDLE* mac;
                const char * env_pair[] = {"", "environ", NULL, NULL};
                if(macCreateHandle(&mac, env_pair))
                    throw std::bad_alloc();
                macs.reset(mac);

                char **pairs = nullptr;

                auto noinstall = macParseDefns(mac, macros, &pairs)<0 || macInstallMacros(mac, pairs)<0;
                free(pairs);
                if(noinstall) {
                    fprintf(stderr, "Error Invalid macros for \"%s\", \"%s\"\n",
                            jsonFilename, macros);
                    return 1;
                }
            }

        }

        for(auto next(gCF.begin()); next != gCF.end();)
        {
            auto it(next++);
            if(it->fname==jsonFilename && it->macros==macros)
                config.groupConfigFiles.erase(it);
        }

        if(!remove) {
            gCF.emplace_back(std::move(jfile), jsonFilename, macros, std::move(macs));
        }
        return 0;
    } catch (std::exception& e) {
        fprintf(stderr, "Error: %s\n", e.what());
        return 1;
    }
}


void processGroups()
{
    GroupConfigProcessor processor;
    epicsGuard<epicsMutex> G(processor.config.groupMapMutex);

    // Parse all info(Q:Group... records to configure groups
    processor.loadConfigFromDb();

    // Load group configuration files
    processor.loadConfigFiles();

    // checks on groupConfigMap
    processor.validateGroups();

    // Configure groups
    processor.defineGroups();

    // Resolve triggers
    processor.resolveTriggerReferences();

    // Create Server Groups
    processor.createGroups();
}

void addGroupSrc()
{
    pvxs::ioc::server()
            .addSource("qsrvGroup", std::make_shared<pvxs::ioc::GroupSource>(), 1);
}

void resetGroups()
{
    auto& config(IOCGroupConfig::instance());

    // server stopped at this point, but lock anyway
    epicsGuard<epicsMutex> G(config.groupMapMutex);

    config.groupMap.clear();
    config.groupConfigFiles.clear();
}

void group_enable() {
    // Register commands to be available in the IOC shell
    IOCShCommand<int, const char*>("pvxgl", "[level, [pattern]]",
                                   "Group Sources list.\n"
                                   "List record/field names.\n"
                                   "If `level` is set then show only down to that level.\n"
                                   "If `pattern` is set then show records that match the pattern.")
            .implementation<&pvxsgl>();

    IOCShCommand<const char*, const char*>("dbLoadGroup",
                                           "JSON file", "macros", dbLoadGroupMsg)
            .implementation<&dbLoadGroupCmd>();
}

}} // namespace pvxs::ioc
