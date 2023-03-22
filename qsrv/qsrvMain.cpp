/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * qsrvMain.cpp: The main entry point for the pvxs qsrv soft IOC.
 * Use this as is, or as the base for your customised IOC application
 */
#include <iostream>
#include "epicsExit.h"
#include "epicsThread.h"
#include "iocsh.h"

#include <epicsGetopt.h>
#include <dbAccess.h>
#include <registryFunction.h>
#include <subRecord.h>
#include <asDbLib.h>
#include <iocInit.h>
#include "pvxs/iochooks.h"

#include "qsrvMain.h"

namespace pvxs {
namespace qsrv {

static void exitCallback(subRecord* pRecord);

// Verbose flag - if true then show verbose output
bool verboseFlag = false;
// Macro to use to show verbose output
// e.g. VERBOSE_MESSAGE "some verbose message: " << variable << " more verbosity\n";
#define VERBOSE_MESSAGE if (verboseFlag) std::cout <<

// DB Loaded flag - true if the database has already been loaded
bool isDbLoaded = false;

/**
 * Print out usage information for the QSRV application
 *
 * @param executableName 	 the name of the executable as passed to main
 * @param initialisationFile the name of the database initialization file. Either the one
 * 							 specified on the commandline or the default one
 */
void usage(std::string& executableName, const std::string& initialisationFile) {
    std::string executableBaseName = executableName
            .substr(executableName.find_last_of(OSI_PATH_SEPARATOR) + 1) // NOLINT(performance-faster-string-find)
            ;
    std::cout << "PVXS configurable IOC server\n\n"
	             "Usage: " << executableBaseName <<
                 " [-h] [-S] [-v] \n"
	          " [-m <macro-name>=<macro-value>[,<macro-name>=<macro-value>]...] ... \n"
	          " [-D <path>] [-G <path>] [-a <path>] [-d <path>] \n"
	          " [-x <prefix>] [<script-path>]\n"
	          "\nDescription:\n"
	          "  Start an in-memory database of PV records which can be accessed via PVAccess, and start an IOC shell.\n\n"
	          "  After configuring the in-memory database with " << initialisationFile.c_str()
              << "\n  (or overriden with the -D option) this command starts an interactive IOC shell, unless the -S flag \n"
	             "  is specified.  Group configuration can optionally be specified using the -G flag, and security can be \n"
	             "  configured using the -a flag.  An initial database of PV records can be established using the -d flag.  \n"
	             "  Finally some startup commands can be run if an optional script-path is specified."
	             "\n"
	             "\nCommon flags:\n"
	             "  -h                     Print this message and exit.\n"
	             "  -S                     Prevents an interactive shell being started. \n"
	             "  -v                     Verbose, display steps taken during startup.\n"
	             "  -D <path>              This overrides the default database configuration file.\n"
	             "                         If specified, it must come before any (-G), (-a), or (-d) flags. Specify \n"
	             "                         the path to the configuration file as well as the\n"
	             "                         extension.  By convention, this file has a .dbd \n"
	             "                         extension.  The compile-time default configuration file\n"
	             "                         is " FULL_PATH_TO_INITIALISATION_FILE ".\n"
	             "  -m <name>=<value>[,<name>=<value>]... \n"
	             "                         Set/replace macro definitions. Macros are used in the \n"
	             "                         iocsh as well as when parsing the access security configuration \n"
	             "                         (-a) and database records file (-d).  You can provide a (-m) flag \n"
	             "                         multiple times on the same command line.  Each occurrence applies to any \n"
	             "                         (-a) and (-d) options that follow it until the next (-m) overrides.  The last\n"
	             "                         macros defined are used in the iocsh\n"
	             "  -a <path>              Access security configuration file.  Use this flag \n"
	             "                         to configure access security.  The security definitions specified \n"
	             "                         are subject to macro substitution.\n"
	             "  -d <path>              Load database record-definitions and group-definitions from file.  Each record-definition "
				 "                         contains a set of field-definitions: `record(<type>,\"<name>\") { field(<name>,\"<value>\")... }...`. "
	             "                         Additionally group-info-definitions are accepted in the place of field-definitions.\n"
	             "                         group-info-definition := `info(Q:group, {\"<name>\": {<group-field-mapping>...}})`. \n"
	             "                         These group-info-definitions define group-names and map into them the \n"
	             "                         specified fields from the record-definition in which they appear. By convention, \n"
				 "                         the extension is .db.  The definitions specified in the given file are subject to macro substitution \n"
	             "  -G <path>              Load database group-definitions from a JSON file. If path starts with `-` then the remaining portion \n"
				 "                         is treated as a group-definitions file to be removed from the list of files to load.  \n"
				 "                         e.g. `-G -grpFile.json` will remove grpFile.json from the list of group-definitions \n"
				 "                         files to load.  If `-G -*` or `-G -` is specified, then all group-definitions files \n"
				 "                         that have been specified so far will be removed.  By convention, the extension is .json. \n"
	             "  -x <prefix>            Specifies the prefix for the database exit record Load.  It is used as a substitution for \n"
	             "                         the $(IOC) macro in " FULL_PATH_TO_EXIT_FILE ". \n"
	             "                         This file is used to configure database shutdown.\n"
	             "  script-path            A command script is optional.  The iocsh commands will be run *after*\n"
	             "                         calling iocInit().  If you want to run the script before iocInit() then \n"
	             "                         don't specify any (-d), (-G) or (-x) flags and perform all database loading in \n"
	             "                         the script itself, or in the interactive shell including calling iocInit().\n"
	             "\n"
	             "Examples:\n"
	             "  " << executableBaseName
              << " -d my.db\n"
	             "                         use default configuration, load database record-definitions \n"
	             "                         and group-definitions from `my.db`, and start an interactive IOC shell \n"
	             "  " << executableBaseName
              << " -m NAME=PV -d my.db\n"
	             "                         use default configuration, and load database record-definitions \n"
	             "                         and group-definitions from `my.db`, after setting macro `NAME` to `PV`\n"
	             "  " << executableBaseName
              << " -D my-config.dbd -d my.db -G my-group-mappings.json \n"
	             "                         use custom configuration `my-config.dbd` to configure the IOC, \n"
	             "                         load database record-definitions and group-definitions from `my.db`, \n"
				 "                         then load additional group-definitions from `my-group-mappings.json,` \n"
	             "                         and start an interactive shell \n";

}

/**
 * Configure the database if it has not been configured previously
 *
 * @param databaseConfigurationFile the name of the file containing configuration information
 */
void configureDatabase(const std::string& databaseConfigurationFile) {
    // Only load configuration file if it has been configured previously
    if (isDbLoaded) {
        return;
    }
    isDbLoaded = true;

    VERBOSE_MESSAGE "dbLoadDatabase(\"" << databaseConfigurationFile << "\")\n";
    if (dbLoadDatabase(databaseConfigurationFile.c_str(), nullptr, nullptr)) {
        throw std::runtime_error(
                    std::string("Failed to load database configuration file: ") + databaseConfigurationFile);
    }

    //  Must match the dbd you've established in your header file and Makefile as the default configuration file
    VERBOSE_MESSAGE "qsrv_registerRecordDeviceDriver(pdbbase)\n";
    qsrv_registerRecordDeviceDriver(pdbbase);
    registryFunctionAdd("exit", (REGISTRYFUNCTION)exitCallback);
}

/**
 * The exit callback function
 *
 * @param pRecord
 */
void exitCallback(subRecord* pRecord) {
    epicsExitLater((pRecord->a == 0.0) ? EXIT_SUCCESS : EXIT_FAILURE);
}

/**
 * Get the relative path prefix (the directory that this executable is running from)
 *
 * @return the prefix to add to any relative paths
 */
std::string getPrefix() {
    std::string prefix;
    char* cPrefix = epicsGetExecDir();
    if (cPrefix) {
        try {
            prefix = cPrefix;
        } catch (...) {
            free(cPrefix);
            throw;
        }
    }
    free(cPrefix);
    return prefix;
}

/**
 * Parse the command line arguments
 *
 * @param argc argument count
 * @param argv argument values
 * @param databaseInitialisationFile the default database initialization file, overridden by (-D) option if specified
 * @param dbIsLoaded set to true if database is loaded by a (-d) or (-x) option
 * @param shouldStartAnInteractiveSession set to true if an interactive session should be started, overridden by (-S) option if specified
 * @param scriptName set to the scriptName if specified
 *
 * @return positive integer if unsuccessful, negative if successful but needs to exit, zero means success
 */
int parseOptions(int argc, char* argv[], std::string& databaseInitialisationFile, bool& dbIsLoaded,
                 bool& shouldStartAnInteractiveSession, std::string& scriptName) {
    std::string iocExecutableName(argv[0]);
    std::string databaseShutdownFile(FULL_PATH_TO_EXIT_FILE);

    std::string commaSeparatedListOfMacroDefinitions;   // This is set if a (-m) option is specified

    // compute relative paths
    {
        std::string prefix = getPrefix();

        databaseInitialisationFile = prefix + RELATIVE_PATH_TO_INITIALISATION_FILE;
        databaseShutdownFile = prefix + RELATIVE_PATH_TO_SHUTDOWN_FILE;
    }

    // Parse the command line and configure and start the IOC
    int opt;        // parsed option from the command line
    while ((opt = getopt(argc, argv, "a:D:d:G:hm:Svx:")) != -1) {
        switch (opt) {
        case 'a':
            configureDatabase(databaseInitialisationFile);
            if (!commaSeparatedListOfMacroDefinitions.empty()) {
                VERBOSE_MESSAGE "asSetSubstitutions(\"" << commaSeparatedListOfMacroDefinitions << "\")\n";
                if (asSetSubstitutions(commaSeparatedListOfMacroDefinitions.c_str()))
                    throw std::bad_alloc();
            }
            VERBOSE_MESSAGE "asSetFilename(\"" << optarg << "\")\n";
            if (asSetFilename(optarg)) {
                throw std::bad_alloc();
            }
            break;
        case 'D':
            if (isDbLoaded) {
                throw std::runtime_error("database configuration file override specified "
				                         "after " FULL_PATH_TO_INITIALISATION_FILE " has already been loaded.\n"
				                         "Add the -D option prior to any -d or -x options and try again");
            }
            databaseInitialisationFile = optarg;
            break;
        case 'd':
            configureDatabase(databaseInitialisationFile);
            VERBOSE_MESSAGE "dbLoadRecords(\"" << optarg << "\""
			                                   << ((commaSeparatedListOfMacroDefinitions.empty()) ? "" :
                                                                                                    std::string(", \"").append(commaSeparatedListOfMacroDefinitions)
                                                                                                    .append("\""))
                                               << ")\n";

            if (dbLoadRecords(optarg, commaSeparatedListOfMacroDefinitions.c_str())) {
                throw std::runtime_error(std::string("Failed to load: ") + optarg);
            }

            dbIsLoaded = true;
            break;
        case 'G':
            pvxs::ioc::dbLoadGroup(optarg);
            break;
        case 'h':
            usage(iocExecutableName, databaseInitialisationFile);
            epicsExit(0);
            return -1;
        case 'm':
            commaSeparatedListOfMacroDefinitions = optarg;
            break;
        case 'S':
            shouldStartAnInteractiveSession = false;
            break;
        case 'v':
            verboseFlag = true;
            break;
        case 'x': {
            std::string xmacro;
            configureDatabase(databaseInitialisationFile);
            xmacro = "IOC=";
            xmacro += optarg;

            if (dbLoadRecords(databaseShutdownFile.c_str(), xmacro.c_str())) {
                throw std::runtime_error(std::string("Failed to load: ") + databaseShutdownFile);
            }

            dbIsLoaded = true;
        }
            break;
        default:
            usage(iocExecutableName, databaseInitialisationFile);
            std::cerr << "Unknown argument: -" << char(optopt) << "\n";
            epicsExit(2);
            return 2;
        }
    }

    // If script specified then return name
    if (optind < argc) {
        scriptName = argv[optind];
    }

    return 0;
}

}
} // pvxs::qsrv

using namespace pvxs::qsrv;

/**
 * Main entry point for the qsrv executable.
 *
 * @param argc the number of command line arguments
 * @param argv the command line arguments
 * @return 0 for successful exit, nonzero otherwise
 */
int main(int argc, char* argv[]) {
    try {
        std::string databaseInitialisationFile(FULL_PATH_TO_INITIALISATION_FILE);
        std::string scriptName;
        bool shouldStartAnInteractiveSession = true;        // Default is true, unless (-S) option is specified
        bool dbIsLoaded = false;                            // Is database loaded
        auto status = parseOptions(argc, argv,
                                   databaseInitialisationFile, dbIsLoaded, shouldStartAnInteractiveSession, scriptName);
        if (status != 0) {
            return status > 0 ? status : 0;
        }

        // Configure the database with the specified configuration file
        configureDatabase(databaseInitialisationFile);

        // If we've loaded a database file or configured the exit callback, then do an iocInit()
        if (dbIsLoaded) {
            VERBOSE_MESSAGE "iocInit()\n";
            iocInit();
            epicsThreadSleep(0.2);
        }

        // If we've specified a script on the command line then run it
        bool userScriptHasBeenExecuted = false;
        if (!scriptName.empty()) {
            VERBOSE_MESSAGE "# Begin execution of: " << scriptName << "\n";
            if (iocsh(scriptName.c_str())) {
                throw std::runtime_error(std::string("Error in ") + scriptName);
            }
            VERBOSE_MESSAGE "# End execution of: " << scriptName << "\n";

            epicsThreadSleep(0.2);
            userScriptHasBeenExecuted = true;
        }

        // If we haven't disabled the interactive shell then enter it
        if (shouldStartAnInteractiveSession) {
            std::cout.flush();
            std::cerr.flush();
            if (iocsh(nullptr)) {
                // if error status then propagate error to epics and shell
                epicsExit(1);
                return 1;
            }
        } else {
            // If non-interactive then exit
            if (dbIsLoaded || userScriptHasBeenExecuted) {
                epicsExitCallAtExits();
                epicsThreadSleep(0.1);
                epicsThreadSuspendSelf();
            } else {
                // Indicate that there was probably an error if nothing was loaded or executed
                std::cerr << "Nothing to do!\n";
                epicsExit(1);
                return 1;
            }
        }

        epicsExit(0);
        return (0);
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        epicsExit(2);
        return 2;
    }
}
