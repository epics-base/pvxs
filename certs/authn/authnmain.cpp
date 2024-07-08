/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#include <iostream>

#include <epicsGetopt.h>

namespace {
void usage(const char *argv0) {
    std::cerr << "Usage: " << argv0 << " <opts> \n"
                                       "\n"
                                       " -v                   Make more noise.\n";
}

int readOptions(int argc, char *argv[], bool &verbose) {
    int opt;
    while ((opt = getopt(argc, argv, "v")) != -1) {
        switch (opt) {
            case 'v':verbose = true;
                break;
            default:usage(argv[0]);
                std::cerr << "\nUnknown argument: " << char(opt) << std::endl;
                return 2;
        }
    }

    return 0;
}

}  // namespace

int main(int argc, char *argv[]) {
    bool verbose = false;
    auto config = ConfigStd::fromEnv();

    // Read commandline options
    int exit_status;
    if ((exit_status = readOptions(config, argc, argv, verbose))) {
        return exit_status - 1;
    }

}
