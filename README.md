# PVXS - PVAccess Protocol Client/Server Library

[![GitHub](https://img.shields.io/github/v/release/epics-base/pvxs)](https://github.com/epics-base/pvxs/releases)
[![Documentation](https://img.shields.io/badge/docs-online-blue)](https://epics-base.github.io/pvxs/)

**PVXS** is a modern C++ library providing comprehensive client and server support for the PVAccess (PVA) protocol, an integral component of the EPICS control system framework. It offers a clean, type-safe API for building distributed control system applications.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Documentation](#documentation)
- [Examples](#examples)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

## Overview

PVXS provides three main components:

1. **Data Container API** (`pvxs::Value`) - Type-safe data structure handling with automatic change tracking
2. **Client API** (`pvxs::client`) - Connect to and interact with PVAccess servers
3. **Server API** (`pvxs::server`) - Create PVAccess servers to serve process variables

PVXS is designed as a modern alternative to pvDataCPP and pvAccessCPP, offering:
- Simplified API using functors instead of interface classes
- Type-safe operations without explicit downcasting
- Built-in change tracking for efficient updates
- Comprehensive support for EPICS Normative Types
- Integration with EPICS IOC Process Database (QSRV 2)

### What is PVAccess?

PVAccess is a network protocol supporting both request/response and publish/subscribe operations. It's closely related to Channel Access (CA) and is designed to work alongside or supersede it. PVAccess supports four primary operations:

- **Get** - Fetch the present value of a Process Variable (PV)
- **Put** - Change the value of a PV
- **Monitor** - Subscribe to changes in a PV's value
- **RPC** - Remote procedure call

### What is a Process Variable (PV)?

In EPICS, a Process Variable (PV) is a globally addressable data structure that represents a piece of equipment state or measurement. PVs are identified by unique names (e.g., `mylab:temp1`, `mylab:valve2`). A typical EPICS control system contains millions of PVs across multiple IOCs (Input/Output Controllers).

## Features

### Client Features
- ✅ Simple, intuitive API for Get, Put, Monitor, and RPC operations
- ✅ Automatic server discovery via UDP broadcast
- ✅ Connection management and automatic reconnection
- ✅ Support for field selection and partial updates
- ✅ Thread-safe operations
- ✅ Configurable via environment variables

### Server Features
- ✅ High-performance PVAccess protocol server
- ✅ Support for static and dynamic PV sources
- ✅ Built-in IOC integration (QSRV 2)
- ✅ Access security support
- ✅ Automatic PV registration and discovery
- ✅ Configurable via environment variables

### Data API Features
- ✅ Type-safe value containers with compile-time checking
- ✅ Automatic change tracking (no separate BitSet objects)
- ✅ Support for all EPICS scalar and array types
- ✅ Built-in Normative Types (NTScalar, NTArray, NTTable, etc.)
- ✅ Custom structure definition
- ✅ Efficient array handling with `shared_array`

### Integration Features
- ✅ EPICS IOC integration (QSRV 2) - automatically serve database records
- ✅ Command-line tools for testing and debugging
- ✅ Python bindings available (pvxslibs package)
- ✅ Comprehensive logging and debugging support

## Requirements

### Compiler
- C++11 compliant compiler:
  - GCC >= 4.8
  - Clang >= 3.3
  - Visual Studio >= 2015 / 12.0

### Dependencies
- **EPICS Base** >= 3.15.1
- **libevent** >= 2.0.1 (optionally bundled with PVXS)
- **CMake** >= 3.10 (only needed when building bundled libevent)

### Operating Systems
- Linux (various distributions)
- macOS
- Windows (via MinGW or Visual Studio)

## Quick Start

### Installation

For detailed installation instructions, see [INSTALLATION.md](docs/INSTALLATION.md).

**Basic installation from source:**

```bash
# Clone the repository
git clone --recursive https://github.com/epics-base/pvxs.git
git clone --branch 7.0 https://github.com/epics-base/epics-base.git

# Configure PVXS
cat <<EOF > pvxs/configure/RELEASE.local
EPICS_BASE=\$(TOP)/../epics-base
EOF

# Build EPICS Base
make -C epics-base

# Build PVXS
make -C pvxs
```

### Simple Client Example

```cpp
#include <pvxs/client.h>
#include <pvxs/log.h>

int main() {
    using namespace pvxs;
    
    // Configure client from environment ($EPICS_PVA_*)
    auto ctxt = client::Context::fromEnv();
    
    // Get a PV value (blocking)
    Value result = ctxt.get("some:pv:name")
                   .exec()
                   ->wait(5.0);
    
    std::cout << result << std::endl;
    return 0;
}
```

### Simple Server Example

```cpp
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/nt.h>

int main() {
    using namespace pvxs;
    
    // Create an NTScalar structure
    Value initial = nt::NTScalar{TypeCode::Float64}.create();
    initial["value"] = 42.0;
    
    // Create a mailbox PV (stores whatever clients send)
    server::SharedPV pv(server::SharedPV::buildMailbox());
    pv.open(initial);
    
    // Create server and add PV
    server::Server::fromEnv()
        .addPV("my:pv:name", pv)
        .run();  // Run until SIGINT
    
    return 0;
}
```

### Using with EPICS IOC

Simply add PVXS to your IOC:

```makefile
# In configure/RELEASE.local
PVXS=/path/to/pvxs
EPICS_BASE=/path/to/epics-base

# In Makefile
PROD_IOC += myioc
myioc_DBD += pvxsIoc.dbd
myioc_LIBS += pvxsIoc pvxs
```

All database records will automatically be served via PVAccess!

## Installation

For comprehensive installation instructions covering:
- Detailed build instructions
- Platform-specific notes
- Dependency installation
- Cross-compilation
- Testing

See [INSTALLATION.md](docs/INSTALLATION.md).

For a quick start guide, see [QUICKSTART.md](docs/QUICKSTART.md).

## Documentation

### Online Documentation

The complete API documentation is available at:
**https://epics-base.github.io/pvxs/**

### Local Documentation

Build documentation from source:

```bash
cd documentation
make html
# Documentation will be in _build/html/
```

### Key Documentation Sections

| Section | Description |
|:--------|:------------|
| [Overview](https://epics-base.github.io/pvxs/overview.html) | Introduction and concepts |
| [Client API](https://epics-base.github.io/pvxs/client.html) | Client usage and examples |
| [Server API](https://epics-base.github.io/pvxs/server.html) | Server implementation guide |
| [Value Container API](https://epics-base.github.io/pvxs/value.html) | Data structure handling |
| [IOC Integration](https://epics-base.github.io/pvxs/ioc.html) | EPICS IOC integration |
| [QSRV 2](https://epics-base.github.io/pvxs/qgroup.html) | High-level IOC integration |
| [Network Configuration](https://epics-base.github.io/pvxs/netconfig.html) | PVAccess network setup |
| [Command Line Tools](https://epics-base.github.io/pvxs/cli.html) | CLI utilities |

### Documentation Quick Links

**User Guides (Markdown):**

- [Quick Start Guide](docs/QUICKSTART.md) - Step-by-step tutorial for new users
- [Installation Guide](docs/INSTALLATION.md) - Detailed installation instructions
- [Troubleshooting Guide](docs/TROUBLESHOOTING.md) - Common issues and solutions
- [Architecture Guide](docs/ARCHITECTURE.md) - System design overview
- [Contributing Guide](docs/CONTRIBUTING.md) - How to contribute to PVXS
- [Documentation Index](docs/DOCUMENTATION.md) - Complete documentation navigation

**API Reference (Online RST Documentation):**

- [Client API - Get/Info](https://epics-base.github.io/pvxs/client.html#get-info) - Get operations and info queries
- [Client API - Put](https://epics-base.github.io/pvxs/client.html#clientputapi) - Put operations
- [Client API - Monitor](https://epics-base.github.io/pvxs/client.html#clientmonapi) - Monitor subscriptions
- [Client API - RPC](https://epics-base.github.io/pvxs/client.html#clientrpcapi) - Remote procedure calls
- [Server API](https://epics-base.github.io/pvxs/server.html) - Server implementation guide
- [Value Container API](https://epics-base.github.io/pvxs/value.html) - Data structure handling
- [Value API - Field Lookup](https://epics-base.github.io/pvxs/value.html#field-lookup) - Accessing fields
- [Value API - Arrays](https://epics-base.github.io/pvxs/value.html#array-fields) - Array handling
- [Network Configuration](https://epics-base.github.io/pvxs/netconfig.html) - PVAccess network setup
- [IOC Integration](https://epics-base.github.io/pvxs/ioc.html) - EPICS IOC integration
- [QSRV 2](https://epics-base.github.io/pvxs/qgroup.html) - High-level IOC integration

## Examples

The repository includes several example programs in the `example/` directory:

### Building Examples

```bash
cd example
make
# Executables will be in O.<host-arch>/
```

### Available Examples

Browse the example source code in the [`example/`](example/) directory:

- **[simpleget.cpp](example/simpleget.cpp)** - Minimal client GET operation
  - Demonstrates basic client usage with blocking `wait()` call
  - See [Client API - Get/Info](https://epics-base.github.io/pvxs/client.html#get-info) for details
  
- **[simplesrv.cpp](example/simplesrv.cpp)** - Minimal server example
  - Shows how to create and serve a simple PV
  - See [Server API](https://epics-base.github.io/pvxs/server.html) for details
  
- **[client.cpp](example/client.cpp)** - Comprehensive client demonstration
  - Demonstrates Get, Put with present value fetching, and result handling
  - See [Client API](https://epics-base.github.io/pvxs/client.html) for all client operations
  
- **[mailbox.cpp](example/mailbox.cpp)** - Mailbox server with PUT handler
  - Shows custom PUT validation, range checking, and timestamp handling
  - See [SharedPV API](https://epics-base.github.io/pvxs/sharedpv.html) for server-side handlers
  
- **[rpc_client.cpp](example/rpc_client.cpp)** - RPC client example
  - Demonstrates remote procedure calls
  - See [Client API - RPC](https://epics-base.github.io/pvxs/client.html#clientrpcapi) for details
  
- **[rpc_server.cpp](example/rpc_server.cpp)** - RPC server example
  - Shows how to implement RPC handlers
  - See [SharedPV API](https://epics-base.github.io/pvxs/sharedpv.html) for RPC handlers
  
- **[ticker.cpp](example/ticker.cpp)** - Periodic update server
  - Demonstrates periodic updates using `post()` to notify subscribers
  - See [SharedPV - Posting Updates](https://epics-base.github.io/pvxs/sharedpv.html) for monitor updates

See also the [Examples documentation](https://epics-base.github.io/pvxs/example.html) for detailed explanations.

### Running Examples

```bash
# Terminal 1: Start a mailbox server
./O.linux-x86_64/mailbox test:pv:1

# Terminal 2: Connect with client
./O.linux-x86_64/client test:pv:1
```

## Command Line Tools

PVXS provides several command-line tools for testing and debugging:

| Tool | Description |
|:-----|:------------|
| `pvxget` | Get PV value (analogous to `pvget`) |
| `pvxput` | Put PV value (analogous to `pvput`) |
| `pvxmonitor` | Monitor PV updates (analogous to `pvmonitor`) |
| `pvxinfo` | Get PV information (analogous to `pvinfo`) |
| `pvxcall` | Execute RPC (analogous to `pvcall`) |
| `pvxlist` | List available PVs |
| `pvxvct` | UDP search/beacon troubleshooting tool |

### Example Usage

```bash
# Get a PV value
pvxget my:pv:name

# Monitor a PV for changes
pvxmonitor my:pv:name

# Put a value
pvxput my:pv:name 42.0

# Get PV information
pvxinfo my:pv:name

# Debug network issues
pvxvct -C -P my:pv:name
```

For detailed tool documentation, see the [CLI Tools documentation](https://epics-base.github.io/pvxs/cli.html).

## Architecture

For a detailed architecture overview, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).

### High-Level Overview

The PVXS library follows a layered architecture:

```
┌─────────────────────────────────────────────────────────┐
│                    PVXS Library                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │   Client     │  │    Server    │  │   Value      │   │
│  │     API      │  │     API      │  │     API      │   │
│  └──────────────┘  └──────────────┘  └──────────────┘   │
│         │                  │                  │         │
│         └──────────────────┼──────────────────┘         │
│                            │                            │
│                 ┌──────────┴──────────┐                 │
│                 │  PVA Protocol       │                 │
│                 │  Implementation     │                 │
│                 └──────────┬──────────┘                 │
│                            │                            │
└────────────────────────────┼────────────────────────────┘
                             │
                ┌────────────┴───────────┐
                │                        │
         ┌──────▼──────┐          ┌──────▼───────┐
         │  EPICS Base │          │  libevent    │
         │   (OSD)     │          │  (Networking)│
         └─────────────┘          └──────────────┘
```

### Key Components

1. **Client Context** - Manages connections to PVAccess servers
2. **Server Instance** - Listens for and handles client connections
3. **Value Container** - Type-safe data structure representation
4. **Network Layer** - PVAccess protocol implementation
5. **IOC Integration** - QSRV 2 for automatic database serving

## Network Configuration

PVXS uses environment variables for network configuration. See the [Network Configuration documentation](https://epics-base.github.io/pvxs/netconfig.html) for complete details.

### Client Configuration (`$EPICS_PVA_*`)

| Variable | Description |
|:---------|:------------|
| `EPICS_PVA_ADDR_LIST` | Server address list |
| `EPICS_PVA_AUTO_ADDR_LIST` | Enable/disable auto-discovery |
| `EPICS_PVA_SERVER_PORT` | Server port (default: 5075) |
| `EPICS_PVA_BROADCAST_PORT` | Broadcast port (default: 5076) |

### Server Configuration (`$EPICS_PVAS_*` or `$EPICS_PVA_*`)

| Variable | Description |
|:---------|:------------|
| `EPICS_PVAS_SERVER_PORT` | Server listening port |
| `EPICS_PVAS_BEACON_ADDR_LIST` | Beacon destination addresses |
| `EPICS_PVAS_AUTO_BEACON_ADDR_LIST` | Enable/disable auto-beaconing |

## Contributing

Contributions are welcome! Please see the [Contributing Guide](docs/CONTRIBUTING.md) for details.

For detailed contribution guidelines, see the [Contributing Guidelines](https://epics-base.github.io/pvxs/details.html#contributing) in the online API documentation.

### Development Workflow

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Run the test suite: `make runtests`
6. Submit a pull request

### Reporting Issues

Report bugs and request features on the [GitHub Issues](https://github.com/epics-base/pvxs/issues) page.

For bug reports, please include:
- PVXS version
- Operating system and version
- Compiler and version
- Steps to reproduce
- Relevant configuration
- Log output (if applicable)

## License

PVXS is distributed subject to a Software License Agreement found in the [LICENSE](LICENSE) file. See [COPYRIGHT](COPYRIGHT) for copyright information.

## Support

### Resources

- **Documentation**: https://epics-base.github.io/pvxs/
- **GitHub Repository**: https://github.com/epics-base/pvxs
- **Issue Tracker**: https://github.com/epics-base/pvxs/issues
- **EPICS Homepage**: https://epics-controls.org/

### Getting Help

1. Check the [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) guide
2. Search existing [GitHub Issues](https://github.com/epics-base/pvxs/issues)
3. Consult the [online documentation](https://epics-base.github.io/pvxs/)
4. Post questions on [EPICS Tech-Talk](https://epics.anl.gov/tech-talk/)

### Version Information

Current version information can be found in:
- `configure/CONFIG_PVXS_VERSION`
- `pvxs/version.h` (after building)

---

## Acknowledgments

This comprehensive documentation suite (README.md, INSTALLATION.md, TROUBLESHOOTING.md, ARCHITECTURE.md, and related documentation) was created and organized by **K. Gofron**, Oak Ridge National Laboratory, December 28, 2025. The integration of markdown user guides into the unified Sphinx environment and reorganization into logical subdirectories was completed in December 2025.

---

**PVXS** is part of the EPICS collaboration. For more information about EPICS, visit https://epics-controls.org/.
