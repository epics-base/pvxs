# PVXS Documentation Index

This document provides a comprehensive index of all PVXS documentation, helping you find the information you need quickly.

## Documentation Overview

PVXS documentation is organized into two complementary formats:

1. **User Guides (Markdown)** - Practical guides for getting started, installation, and troubleshooting
2. **API Reference (RST)** - Detailed technical API documentation

Both formats are designed to work together, with extensive cross-referencing.

## Quick Navigation

### 🚀 Getting Started

| Document | Description | Format |
|----------|-------------|--------|
| [README.md](../README.md) | Project overview, features, quick examples | Markdown |
| [QUICKSTART.md](QUICKSTART.md) | Step-by-step tutorial for new users | Markdown |
| [Online Documentation](https://epics-base.github.io/pvxs/) | Complete API reference | RST (online) |

### 📦 Installation

| Document | Description | Format |
|----------|-------------|--------|
| [INSTALLATION.md](INSTALLATION.md) | Detailed installation guide | Markdown |
| [Building from Source](https://epics-base.github.io/pvxs/building.html) | Advanced build options | RST (online) |
| [Network Configuration](https://epics-base.github.io/pvxs/netconfig.html) | Network setup details | RST (online) |

### 🔧 Usage & Development

| Document | Description | Format |
|----------|-------------|--------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | System architecture overview | Markdown |
| [Client API](https://epics-base.github.io/pvxs/client.html) | Client API reference | RST (online) |
| [Server API](https://epics-base.github.io/pvxs/server.html) | Server API reference | RST (online) |
| [Value Container API](https://epics-base.github.io/pvxs/value.html) | Value API reference | RST (online) |
| [Examples](https://epics-base.github.io/pvxs/example.html) | Code examples | RST (online) |

### 🐛 Troubleshooting & Support

| Document | Description | Format |
|----------|-------------|--------|
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Common issues and solutions | Markdown |
| [Bug Reporting](https://epics-base.github.io/pvxs/details.html#reportbug) | How to report bugs | RST (online) |
| [Release Notes](https://epics-base.github.io/pvxs/releasenotes.html) | Known issues by version | RST (online) |
| [Command Line Tools](https://epics-base.github.io/pvxs/cli.html) | CLI utilities | RST (online) |

### 👥 Contributing

| Document | Description | Format |
|----------|-------------|--------|
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contributor guidelines | Markdown |
| [Contributing Guidelines](https://epics-base.github.io/pvxs/details.html#contrib) | Detailed contribution info | RST (online) |

## Documentation by Topic

### Client Development

**Getting Started:**
- [QUICKSTART.md](QUICKSTART.md) - Tutorial with client examples
- [Client API Overview](https://epics-base.github.io/pvxs/client.html) - Complete API reference

**Specific Topics:**
- [Get/Info Operations](https://epics-base.github.io/pvxs/client.html#get-info) - Fetching PV values
- [Put Operations](https://epics-base.github.io/pvxs/client.html#clientputapi) - Updating PV values
- [Monitor Operations](https://epics-base.github.io/pvxs/client.html#clientmonapi) - Subscribing to updates
- [RPC Operations](https://epics-base.github.io/pvxs/client.html#clientrpcapi) - Remote procedure calls
- [Client Configuration](https://epics-base.github.io/pvxs/client.html#configuration) - Network setup

**Examples:**
- [simpleget.cpp](../example/simpleget.cpp) - Minimal client example
- [client.cpp](../example/client.cpp) - Comprehensive client demo
- [rpc_client.cpp](../example/rpc_client.cpp) - RPC client example

### Server Development

**Getting Started:**
- [QUICKSTART.md](QUICKSTART.md) - Tutorial with server examples
- [Server API Overview](https://epics-base.github.io/pvxs/server.html) - Complete API reference

**Specific Topics:**
- [SharedPV](https://epics-base.github.io/pvxs/sharedpv.html) - Creating and managing PVs
- [Source API](https://epics-base.github.io/pvxs/source.html) - Dynamic PV sources
- [Server Configuration](https://epics-base.github.io/pvxs/server.html#configuration) - Network setup

**Examples:**
- [simplesrv.cpp](../example/simplesrv.cpp) - Minimal server example
- [mailbox.cpp](../example/mailbox.cpp) - Server with PUT validation
- [rpc_server.cpp](../example/rpc_server.cpp) - RPC server example
- [ticker.cpp](../example/ticker.cpp) - Periodic update server

### Data Handling

**Getting Started:**
- [Value Container API](https://epics-base.github.io/pvxs/value.html) - Complete API reference
- [ARCHITECTURE.md](ARCHITECTURE.md#data-layer) - Data layer overview

**Specific Topics:**
- [Field Lookup](https://epics-base.github.io/pvxs/value.html#field-lookup) - Accessing fields
- [Array Handling](https://epics-base.github.io/pvxs/value.html#array-fields) - Working with arrays
- [Type Definitions](https://epics-base.github.io/pvxs/typedef.html) - Creating custom types
- [Normative Types](https://epics-base.github.io/pvxs/nt.html) - Standard EPICS types

**Examples:**
- See examples in `example/` directory for Value usage

### IOC Integration

**Getting Started:**
- [IOC Integration](https://epics-base.github.io/pvxs/ioc.html) - IOC integration overview
- [QSRV 2](https://epics-base.github.io/pvxs/qgroup.html) - High-level IOC integration

**Specific Topics:**
- [Single PV Access](https://epics-base.github.io/pvxs/ioc.html#single-pv) - Individual PV access
- [Group PV Access](https://epics-base.github.io/pvxs/qgroup.html) - Batch operations
- [PVA Links](https://epics-base.github.io/pvxs/pvalink.html) - Linking database records
- [Access Security](https://epics-base.github.io/pvxs/ioc.html#access-security) - Security integration

### Network Configuration

**Getting Started:**
- [Network Configuration](https://epics-base.github.io/pvxs/netconfig.html) - Complete guide
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md#network-issues) - Network troubleshooting

**Topics:**
- Client configuration (`$EPICS_PVA_*` variables)
- Server configuration (`$EPICS_PVAS_*` variables)
- Discovery mechanism
- Address lists and routing

### Command-Line Tools

**Getting Started:**
- [Command Line Tools](https://epics-base.github.io/pvxs/cli.html) - Complete tool documentation
- [README.md](README.md#command-line-tools) - Quick reference

**Tools:**
- `pvxget` - Get PV values
- `pvxput` - Put PV values
- `pvxmonitor` - Monitor PV updates
- `pvxinfo` - Get PV information
- `pvxcall` - Execute RPC
- `pvxlist` - List available PVs
- `pvxvct` - Network troubleshooting tool

## Documentation Format Guide

### Markdown Documentation (User Guides)

**Location:** Repository root (`*.md` files)

**Best for:**
- Getting started tutorials
- Step-by-step instructions
- Installation guides
- Troubleshooting
- Conceptual explanations

**Files:**
- `../README.md` - Main project overview
- `QUICKSTART.md` - New user tutorial
- `INSTALLATION.md` - Installation guide
- `TROUBLESHOOTING.md` - Troubleshooting guide
- `ARCHITECTURE.md` - Architecture overview
- `CONTRIBUTING.md` - Contributor guide

### RST Documentation (API Reference)

**Location:** `documentation/` directory (`*.rst` files)

**Best for:**
- Function/class signatures
- Method parameters
- Available classes and methods
- Detailed technical specifications

**Online:** https://epics-base.github.io/pvxs/

**Build locally:**
```bash
cd documentation
make html
```

## Finding Information

### "How do I...?"

| Task | Document |
|------|----------|
| Get started quickly | [QUICKSTART.md](QUICKSTART.md) |
| Install PVXS | [INSTALLATION.md](INSTALLATION.md) |
| Create a client | [Client API](https://epics-base.github.io/pvxs/client.html) |
| Create a server | [Server API](https://epics-base.github.io/pvxs/server.html) |
| Work with data | [Value API](https://epics-base.github.io/pvxs/value.html) |
| Integrate with IOC | [IOC Integration](https://epics-base.github.io/pvxs/ioc.html) |
| Troubleshoot issues | [TROUBLESHOOTING.md](TROUBLESHOOTING.md) |
| Configure network | [Network Configuration](https://epics-base.github.io/pvxs/netconfig.html) |
| Contribute code | [CONTRIBUTING.md](CONTRIBUTING.md) |

### "What is...?"

| Concept | Document |
|---------|----------|
| PVXS overview | [README.md](../README.md) |
| Architecture | [ARCHITECTURE.md](ARCHITECTURE.md) |
| PVAccess protocol | [README.md](../README.md#what-is-pvaccess) |
| Process Variables | [README.md](../README.md#what-is-a-process-variable-pv) |
| Value containers | [Value API](https://epics-base.github.io/pvxs/value.html) |
| QSRV 2 | [QSRV 2](https://epics-base.github.io/pvxs/qgroup.html) |

### "Where is the API for...?"

| API | Document |
|-----|----------|
| Client operations | [Client API](https://epics-base.github.io/pvxs/client.html) |
| Server setup | [Server API](https://epics-base.github.io/pvxs/server.html) |
| Value handling | [Value API](https://epics-base.github.io/pvxs/value.html) |
| Type definitions | [TypeDef API](https://epics-base.github.io/pvxs/typedef.html) |
| SharedPV | [SharedPV API](https://epics-base.github.io/pvxs/sharedpv.html) |
| Source | [Source API](https://epics-base.github.io/pvxs/source.html) |
| Utilities | [Utilities](https://epics-base.github.io/pvxs/util.html) |

## Documentation Maintenance

### For Documentation Contributors

See [documentation/README.md](../documentation/README.md) for:
- Documentation structure details
- How to update RST files
- How to update Markdown guides
- Building documentation locally
- Documentation standards

## Additional Resources

- [GitHub Repository](https://github.com/epics-base/pvxs) - Source code and issue tracker
- [Online Documentation](https://epics-base.github.io/pvxs/) - Latest API reference
- [EPICS Homepage](https://epics-controls.org/) - EPICS project information
- [EPICS Tech-Talk](https://epics.anl.gov/tech-talk/) - Community support forum

## Acknowledgments

This documentation index was created and organized by **K. Gofron**, Oak Ridge National Laboratory, December 28, 2025.

