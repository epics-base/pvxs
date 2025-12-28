# PVXS Documentation

This directory contains the comprehensive documentation for PVXS, the PVAccess Protocol Client/Server Library.

## Documentation Structure

The PVXS documentation is organized into two complementary formats:

### 1. RST Documentation (API Reference)

The `*.rst` files in this directory are the **source files for the official API reference documentation** published at https://epics-base.github.io/pvxs/.

**Purpose:** Detailed API reference, generated from code documentation and structured for technical reference.

**Key Documents:**
- `index.rst` - Main documentation index
- `overview.rst` - Overview and concepts
- `client.rst` - Client API reference
- `server.rst` - Server API reference
- `value.rst` - Value Container API reference
- `ioc.rst` - IOC Integration documentation
- `building.rst` - Building from source (detailed)
- `netconfig.rst` - Network configuration
- `cli.rst` - Command-line tools
- `example.rst` - Code examples
- `details.rst` - Bug reporting, contributing, release policy
- `releasenotes.rst` - Release notes

**Building the Documentation:**

To build the HTML documentation locally:

```bash
cd documentation
make html
# Documentation will be in _build/html/
```

### 2. Markdown Documentation (User Guides)

User-friendly guides in Markdown format located in the `docs/` directory:

**Purpose:** Practical guides for getting started, installation, troubleshooting, and understanding the system.

**User Guides:**
- [`README.md`](../README.md) - Main project overview and quick start (in repository root)
- [`QUICKSTART.md`](../docs/QUICKSTART.md) - Step-by-step tutorial for new users
- [`INSTALLATION.md`](../docs/INSTALLATION.md) - Detailed installation guide
- [`TROUBLESHOOTING.md`](../docs/TROUBLESHOOTING.md) - Common issues and solutions
- [`ARCHITECTURE.md`](../docs/ARCHITECTURE.md) - System architecture overview
- [`CONTRIBUTING.md`](../docs/CONTRIBUTING.md) - Contributor guidelines

## Documentation Navigation

### For New Users

1. Start with [`README.md`](../README.md) for an overview
2. Follow [`QUICKSTART.md`](../docs/QUICKSTART.md) for hands-on experience
3. Refer to [`INSTALLATION.md`](../docs/INSTALLATION.md) for detailed setup
4. Use [`TROUBLESHOOTING.md`](../docs/TROUBLESHOOTING.md) if you encounter issues

### For Developers

1. Review [`ARCHITECTURE.md`](../docs/ARCHITECTURE.md) for system design
2. Consult the [online API documentation](https://epics-base.github.io/pvxs/) for detailed APIs
3. Check [`CONTRIBUTING.md`](../docs/CONTRIBUTING.md) for development guidelines
4. See `example.rst` and the [`example/`](../example/) directory for code examples

### For API Reference

1. Browse the [online documentation](https://epics-base.github.io/pvxs/) (generated from RST files)
2. Or build locally: `make html` in this directory
3. See `index.rst` for the table of contents

## Documentation Types

### API Reference (RST)

**Best for:**
- Looking up function/class signatures
- Understanding method parameters
- Finding available classes and methods
- Detailed technical specifications

**Format:** ReStructuredText (RST) with Sphinx
**Location:** Files in this directory (`*.rst`)
**Online:** https://epics-base.github.io/pvxs/

### User Guides (Markdown)

**Best for:**
- Getting started quickly
- Step-by-step tutorials
- Installation instructions
- Troubleshooting common problems
- Understanding concepts and architecture

**Format:** Markdown
**Location:** `docs/` directory (`docs/*.md`), with `README.md` in repository root

## Cross-Referencing

The documentation is designed to work together:

- **Markdown guides** link to specific RST sections for detailed API information
- **RST documentation** references markdown guides for user-friendly introductions
- **Both formats** link to code examples in the `example/` directory

## Contributing to Documentation

### Updating API Documentation (RST)

1. Modify the relevant `*.rst` file in this directory
2. If documenting code, ensure Doxygen comments are up to date
3. Build locally to verify: `make html`
4. Follow RST/Sphinx conventions

### Updating User Guides (Markdown)

1. Modify the relevant `*.md` file in the repository root
2. Follow Markdown best practices
3. Maintain cross-references to RST documentation
4. Test all links

### Documentation Standards

- **Clarity:** Write clearly and concisely
- **Examples:** Include code examples where helpful
- **Links:** Cross-reference related documentation
- **Accuracy:** Keep documentation in sync with code
- **Organization:** Follow the existing structure

## Key Documentation Files

### RST Files (API Reference)

| File | Description |
|------|-------------|
| `index.rst` | Main documentation index |
| `overview.rst` | Overview, concepts, comparisons with other modules |
| `client.rst` | Complete Client API reference |
| `server.rst` | Complete Server API reference |
| `value.rst` | Value Container API reference |
| `ioc.rst` | IOC Integration and QSRV 2 |
| `building.rst` | Detailed build instructions |
| `netconfig.rst` | Network configuration details |
| `cli.rst` | Command-line tools documentation |
| `example.rst` | Code examples overview |
| `util.rst` | Utility functions (logging, version, etc.) |
| `details.rst` | Bug reporting, contributing, release policy |
| `releasenotes.rst` | Release notes and changelog |

### Sub-documents

- `nt.rst`, `ntscalar.rst` - Normative Types documentation
- `typedef.rst` - Type definition API
- `sharedpv.rst` - SharedPV API
- `source.rst` - Source API
- `qgroup.rst` - Group PV documentation
- `pvalink.rst` - PVA Links documentation

### Markdown Files (User Guides)

Located in `docs/` directory (except README.md which is in repository root):
- `../README.md` - Main overview (in repository root)
- `../docs/QUICKSTART.md` - Quick start tutorial
- `../docs/INSTALLATION.md` - Installation guide
- `../docs/TROUBLESHOOTING.md` - Troubleshooting guide
- `../docs/ARCHITECTURE.md` - Architecture overview
- `../docs/CONTRIBUTING.md` - Contributor guide

## Building Documentation

### Prerequisites

- Sphinx (Python package)
- Doxygen (for API extraction)
- Required Python packages (see `conf.py`)

### Build Commands

```bash
# Build HTML documentation
cd documentation
make html

# Clean build artifacts
make clean

# Build all formats (if configured)
make
```

Output will be in `_build/html/` directory.

## Online Documentation

The latest documentation is always available online at:
**https://epics-base.github.io/pvxs/**

The online documentation is automatically generated from the RST files in this directory and is updated with each release.

## Getting Help

- **Documentation Issues:** Report problems with documentation via [GitHub Issues](https://github.com/epics-base/pvxs/issues)
- **Questions:** Ask on [EPICS Tech-Talk](https://epics.anl.gov/tech-talk/)
- **Suggestions:** Contribute improvements via Pull Requests

## Acknowledgments

This documentation structure was created and organized by **K. Gofron**, Oak Ridge National Laboratory, December 28, 2025.

