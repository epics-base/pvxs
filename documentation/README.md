# PVXS Documentation

This directory contains the comprehensive documentation for PVXS, the PVAccess Protocol Client/Server Library.

## Documentation Structure

The PVXS documentation is now fully integrated into a unified Sphinx environment, combining both RST (API reference) and Markdown (user guides) formats for seamless cross-referencing.

### Directory Organization

```
documentation/
├── guides/              # User guides (Markdown)
│   ├── quickstart.md
│   ├── installation.md
│   ├── troubleshooting.md
│   └── architecture.md
├── api/                 # API reference (RST)
│   ├── overview.rst
│   ├── value.rst
│   ├── client.rst
│   ├── server.rst
│   ├── ioc.rst
│   ├── util.rst
│   ├── details.rst
│   ├── typedef.rst
│   ├── sharedpv.rst
│   └── source.rst
├── reference/           # Reference documentation (RST)
│   ├── building.rst
│   ├── netconfig.rst
│   ├── cli.rst
│   ├── nt.rst
│   ├── ntscalar.rst
│   ├── qgroup.rst
│   └── pvalink.rst
├── examples/            # Examples and additional content
│   ├── example.rst
│   ├── releasenotes.rst
│   └── contributing.md
├── images/              # Images and graphics (SVG, PNG, etc.)
│   ├── nt_table1.svg
│   ├── nt_table2.svg
│   ├── nt_table3.svg
│   └── nt_table4.svg
├── index.rst            # Main documentation index
└── conf.py              # Sphinx configuration
```

## Documentation Types

### User Guides (Markdown)

**Location:** `guides/` and `examples/` directories

**Purpose:** Practical guides for getting started, installation, troubleshooting, and understanding the system.

**Key Documents:**

- [Quick Start Guide](https://epics-base.github.io/pvxs/guides/quickstart.html) - Step-by-step tutorial for new users
- [Installation Guide](https://epics-base.github.io/pvxs/guides/installation.html) - Detailed installation guide
- [Troubleshooting Guide](https://epics-base.github.io/pvxs/guides/troubleshooting.html) - Common issues and solutions
- [Architecture Guide](https://epics-base.github.io/pvxs/guides/architecture.html) - System architecture overview
- [Contributing Guide](https://epics-base.github.io/pvxs/examples/contributing.html) - Contributor guidelines

**Best for:**

- Getting started quickly
- Step-by-step tutorials
- Installation instructions
- Troubleshooting common problems
- Understanding concepts and architecture

### API Reference (RST)

**Location:** `api/` directory

**Purpose:** Detailed API reference, generated from code documentation and structured for technical reference.

**Key Documents:**

- `api/overview.rst` - Overview, concepts, comparisons with other modules
- `api/client.rst` - Complete Client API reference
- `api/server.rst` - Complete Server API reference
- `api/value.rst` - Value Container API reference
- `api/ioc.rst` - IOC Integration and QSRV 2
- `api/util.rst` - Utility functions (logging, version, etc.)
- `api/details.rst` - Bug reporting, contributing, release policy
- `api/typedef.rst` - Type definition API
- `api/sharedpv.rst` - SharedPV API
- `api/source.rst` - Source API

**Best for:**

- Looking up function/class signatures
- Understanding method parameters
- Finding available classes and methods
- Detailed technical specifications

### Reference Documentation (RST)

**Location:** `reference/` directory

**Purpose:** Reference documentation for specific features and tools.

**Key Documents:**

- `reference/building.rst` - Detailed build instructions
- `reference/netconfig.rst` - Network configuration details
- `reference/cli.rst` - Command-line tools documentation
- `reference/nt.rst`, `reference/ntscalar.rst` - Normative Types documentation
- `reference/qgroup.rst` - Group PV documentation
- `reference/pvalink.rst` - PVA Links documentation

### Examples and Additional Content

**Location:** `examples/` directory

- `examples/example.rst` - Code examples overview
- `examples/releasenotes.rst` - Release notes and changelog
- `examples/contributing.md` - Contributor guidelines

## Quick Navigation

### For New Users

1. Start with [`README.md`](../README.md) in the repository root for an overview
2. Follow the [Quick Start Guide](https://epics-base.github.io/pvxs/guides/quickstart.html) for hands-on experience
3. Refer to the [Installation Guide](https://epics-base.github.io/pvxs/guides/installation.html) for detailed setup
4. Use the [Troubleshooting Guide](https://epics-base.github.io/pvxs/guides/troubleshooting.html) if you encounter issues

### For Developers

1. Review the [Architecture Guide](https://epics-base.github.io/pvxs/guides/architecture.html) for system design
2. Consult the [online API documentation](https://epics-base.github.io/pvxs/) for detailed APIs
3. Check the [Contributing Guide](https://epics-base.github.io/pvxs/examples/contributing.html) for development guidelines
4. See [Examples](https://epics-base.github.io/pvxs/examples/example.html) and the [`example/`](../example/) directory for code examples

### For API Reference

1. Browse the [online documentation](https://epics-base.github.io/pvxs/) (generated from RST and Markdown files)
2. Or build locally: `make html` in this directory
3. See `index.rst` for the table of contents

## Building Documentation

### Prerequisites

- **Doxygen** - For extracting API documentation from source code
- **Sphinx** - Python documentation generator
- **Python packages:**
  - `sphinx`
  - `breathe` - Bridge between Sphinx and Doxygen
  - `myst-parser` - Markdown parser for Sphinx
- **Optional:**
  - `inkscape` - For processing SVG images (falls back to copying if not available)
  - `graphviz` - For generating diagrams

### Installation

**On Debian/Ubuntu:**

```bash
sudo apt-get install doxygen python3-sphinx python3-breathe python3-myst-parser inkscape graphviz
```

**On RHEL/CentOS:**

```bash
sudo yum install doxygen python3-sphinx python3-breathe inkscape graphviz
pip3 install myst-parser
```

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

Output will be in `html/` directory (or `_build/html/` depending on configuration).

## Cross-Referencing

The documentation is designed to work together seamlessly:

- **Markdown guides** can reference RST sections using `:doc:` and `:ref:` syntax
- **RST documentation** can reference markdown guides using the same syntax
- **Both formats** link to code examples in the `example/` directory
- All cross-references are resolved by Sphinx during the build process

## Contributing to Documentation

### Updating API Documentation (RST)

1. Modify the relevant `*.rst` file in the `api/` or `reference/` directories
2. If documenting code, ensure Doxygen comments are up to date in the source files
3. Build locally to verify: `make html`
4. Follow RST/Sphinx conventions

### Updating User Guides (Markdown)

1. Modify the relevant `*.md` file in the `guides/` or `examples/` directories
2. Use Sphinx cross-reference syntax (`:doc:` and `:ref:`) for linking to other documentation
3. Build locally to verify: `make html`
4. Follow Markdown best practices

### Adding Images

1. Place image files (SVG, PNG, etc.) in the `images/` directory
2. Reference them in RST using: `.. image:: ../images/filename.svg`
3. Reference them in Markdown using: `![Alt text](../images/filename.svg)`

### Documentation Standards

- **Clarity:** Write clearly and concisely
- **Examples:** Include code examples where helpful
- **Links:** Cross-reference related documentation using Sphinx syntax
- **Accuracy:** Keep documentation in sync with code
- **Organization:** Follow the existing directory structure

## Online Documentation

The latest documentation is always available online at:
**https://epics-base.github.io/pvxs/**

The online documentation is automatically generated from the RST and Markdown files in this directory and is updated with each release via GitHub Actions.

## Getting Help

- **Documentation Issues:** Report problems with documentation via [GitHub Issues](https://github.com/epics-base/pvxs/issues)
- **Questions:** Ask on [EPICS Tech-Talk](https://epics.anl.gov/tech-talk/)
- **Suggestions:** Contribute improvements via Pull Requests

## Acknowledgments

This documentation structure was created and organized by **K. Gofron**, Oak Ridge National Laboratory, December 28, 2025. The integration of markdown user guides into the Sphinx environment and reorganization into logical subdirectories was completed in December 2025.
