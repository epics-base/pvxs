# PVXS Installation Guide

This guide provides comprehensive instructions for installing and building PVXS from source.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Installation](#quick-installation)
- [Detailed Installation Steps](#detailed-installation-steps)
- [Platform-Specific Notes](#platform-specific-notes)
- [Dependency Installation](#dependency-installation)
- [Building Bundled libevent](#building-bundled-libevent)
- [Cross-Compilation](#cross-compilation)
- [Testing the Installation](#testing-the-installation)
- [Including PVXS in Your Application](#including-pvxs-in-your-application)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### Required Software

1. **EPICS Base** >= 3.15.1
   - Download from: https://github.com/epics-base/epics-base/releases
   - Or clone from: https://github.com/epics-base/epics-base

2. **C++11 Compliant Compiler**
   - GCC >= 4.8
   - Clang >= 3.3
   - Visual Studio >= 2015 (Windows)

3. **Make** - GNU Make (standard on Linux/macOS)

4. **Git** - For cloning the repository

### Optional Dependencies

1. **libevent** >= 2.0.1
   - Can be installed via system package manager (recommended)
   - Or built from source and bundled with PVXS
   - Required for networking functionality

2. **CMake** >= 3.10
   - Only needed if building bundled libevent
   - Download from: https://cmake.org/

3. **Doxygen** and **Sphinx** (for building documentation)
   - Optional, for generating documentation from source

## Quick Installation

For a standard installation on Linux/macOS:

```bash
# 1. Clone EPICS Base
git clone --branch 7.0 https://github.com/epics-base/epics-base.git
cd epics-base
make
cd ..

# 2. Clone PVXS
git clone --recursive https://github.com/epics-base/pvxs.git
cd pvxs

# 3. Configure PVXS to find EPICS Base
cat <<EOF > configure/RELEASE.local
EPICS_BASE=\$(TOP)/../epics-base
EOF

# 4. Install system libevent (recommended)
# On Debian/Ubuntu:
sudo apt-get install libevent-dev

# On RHEL/CentOS 7+:
sudo yum install libevent-devel

# On macOS (Homebrew):
brew install libevent

# 5. Build PVXS
make

# 6. Run tests (recommended)
make runtests
```

## Detailed Installation Steps

### Step 1: Install EPICS Base

EPICS Base must be installed before building PVXS.

```bash
# Clone EPICS Base (branch 7.0 is recommended)
git clone --branch 7.0 https://github.com/epics-base/epics-base.git
cd epics-base

# Build EPICS Base
make

# Verify installation
make install

cd ..
```

**Note:** Record the path where EPICS Base is installed. You'll need it in the next step.

### Step 2: Clone PVXS Repository

```bash
# Clone PVXS with submodules (if any)
git clone --recursive https://github.com/epics-base/pvxs.git
cd pvxs
```

### Step 3: Configure PVXS

Create a `configure/RELEASE.local` file to specify the location of EPICS Base:

```bash
# If EPICS Base is in a sibling directory
cat <<EOF > configure/RELEASE.local
EPICS_BASE=\$(TOP)/../epics-base
EOF

# OR if EPICS Base is installed elsewhere, use absolute path:
cat <<EOF > configure/RELEASE.local
EPICS_BASE=/path/to/epics-base
EOF
```

**Alternative:** You can edit `configure/RELEASE.local` directly with your preferred editor.

### Step 4: Install libevent

libevent is required for networking functionality. You have two options:

#### Option A: Install via System Package Manager (Recommended)

**On Debian/Ubuntu:**
```bash
sudo apt-get update
sudo apt-get install libevent-dev
```

**On RHEL/CentOS 7 and later:**
```bash
sudo yum install libevent-devel
```

**On RHEL 6 and earlier:**
```bash
sudo yum install libevent2-devel
```

**On macOS (Homebrew):**
```bash
brew install libevent
export LIBEVENT=$(brew --prefix)
```

**On Fedora:**
```bash
sudo dnf install libevent-devel
```

#### Option B: Build Bundled libevent

If you cannot install libevent via package manager, PVXS can build it for you:

```bash
# Build bundled libevent (requires CMake >= 3.10)
make -C bundle libevent
```

This will build libevent for your host architecture. For additional architectures:

```bash
# For a specific architecture
make -C bundle libevent.linux-x86_64-debug

# For Windows MinGW cross-compile
make -C bundle libevent.windows-x64-mingw
```

**Note:** Building bundled libevent requires CMake to be installed.

### Step 5: Build PVXS

```bash
# Build for host architecture
make

# To build for a specific architecture (e.g., for cross-compilation)
make EPICS_HOST_ARCH=linux-x86_64
```

The build process will:
1. Compile all source files
2. Create libraries (`libpvxs.so`/`libpvxs.a` and `libpvxsIoc.so`/`libpvxsIoc.a`)
3. Build command-line tools (pvxget, pvxput, etc.)
4. Build example programs

### Step 6: Verify Installation

```bash
# Run unit tests (recommended)
make runtests

# Check that tools were built
ls -la O.*/bin/pvx*
```

If tests pass, your installation is successful!

## Platform-Specific Notes

### Linux

PVXS has been tested on:
- Ubuntu 16.04 and later
- Debian 9 and later
- RHEL/CentOS 7 and later
- Fedora 25 and later
- openSUSE Leap

**Notes:**
- Ensure development tools are installed: `build-essential` (Debian/Ubuntu) or `Development Tools` group (RHEL/Fedora)
- On older distributions, you may need to build bundled libevent

### macOS

**Requirements:**
- Xcode Command Line Tools (install via `xcode-select --install`)
- Homebrew (recommended for libevent)

**Building:**
```bash
# Install libevent via Homebrew
brew install libevent
export LIBEVENT=$(brew --prefix)

# Build PVXS
make
```

**Notes:**
- macOS versions 10.12 (Sierra) and later are supported
- If using Homebrew libevent, ensure `LIBEVENT` environment variable is set

### Windows

PVXS can be built on Windows using:
- **MinGW/MSYS2** (recommended)
- **Visual Studio** (with appropriate modifications)

#### MinGW/MSYS2

```bash
# In MSYS2 terminal
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-make
pacman -S mingw-w64-x86_64-libevent

# Clone and build EPICS Base
# (follow EPICS Base Windows installation instructions)

# Configure and build PVXS
make
```

#### Visual Studio

Visual Studio support may require additional configuration. Refer to EPICS Base documentation for Visual Studio setup.

### Cross-Compilation

PVXS supports cross-compilation for various target architectures.

#### Example: Cross-compile for Linux ARM

```bash
# Set target architecture
export EPICS_HOST_ARCH=linux-arm

# Build bundled libevent for target
make -C bundle libevent.linux-arm

# Build PVXS
make EPICS_HOST_ARCH=linux-arm
```

#### Example: Cross-compile for Windows (MinGW)

```bash
# Build bundled libevent for MinGW
make -C bundle libevent.windows-x64-mingw

# Build PVXS
make EPICS_HOST_ARCH=windows-x64-mingw
```

**Note:** Cross-compilation requires appropriate toolchains to be installed and configured.

## Dependency Installation

### Installing EPICS Base from Source

If you need to install EPICS Base:

```bash
# Clone EPICS Base
git clone --branch 7.0 https://github.com/epics-base/epics-base.git
cd epics-base

# Review and edit configure files if needed
# (Most default settings work for most systems)

# Build
make

# Install (optional - builds in-place by default)
make install
```

For detailed EPICS Base installation, see: https://epics.anl.gov/base/R3-16/1-docs/README.html

### Installing libevent from Source

If building bundled libevent is not possible, you can build libevent separately:

```bash
# Download libevent (version >= 2.0.1)
wget https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz
tar -xzf libevent-2.1.12-stable.tar.gz
cd libevent-2.1.12-stable

# Configure and build
./configure --prefix=/usr/local
make
sudo make install
```

Then ensure PVXS can find it (may require setting `LIBEVENT` environment variable or library paths).

## Building Bundled libevent

PVXS includes the ability to build libevent as a bundled dependency. This is useful when:
- System package manager doesn't provide libevent
- You need a specific version of libevent
- Cross-compiling

### Requirements for Bundled libevent

- CMake >= 3.10
- C compiler (GCC, Clang, or MSVC)

### Building Bundled libevent

```bash
# Build for host architecture
make -C bundle libevent

# This is equivalent to:
make -C bundle libevent.$(EPICS_HOST_ARCH)
```

### Building for Specific Architecture

```bash
# List available architectures
ls bundle/libevent/

# Build for specific architecture
make -C bundle libevent.linux-x86_64-debug
make -C bundle libevent.linux-arm
make -C bundle libevent.windows-x64-mingw
```

### Using Bundled libevent

When built, bundled libevent is automatically used by PVXS. No additional configuration is needed.

## Cross-Compilation

PVXS supports cross-compilation for various target platforms.

### Prerequisites

1. Cross-compilation toolchain installed
2. EPICS Base configured for target architecture
3. libevent available for target (or build bundled version)

### Steps

1. **Configure EPICS Base for target architecture**
   ```bash
   cd epics-base
   make EPICS_HOST_ARCH=linux-arm
   ```

2. **Build bundled libevent for target** (if needed)
   ```bash
   cd pvxs
   make -C bundle libevent.linux-arm
   ```

3. **Build PVXS for target**
   ```bash
   make EPICS_HOST_ARCH=linux-arm
   ```

### Supported Cross-Compilation Targets

- Linux ARM (various variants)
- Linux PowerPC
- Windows (via MinGW)
- Other architectures supported by EPICS Base

Check EPICS Base documentation for supported architectures.

## Testing the Installation

### Running Unit Tests

PVXS includes a comprehensive test suite. It's recommended to run tests after installation:

```bash
# Run all tests
make runtests

# Run tests for specific architecture
make EPICS_HOST_ARCH=linux-x86_64 runtests
```

### Manual Testing

Test the installation by running example programs:

```bash
# Build examples
cd example
make

# Terminal 1: Start a test server
./O.linux-x86_64/simplesrv

# Terminal 2: Test client
./O.linux-x86_64/simpleget test:pv:name
```

### Testing Command-Line Tools

```bash
# Test pvxget (requires a running server)
pvxget my:pv:name

# Test pvxinfo
pvxinfo my:pv:name

# Test pvxmonitor (Ctrl+C to stop)
pvxmonitor my:pv:name
```

## Including PVXS in Your Application

### For EPICS IOC Applications

Add PVXS to your IOC's `configure/RELEASE` or `configure/RELEASE.local`:

```makefile
PVXS=/path/to/your/build/of/pvxs
EPICS_BASE=/path/to/your/build/of/epics-base
```

In your IOC's `Makefile`:

```makefile
PROD_IOC += myioc

myioc_DBD += pvxsIoc.dbd
myioc_DBD += base.dbd

myioc_LIBS += pvxsIoc pvxs
myioc_LIBS += $(EPICS_BASE_IOC_LIBS)
```

**Important:** The `pvxsIoc` library should only be included for IOCs. Omit it for standalone applications.

### For Standalone Applications

Add PVXS to your application's `configure/RELEASE` or `configure/RELEASE.local`:

```makefile
PVXS=/path/to/your/build/of/pvxs
EPICS_BASE=/path/to/your/build/of/epics-base
```

In your application's `Makefile`:

```makefile
PROD += myapp

myapp_LIBS += pvxs
myapp_LIBS += Com

myapp_SRCS += myapp.cpp
```

The PVXS build system automatically adds libevent to the link line.

### Using CONFIG_PVXS_MODULE

PVXS provides a configuration file `$(PVXS)/cfg/CONFIG_PVXS_MODULE` that simplifies inclusion:

```makefile
include $(PVXS)/cfg/CONFIG_PVXS_MODULE

# This automatically sets up library dependencies
```

## Troubleshooting

### Build Errors

**Error: "Cannot find EPICS Base"**
- Ensure `EPICS_BASE` is set correctly in `configure/RELEASE.local`
- Verify EPICS Base was built successfully
- Check that EPICS Base path exists and is accessible

**Error: "Cannot find libevent"**
- Install libevent via package manager, OR
- Build bundled libevent: `make -C bundle libevent`
- On macOS with Homebrew: Set `LIBEVENT=$(brew --prefix)`

**Error: "CMake not found" (when building bundled libevent)**
- Install CMake >= 3.10
- Or install system libevent instead

**Compilation errors**
- Ensure you have a C++11 compliant compiler
- Check compiler version: `g++ --version` or `clang++ --version`
- Verify all dependencies are correctly installed

### Runtime Errors

**Error: "Cannot find shared library"**
- Add PVXS library path to `LD_LIBRARY_PATH` (Linux) or `DYLD_LIBRARY_PATH` (macOS)
- Or install PVXS libraries to system library path

**Network connection errors**
- Check `$EPICS_PVA_ADDR_LIST` environment variable
- Verify server is running and accessible
- Check firewall settings
- Use `pvxvct` tool for network debugging

**Tests failing**
- Ensure network ports are available (default: 5075, 5076)
- Check that no other PVAccess servers are running on same ports
- Verify EPICS Base is correctly installed and configured

### Getting Help

If you encounter issues not covered here:

1. Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
2. Search [GitHub Issues](https://github.com/epics-base/pvxs/issues)
3. Review [online documentation](https://epics-base.github.io/pvxs/)
4. Post questions on [EPICS Tech-Talk](https://epics.anl.gov/tech-talk/)

## Next Steps

After successful installation:

1. Follow the [Quick Start Guide](QUICKSTART.md) for hands-on experience
2. Read the [README.md](../README.md) for an overview
3. Explore the [Examples](https://github.com/epics-base/pvxs/tree/master/example)
4. Review the [API Documentation](https://epics-base.github.io/pvxs/)
5. Check [ARCHITECTURE.md](ARCHITECTURE.md) for design details
6. Integrate PVXS into your application

## Related Documentation

**Detailed Build Documentation:**
- [Building from Source (Detailed)](../documentation/building.rst) - Advanced build options and cross-compilation details
- [Network Configuration](../documentation/netconfig.rst) - Network setup and environment variables
- [Running Tests](../documentation/building.rst#runtests) - Test suite execution

**Installation-Related Guides:**
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common installation issues and solutions
- [README.md](../README.md) - Quick start and overview
- [Building from Source](https://epics-base.github.io/pvxs/building.html) - Online build documentation

**Python Bindings:**
- Python bindings (pvxslibs) installation is handled separately via pip
- See [Python package](https://pypi.org/project/pvxslibs/) for installation instructions
- Note: Python bindings require EPICS Base and PVXS to be installed first

## Additional Resources

- **EPICS Base Documentation**: https://epics.anl.gov/base/
- **PVAccess Specification**: https://epics.anl.gov/base/R3-16/0-docs/EPICS_Network_Protocols.pdf
- **EPICS Controls Homepage**: https://epics-controls.org/
- **PVXS GitHub Repository**: https://github.com/epics-base/pvxs

## Acknowledgments

This installation documentation was created and organized by **K. Gofron**, Oak Ridge National Laboratory, December 28, 2025.

---

**Last Updated:** See git history for latest changes.

