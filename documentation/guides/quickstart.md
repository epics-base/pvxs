# PVXS Quick Start Guide

This guide will help you get started with PVXS in minutes. We'll walk through installing PVXS and running simple client and server examples.

## Prerequisites

Before starting, ensure you have:
- EPICS Base >= 3.15.1 installed and built
- A C++11 compliant compiler (GCC >= 4.8, Clang >= 3.3, or Visual Studio >= 2015)
- libevent >= 2.0.1 (or build bundled version)

## Step 1: Install PVXS

### Quick Installation

```bash
# Clone EPICS Base (if not already done)
git clone --branch 7.0 https://github.com/epics-base/epics-base.git
cd epics-base
make
cd ..

# Clone PVXS
git clone --recursive https://github.com/epics-base/pvxs.git
cd pvxs

# Configure PVXS
cat <<EOF > configure/RELEASE.local
EPICS_BASE=\$(TOP)/../epics-base
EOF

# Install system libevent (recommended)
# On Debian/Ubuntu:
sudo apt-get install libevent-dev
# On RHEL/CentOS:
sudo yum install libevent-devel
# On macOS:
brew install libevent

# Build PVXS
make
```

For detailed installation instructions, see :doc:`guides/installation`.

## Step 2: Verify Installation

Check that PVXS built successfully:

```bash
# Run unit tests (recommended)
make runtests

# Check that tools were built
ls -la O.*/bin/pvx*
```

## Step 3: Run Your First Server

In one terminal, start a simple server:

```bash
cd example
make
./O.linux-x86_64/simplesrv
```

You should see output indicating the server is running. The server creates a PV named `my:pv:name` with a double value of 42.0.

**What's happening:**

The server code (see `simplesrv.cpp <../example/simplesrv.cpp>`_) does the following:

1. Creates an NTScalar structure (a standard EPICS type) with a double value
2. Sets an initial value of 42.0
3. Creates a mailbox PV (stores whatever clients send)
4. Opens the PV with the initial value
5. Adds the PV to a server configured from environment variables
6. Runs the server (blocks until Ctrl+C)

## Step 4: Connect with a Client

In another terminal, run the simple client:

```bash
cd example
./O.linux-x86_64/simpleget my:pv:name
```

You should see the PV value printed to stdout.

**What's happening:**

The client code (see `simpleget.cpp <../example/simpleget.cpp>`_) does the following:

1. Creates a client context configured from environment variables
2. Initiates a GET operation for the PV name
3. Waits up to 5 seconds for the response
4. Prints the received value

## Step 5: Modify and Experiment

### Try Changing the Value

In the client terminal, you can use the command-line tools:

```bash
# Get the value
pvxget my:pv:name

# Put a new value
pvxput my:pv:name 99.5

# Get it again to see the change
pvxget my:pv:name

# Monitor for changes (press Ctrl+C to stop)
pvxmonitor my:pv:name
```

### Try the Mailbox Example

The mailbox server (see `mailbox.cpp <../example/mailbox.cpp>`_) includes a PUT handler with validation:

```bash
# Terminal 1: Start mailbox server
cd example
./O.linux-x86_64/mailbox test:pv:1

# Terminal 2: Use the client example to interact
./O.linux-x86_64/client test:pv:1
```

The mailbox server:
- Validates PUT values (clips to range [-100.0, 100.0])
- Adds timestamps automatically
- Notifies subscribers when values change

## Understanding the Code

### Client Example Breakdown

```cpp
#include <pvxs/client.h>
#include <pvxs/log.h>

int main() {
    using namespace pvxs;
    
    // Configure client from environment ($EPICS_PVA_*)
    auto ctxt = client::Context::fromEnv();
    
    // Get a PV value (blocking)
    Value result = ctxt.get("some:pv:name")
                   .exec()      // Start the operation
                   ->wait(5.0); // Wait up to 5 seconds
    
    std::cout << result << std::endl;
    return 0;
}
```

**Key concepts:**
- `Context::fromEnv()` - Creates client configured from `$EPICS_PVA_*` environment variables
- `.get("pv:name")` - Creates a GetBuilder for the named PV
- `.exec()` - Starts the network operation, returns an Operation handle
- `.wait(5.0)` - Blocks until operation completes or timeout

See :doc:`api/client` for detailed documentation.

### Server Example Breakdown

```cpp
#include <pvxs/server.h>
#include <pvxs/sharedpv.h>
#include <pvxs/nt.h>

int main() {
    using namespace pvxs;
    
    // Create an NTScalar structure with double value
    Value initial = nt::NTScalar{TypeCode::Float64}.create();
    initial["value"] = 42.0;
    
    // Create a mailbox PV (stores client PUTs)
    server::SharedPV pv(server::SharedPV::buildMailbox());
    pv.open(initial);  // Set the data type and initial value
    
    // Create server and add PV
    server::Server::fromEnv()    // Configure from environment
        .addPV("my:pv:name", pv) // Register the PV
        .run();                  // Run until SIGINT
    
    return 0;
}
```

**Key concepts:**
- `nt::NTScalar{TypeCode::Float64}` - Creates a standard EPICS scalar type
- `SharedPV::buildMailbox()` - Creates a PV that stores PUT values
- `.open(initial)` - Sets the data type and initial value
- `Server::fromEnv()` - Creates server configured from environment variables
- `.run()` - Starts server and blocks until interrupted

See :doc:`api/server` for detailed documentation.

## Next Steps

Now that you have PVXS working, explore further:

1. **Read the Full Documentation:**
   - `README.md <../README.md>`_ - Overview and features (external reference)
   - :doc:`guides/architecture` - System design
   - :doc:`api/overview` - Complete API reference overview

2. **Explore Examples:**
   - `client.cpp <../example/client.cpp>`_ - Comprehensive client demo
   - `mailbox.cpp <../example/mailbox.cpp>`_ - Server with PUT validation
   - `rpc_client.cpp <../example/rpc_client.cpp>`_ and `rpc_server.cpp <../example/rpc_server.cpp>`_ - RPC examples
   - `ticker.cpp <../example/ticker.cpp>`_ - Periodic updates

3. **Learn About:**
   - :doc:`reference/netconfig` - Configuring network settings
   - :doc:`api/value` - Working with data structures
   - :doc:`api/ioc` - Integrating with EPICS IOCs

4. **Build Your Application:**
   - See :doc:`guides/installation` for including PVXS in your project
   - Check :doc:`guides/troubleshooting` if you encounter issues

## Common Issues

**Server not found:**
- Check that server is running
- Verify `$EPICS_PVA_ADDR_LIST` environment variable (if needed)
- Check firewall settings (ports 5075 TCP, 5076 UDP)

**Connection timeout:**
- Verify network connectivity
- Check server logs for errors
- Ensure client and server are on same network (or configure addresses explicitly)

**Build errors:**
- See :doc:`guides/installation` for troubleshooting
- Check that EPICS Base is built and accessible
- Verify libevent is installed

For more troubleshooting help, see :doc:`guides/troubleshooting`.

## Additional Resources

- [PVXS GitHub Repository](https://github.com/epics-base/pvxs)
- [EPICS Controls Homepage](https://epics-controls.org/)
- [EPICS Tech-Talk](https://epics.anl.gov/tech-talk/) - Community support forum

## Acknowledgments

This quick start guide was created and organized by **K. Gofron**, Oak Ridge National Laboratory, December 28, 2025.

