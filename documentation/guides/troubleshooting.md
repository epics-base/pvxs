# PVXS Troubleshooting Guide

This guide helps diagnose and resolve common issues with PVXS.

## Network Issues

### Cannot Find PVs / Servers Not Discovered

**Symptoms:**

- Client cannot find servers
- `pvxget` or other tools report "PV not found"
- Timeouts when trying to connect

**Diagnosis:**

1. **Check environment variables:**

   ```bash
   # Client configuration
   echo $EPICS_PVA_ADDR_LIST
   echo $EPICS_PVA_AUTO_ADDR_LIST
   echo $EPICS_PVA_SERVER_PORT
   echo $EPICS_PVA_BROADCAST_PORT
   
   # Server configuration
   echo $EPICS_PVAS_SERVER_PORT
   echo $EPICS_PVAS_BEACON_ADDR_LIST
   echo $EPICS_PVAS_AUTO_BEACON_ADDR_LIST
   ```

2. **Test with pvxvct:**

   ```bash
   # On server host - listen for searches
   pvxvct -C -P test:pv:name
   
   # On client host - try to connect
   pvxget test:pv:name
   
   # If pvxvct doesn't see searches, check firewall
   ```

3. **Check firewall settings:**

   - Default ports: 5075 (TCP) and 5076 (UDP)
   - Ensure UDP port 5076 is open for discovery
   - Ensure TCP port 5075 is open for connections
   - On Linux: `sudo ufw allow 5075/tcp && sudo ufw allow 5076/udp`
   - On macOS: Check System Preferences > Security & Privacy > Firewall

4. **Verify network configuration:**

   ```bash
   # List available servers
   pvxlist
   
   # Get verbose debug output
   export PVXS_LOG=*=DEBUG
   pvxget -d my:pv:name
   ```

**Solutions:**

- Set `EPICS_PVA_ADDR_LIST` to explicitly list server addresses
- Disable auto-discovery if in non-broadcast environment: `EPICS_PVA_AUTO_ADDR_LIST=NO`
- Check router/firewall allows UDP broadcast on port 5076
- Use `EPICS_PVA_ADDR_LIST` for static server lists

### UDP Broadcast Not Working

**Symptoms:**

- Servers not discovered automatically
- Works with explicit address list

**Diagnosis:**

```bash
# Check if UDP broadcast is being received
pvxvct -C -P test:pv:name

# On another host, try to connect
pvxget test:pv:name
```

**Solutions:**

- Ensure clients and servers are on same broadcast domain
- Check firewall allows UDP on port 5076
- For cross-subnet: Use `EPICS_PVA_ADDR_LIST` with explicit addresses
- Check routing tables if using multiple network interfaces

### Connection Refused

**Symptoms:**

- Client finds server but cannot connect
- "Connection refused" errors

**Diagnosis:**

```bash
# Check if server is listening
netstat -tuln | grep 5075
# or
ss -tuln | grep 5075

# Check server logs
export PVXS_LOG=*=DEBUG
# Run server and check for bind errors
```

**Solutions:**

- Verify server is actually running
- Check if port 5075 is already in use by another process
- Verify `EPICS_PVAS_SERVER_PORT` matches client expectations
- Check server logs for bind errors

## Build and Compilation Issues

### EPICS Base Not Found

**Error:**

```
configure/RELEASE: No such file or directory
EPICS_BASE not found
```

**Solutions:**

1. Verify `EPICS_BASE` is set in `configure/RELEASE.local`:

   ```bash
   cat configure/RELEASE.local
   # Should contain: EPICS_BASE=/path/to/epics-base
   ```

2. Use absolute path if relative path doesn't work:

   ```bash
   echo "EPICS_BASE=/absolute/path/to/epics-base" > configure/RELEASE.local
   ```

3. Verify EPICS Base was built:

   ```bash
   ls /path/to/epics-base/lib/linux-x86_64/
   ```

### libevent Not Found

**Error:**

```
Cannot find libevent
libevent library not found
```

**Solutions:**

1. Install system libevent:

   ```bash
   # Debian/Ubuntu
   sudo apt-get install libevent-dev
   
   # RHEL/CentOS
   sudo yum install libevent-devel
   
   # macOS
   brew install libevent
   export LIBEVENT=$(brew --prefix)
   ```

2. Build bundled libevent:

   ```bash
   make -C bundle libevent
   ```

3. If libevent is in non-standard location:

   ```bash
   export LIBEVENT=/path/to/libevent
   export LD_LIBRARY_PATH=$LIBEVENT/lib:$LD_LIBRARY_PATH
   make clean
   make
   ```

### Compiler Errors

**Error:** C++11 features not recognized

**Solutions:**

1. Check compiler version:

   ```bash
   g++ --version  # Should be >= 4.8
   clang++ --version  # Should be >= 3.3
   ```

2. Update compiler if needed

3. For older GCC, may need to specify C++11:

   ```bash
   export CXXFLAGS="-std=c++11"
   make clean
   make
   ```

### CMake Not Found (for bundled libevent)

**Error:**

```
CMake not found
cmake: command not found
```

**Solutions:**

1. Install CMake:

   ```bash
   # Debian/Ubuntu
   sudo apt-get install cmake
   
   # RHEL/CentOS
   sudo yum install cmake
   
   # macOS
   brew install cmake
   ```

2. Or use system libevent instead (recommended)

## Runtime Errors

### Shared Library Not Found

**Error:**

```
error while loading shared libraries: libpvxs.so.X: cannot open shared object file
```

**Solutions:**

1. Add PVXS library path to `LD_LIBRARY_PATH`:

   ```bash
   export LD_LIBRARY_PATH=/path/to/pvxs/lib/linux-x86_64:$LD_LIBRARY_PATH
   ```

2. Or install libraries to system path:

   ```bash
   sudo cp /path/to/pvxs/lib/linux-x86_64/*.so* /usr/local/lib/
   sudo ldconfig
   ```

3. On macOS, use `DYLD_LIBRARY_PATH`:

   ```bash
   export DYLD_LIBRARY_PATH=/path/to/pvxs/lib/darwin-x86:$DYLD_LIBRARY_PATH
   ```

### Segmentation Fault

**Symptoms:**

- Application crashes with segmentation fault
- Occurs during PVXS operations

**Diagnosis:**

1. Enable core dumps:

   ```bash
   ulimit -c unlimited
   ```

2. Run with debugger:

   ```bash
   gdb ./myapp
   (gdb) run
   # When crash occurs:
   (gdb) bt
   ```

3. Check for common causes:

   - Using destroyed Context/Server objects
   - Accessing Value objects after their container is destroyed
   - Thread safety violations

**Solutions:**

- Ensure Context/Server objects remain in scope during operations
- Use shared pointers for long-lived objects
- Verify thread safety (Context/Server may not be thread-safe for configuration)
- Check for use-after-free in callbacks

### Memory Leaks

**Symptoms:**

- Memory usage grows over time
- Valgrind reports leaks

**Diagnosis:**

```bash
# Run with valgrind
valgrind --leak-check=full ./myapp

# Or use sanitizers
export CXXFLAGS="-fsanitize=address -g"
make clean && make
```

**Common Causes:**

- Not properly closing Context or Server
- Circular references in callbacks
- Not cleaning up Operation handles

**Solutions:**

- Ensure Context/Server are properly closed/destroyed
- Use weak_ptr in callbacks to avoid circular references
- Store Operation handles and ensure they complete

## Client Connection Problems

### Timeout on Get/Put Operations

**Symptoms:**

- Operations timeout even when server is reachable

**Diagnosis:**

```bash
# Check with verbose logging
export PVXS_LOG=*=DEBUG
pvxget -d my:pv:name 2>&1 | grep -i timeout
```

**Solutions:**

1. Increase timeout:

   ```cpp
   auto result = ctxt.get("pv:name")
                 .exec()
                 ->wait(10.0);  // Increase from default 5.0
   ```

2. Check network latency:

   ```bash
   ping server-host
   ```

3. Verify server is responsive:

   ```bash
   pvxinfo my:pv:name  # Should return quickly
   ```

### Connection Drops Frequently

**Symptoms:**

- Connections work initially but drop
- Need to reconnect frequently

**Diagnosis:**

- Check for network instability
- Verify keepalive settings
- Check server logs for disconnection reasons

**Solutions:**

- Check network stability: `ping -c 100 server-host`
- Verify firewall not dropping idle connections
- Check server load (may be overloaded)
- Implement automatic reconnection logic in application

### Cannot Connect to Specific PV

**Symptoms:**

- Other PVs work, but one specific PV fails

**Diagnosis:**

```bash
# Check if PV exists on server
pvxlist | grep my:pv:name

# Get detailed info
pvxinfo my:pv:name

# Try with verbose logging
export PVXS_LOG=*=DEBUG
pvxget -d my:pv:name
```

**Solutions:**

- Verify PV name spelling (case-sensitive)
- Check if PV is actually registered on server
- Verify PV hasn't been closed/removed
- Check server logs for errors related to this PV

## Server Issues

### Server Won't Start

**Symptoms:**

- Server fails to bind to port
- Immediate exit on startup

**Diagnosis:**

```bash
# Check if port is in use
netstat -tuln | grep 5075
# or
lsof -i :5075

# Run with debug logging
export PVXS_LOG=*=DEBUG
./myserver
```

**Solutions:**

1. Change port:

   ```bash
   export EPICS_PVAS_SERVER_PORT=5077
   ```

2. Kill process using port:

   ```bash
   sudo kill -9 $(lsof -t -i:5075)
   ```

3. Check permissions (binding to port < 1024 requires root)

### PV Not Visible to Clients

**Symptoms:**

- Server runs, but PVs not discoverable
- `pvxlist` doesn't show PVs

**Diagnosis:**

```bash
# Check server is running and listening
netstat -tuln | grep 5075

# Check beacon is being sent
pvxvct -S

# Verify PV is actually registered
# (check server code/logs)
```

**Solutions:**

- Verify `addPV()` was called before `run()`
- Check PV is opened before adding to server
- Verify server configuration allows auto-beaconing
- Check network configuration (beacons may not be reaching clients)

### Server Performance Issues

**Symptoms:**

- Slow response to client requests
- High CPU usage
- Dropped connections under load

**Diagnosis:**

```bash
# Check server load
top -p $(pgrep myserver)

# Profile with perf (Linux)
perf record -p $(pgrep myserver)
perf report

# Check for lock contention
export PVXS_LOG=*=DEBUG
# Look for thread blocking
```

**Solutions:**

- Profile code to identify bottlenecks
- Consider using multiple server instances
- Optimize Value creation (reuse when possible)
- Check for inefficient callbacks
- Verify libevent is being used efficiently

## IOC Integration Issues

### IOC Won't Start with PVXS

**Error:**

```
Error loading pvxsIoc.dbd
```

**Solutions:**

1. Verify PVXS is in RELEASE file:

   ```makefile
   PVXS=/path/to/pvxs
   ```

2. Check pvxsIoc.dbd exists:

   ```bash
   ls $PVXS/dbd/pvxsIoc.dbd
   ```

3. Verify libraries are linked:

   ```makefile
   myioc_LIBS += pvxsIoc pvxs
   ```

### Database Records Not Served

**Symptoms:**

- IOC starts but PVs not accessible via PVAccess
- `pvxlist` doesn't show database records

**Solutions:**

1. Verify QSRV 2 is enabled:

   ```bash
   # In IOC startup script
   qsrv2Start()
   ```

2. Check database records exist:

   ```bash
   dbLoadRecords("mydb.db", "P=myprefix:")
   ```

3. Verify QSRV 2 database file:

   ```bash
   # Check for qsrv2.db in IOC startup
   dbLoadRecords("$(PVXS)/db/qsrv2.db")
   ```

### Access Security Not Working

**Symptoms:**

- Access security configured but not enforced
- All users can access restricted PVs

**Solutions:**

1. Verify access security plugin is loaded:

   ```bash
   # In IOC startup
   pvxsAccessSecurity("path/to/rules")
   ```

2. Check access security rules file format
3. Verify credentials are being passed correctly
4. Enable debug logging:

   ```bash
   export PVXS_LOG=security=DEBUG
   ```

## Performance Issues

### High CPU Usage

**Symptoms:**

- PVXS using significant CPU
- System becomes slow

**Diagnosis:**

```bash
# Profile with perf
perf top -p $(pgrep myapp)

# Check for excessive logging
export PVXS_LOG=*=ERROR  # Reduce logging
```

**Solutions:**

- Reduce logging verbosity
- Check for tight polling loops
- Optimize callbacks (avoid heavy operations)
- Use Monitor instead of repeated Get operations
- Profile and optimize hot paths

### High Memory Usage

**Symptoms:**

- Memory usage grows over time
- Out of memory errors

**Diagnosis:**

```bash
# Monitor memory usage
watch -n 1 'ps aux | grep myapp'

# Use valgrind
valgrind --tool=massif ./myapp
```

**Solutions:**

- Check for memory leaks (see Memory Leaks section)
- Limit number of simultaneous operations
- Release Value objects when no longer needed
- Use shared_array for large arrays efficiently

### Slow Operations

**Symptoms:**

- Get/Put operations are slow
- Monitor updates lag

**Diagnosis:**

```bash
# Check network latency
ping server-host

# Profile with timing
time pvxget my:pv:name

# Enable debug logging to see timing
export PVXS_LOG=*=DEBUG
```

**Solutions:**

- Optimize network configuration
- Reduce field selection (request only needed fields)
- Use Monitor for frequently changing values
- Check server performance
- Verify not hitting rate limits

## Debugging Tools

### pvxvct - Virtual Cable Tester

Network debugging tool:

```bash
# Listen for client searches
pvxvct -C -P test:pv:name

# Listen for server beacons
pvxvct -S

# Specify address/port
pvxvct -C -B 0.0.0.0:5076 -P test:pv:name
```

### Verbose Logging

Enable detailed logging:

```bash
# Enable all debug logging
export PVXS_LOG=*=DEBUG

# Enable specific component
export PVXS_LOG=client=DEBUG,server=INFO

# Multiple components
export PVXS_LOG=client.io=DEBUG,server.channel=DEBUG

# Log to file
export PVXS_LOG=*=DEBUG
./myapp 2>&1 | tee pvxs.log
```

### Debugging with gdb

```bash
# Attach to running process
gdb -p $(pgrep myapp)

# Run with gdb
gdb ./myapp
(gdb) run

# When crash occurs:
(gdb) bt
(gdb) info registers
(gdb) print variable_name
```

### Network Packet Capture

```bash
# Capture PVAccess traffic
tcpdump -i any -w pvxs.pcap port 5075 or port 5076

# Analyze with wireshark
wireshark pvxs.pcap
```

## Common Error Messages

### "PV not found"

**Meaning:** Client cannot locate the specified PV

**Solutions:**

- Verify PV name is correct
- Check server is running
- Verify network configuration
- Use `pvxlist` to see available PVs
- Check server logs for errors

### "Connection timeout"

**Meaning:** Operation timed out waiting for server response

**Solutions:**

- Increase timeout value
- Check network connectivity
- Verify server is responsive
- Check for firewall issues

### "Type mismatch"

**Meaning:** Value type doesn't match expected type

**Solutions:**

- Check actual PV type: `pvxinfo my:pv:name`
- Use correct type in code
- Handle type conversion properly

### "Operation cancelled"

**Meaning:** Operation was cancelled (e.g., Context closed)

**Solutions:**

- Ensure Context remains valid during operation
- Don't close Context while operations are in progress
- Check for exceptions in callbacks

### "Invalid value"

**Meaning:** Value structure is invalid or incomplete

**Solutions:**

- Verify Value structure matches expected format
- Check all required fields are present
- Ensure Value is properly initialized

## Getting Help

If you cannot resolve your issue:

1. **Check Documentation:**

   - :doc:`api/overview` - API Documentation
   - `README.md <../README.md>`_ - Overview (external reference)
   - :doc:`guides/installation` - Installation guide
   - :doc:`guides/architecture` - Architecture overview
   - :ref:`reportbug <api/details:reportbug>` - How to report bugs
   - :doc:`releasenotes` - Known issues by version
   - :doc:`reference/netconfig` - Network troubleshooting details

2. **Search Existing Issues:**

   - [GitHub Issues](https://github.com/epics-base/pvxs/issues)
   - Search for similar problems

3. **Gather Information:**

   - PVXS version
   - Operating system and version
   - Compiler and version
   - EPICS Base version
   - Error messages and logs
   - Steps to reproduce

4. **Create Issue Report:**

   - Include all gathered information
   - Provide minimal reproduction case
   - Attach relevant logs
   - Describe expected vs. actual behavior

5. **EPICS Community:**

   - [EPICS Tech-Talk](https://epics.anl.gov/tech-talk/)
   - Search archives for similar issues
   - Post questions with detailed information

## Related Documentation

**API Reference:**

- :doc:`api/client` - Client configuration and operations
- :doc:`api/server` - Server configuration and setup
- :doc:`api/value` - Data structure handling
- :doc:`reference/netconfig` - Detailed network setup

**Reference Documentation:**

- :doc:`reference/cli` - CLI utility documentation
- :doc:`examples/example` - Code examples and walkthroughs
- :ref:`logconfig <api/util:logconfig>` - Logging setup

**Troubleshooting Resources:**

- See example code in `../example/` directory for working patterns
- Check `simpleget.cpp <../example/simpleget.cpp>`_ for basic client usage
- Check `simplesrv.cpp <../example/simplesrv.cpp>`_ for basic server setup

## Acknowledgments

This troubleshooting documentation was created and organized by **K. Gofron**, Oak Ridge National Laboratory, December 28, 2025.

---

**Note:** When reporting issues, always include:

- PVXS version (from `configure/CONFIG_PVXS_VERSION`)
- Operating system
- Compiler version
- EPICS Base version
- Complete error messages
- Steps to reproduce
- Relevant log output

