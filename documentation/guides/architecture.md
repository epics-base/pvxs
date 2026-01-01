# PVXS Architecture

This document provides an overview of the PVXS architecture, design principles, and internal structure.

## Overview

PVXS is a modern C++ library implementing the PVAccess (PVA) protocol for EPICS. It provides three main layers:

1. **Data Layer** - Type-safe data containers (`pvxs::Value`)
2. **Network Layer** - PVAccess protocol implementation
3. **Application Layer** - Client and Server APIs

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                        │
│  ┌──────────────┐              ┌──────────────┐            │
│  │   Client     │              │   Server     │            │
│  │     API      │              │     API      │            │
│  └──────────────┘              └──────────────┘            │
│         │                              │                    │
│         └──────────────┬───────────────┘                    │
│                        │                                    │
│                 ┌──────▼──────┐                             │
│                 │   Data      │                             │
│                 │   Layer     │                             │
│                 │  (Value)    │                             │
│                 └──────┬──────┘                             │
└────────────────────────┼────────────────────────────────────┘
                         │
┌────────────────────────┼────────────────────────────────────┐
│                 ┌──────▼──────┐                             │
│                 │   Network   │                             │
│                 │   Layer     │                             │
│                 │  (PVAccess) │                             │
│                 └──────┬──────┘                             │
└────────────────────────┼────────────────────────────────────┘
                         │
┌────────────────────────┼────────────────────────────────────┐
│                 ┌──────▼──────┐      ┌──────────────┐      │
│                 │  EPICS Base │      │  libevent    │      │
│                 │   (OSD)     │      │  (Networking)│      │
│                 └─────────────┘      └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

## Design Principles

### 1. Type Safety

PVXS eliminates the need for explicit downcasting and NULL pointer checks common in pvDataCPP. The `Value` class uses a single type that handles all data types internally.

**Before (pvDataCPP):**

```cpp
PVStructurePtr top = ...;
PVIntPtr value = top->getSubField<PVInt>("value");
if(!value)
    throw ...;
int32_t val = value->get();
```

**After (PVXS):**

```cpp
Value top = ...;
int32_t val = top["value"].as<int32_t>();  // Throws if missing or wrong type
```

### 2. Exception-Based Error Handling

PVXS uses exceptions for error handling rather than return codes, making error paths explicit and reducing the chance of ignored errors.

### 3. Functor-Based Callbacks

Instead of requiring interface classes (as in pvAccessCPP), PVXS uses C++ functors/lambdas for callbacks, reducing boilerplate code.

**Before (pvAccessCPP):**

```cpp
struct MyCallback : public pvac::GetCallback {
    void getDone(const GetEvent& evt) override { ... }
};
MyCallback cb;
chan.get(&cb);
```

**After (PVXS):**

```cpp
ctxt.get("pv:name")
    .result([](Result&& r) { ... })
    .exec();
```

### 4. Automatic Change Tracking

Change tracking is built into the `Value` class, eliminating the need for separate `BitSet` objects.

**Before (pvDataCPP):**

```cpp
PVStructurePtr top = ...;
BitSetPtr changed(new BitSet(...));
value->put(42);
changed->set(value->getFieldOffset());
```

**After (PVXS):**

```cpp
Value top = ...;
top["value"] = 42;  // Automatically marked as changed
assert(top["value"].isMarked());
```

### 5. Modern C++ Features

PVXS leverages C++11 features:
- Move semantics for efficient transfers
- Smart pointers for automatic memory management
- RAII for resource management
- Type traits for compile-time checking

## Architecture Components

### Core Components

1. **Value Container** (`pvxs::Value`)
   - Type-safe data structure representation
   - Supports all EPICS scalar and array types
   - Built-in change tracking
   - Efficient array handling with `shared_array`

2. **Client Context** (`pvxs::client::Context`)
   - Manages connections to PVAccess servers
   - Handles server discovery
   - Provides Get, Put, Monitor, RPC operations
   - Automatic reconnection

3. **Server Instance** (`pvxs::server::Server`)
   - Listens for client connections
   - Manages multiple data sources
   - Handles concurrent client requests
   - Automatic beaconing for discovery

4. **SharedPV** (`pvxs::server::SharedPV`)
   - Represents a single PV served by a server
   - Mailbox mode for simple storage
   - Custom handlers for Put/RPC operations
   - Supports multiple concurrent subscribers

5. **Source** (`pvxs::server::Source`)
   - Abstract interface for PV sources
   - Allows dynamic PV registration
   - Used by IOC integration

## Data Layer

### Value Container

The `Value` class is the central data container in PVXS. It represents a single data structure, field, or array element.

See :doc:`api/value` for detailed API documentation.

**Key Features:**

- **Type Safety**: Compile-time and runtime type checking
- **Change Tracking**: Automatic marking of modified fields
- **Efficient Access**: Direct field access via `operator[]`
- **Type Conversion**: Safe conversions between compatible types
- **Array Support**: Efficient handling of arrays with `shared_array`

**Structure:**

```
Value
├── Type information (TypeCode)
├── Data storage (variant-based)
├── Change tracking (BitSet-like, internal)
├── Field metadata
└── Children (for structures)
```

**Example Usage:**

```cpp
// Create an NTScalar structure
Value pv = nt::NTScalar{TypeCode::Float64}.create();

// Set value (automatically marked as changed)
pv["value"] = 42.0;

// Access value with type conversion
double val = pv["value"].as<double>();

// Check if field is marked
if(pv["value"].isMarked()) {
    // Field has been modified
}

// Clone with empty structure
Value empty = pv.cloneEmpty();

// Iterate over fields
for(Value field : pv.ichildren()) {
    std::cout << pv.nameOf(field) << std::endl;
}
```

### Type System

PVXS supports all EPICS data types:

**Scalar Types:**

- `TypeCode::Int8`, `Int16`, `Int32`, `Int64`
- `TypeCode::UInt8`, `UInt16`, `UInt32`, `UInt64`
- `TypeCode::Float32`, `Float64`
- `TypeCode::String`
- `TypeCode::Bool`

**Array Types:**

- Arrays of any scalar type
- Efficient storage with `shared_array<T>`

**Structures:**

- Nested structures
- Union types
- Variant unions

**Normative Types:**

- `NTScalar` - Scalar with metadata
- `NTScalarArray` - Array with metadata
- `NTEnum` - Enumeration
- `NTTable` - Table/table
- `NTNDArray` - ND array (for areaDetector)
- `NTURI` - URI structure

## Network Layer

### PVAccess Protocol

PVXS implements the PVAccess protocol version 1.x, providing:

**Operations:**

- **GET_FIELD (Info)** - Query PV structure
- **GET** - Fetch present value
- **PUT** - Update PV value
- **RPC** - Remote procedure call
- **MONITOR** - Subscribe to updates
- **SEARCH** - Server discovery (UDP)

**Protocol Features:**

- Binary encoding (efficient)
- Field selection (partial updates)
- Flow control (for Monitor)
- Compression support
- Authentication framework

### Connection Management

**Client Side:**

- Automatic server discovery via UDP broadcast
- Connection pooling (reuse connections)
- Automatic reconnection on failure
- Connection health monitoring

**Server Side:**

- Accept multiple concurrent connections
- Per-connection state management
- Connection lifecycle tracking
- Graceful shutdown

### Discovery Mechanism

1. **UDP Search (Client → Server)**
   - Client broadcasts search request on port 5076
   - Request includes PV name pattern
   - Servers matching pattern respond

2. **UDP Beacon (Server → Client)**
   - Server periodically broadcasts beacon
   - Beacon includes server address and port
   - Clients can listen to discover all servers

## Client Architecture

### Client Context

The `Context` class manages all client-side operations:

See :doc:`api/client` for detailed API documentation.

```
Context
├── Config (network settings)
├── Connection Manager
│   ├── Active connections
│   ├── Connection pool
│   └── Discovery handler
├── Operation Manager
│   ├── Pending operations
│   └── Operation lifecycle
└── Event Loop Integration
    └── libevent integration
```

**Key Responsibilities:**

- Server discovery and connection management
- Operation lifecycle (Get, Put, Monitor, RPC)
- Error handling and retry logic
- Thread safety for concurrent operations

### Operation Flow (Get Example)

```
1. Client: ctxt.get("pv:name")
   └── Creates GetBuilder

2. Client: .exec()
   └── Starts operation
   └── Checks connection pool

3. If no connection:
   ├── Send UDP search
   ├── Wait for server response
   └── Establish TCP connection

4. Send GET request
   └── Includes pvRequest (field selection)

5. Wait for response
   └── Parse response
   └── Create Value from data

6. Invoke callback or return result
   └── result() callback (if set)
   └── or wait() return
```

### Builder Pattern

Operations use a builder pattern for configuration:

```cpp
auto op = ctxt.get("pv:name")
    .pvRequest("field(value,alarm)")
    .result([](Result&& r) {
        Value v = r();
        // Process value
    })
    .exec();

// op can be stored and canceled later
```

This allows:
- Fluent API
- Optional configuration
- Delayed execution
- Operation cancellation

## Server Architecture

### Server Structure

See :doc:`api/server` and :doc:`api/sharedpv` for detailed API documentation.

```
Server
├── Config (network settings)
├── Network Listener (TCP)
├── Beacon Sender (UDP)
├── Source Manager
│   ├── __builtin (StaticSource)
│   ├── __server (server info)
│   └── User Sources
└── Connection Handler
    ├── Per-connection state
    └── Request routing
```

### Source System

Sources provide a pluggable architecture for PV registration:

**Built-in Sources:**

- **`__builtin`** - Static PVs added via `addPV()`
- **`__server`** - Server information PV

**IOC Source:**

- **QSRV2** - Database record integration

**Custom Sources:**

- User-defined sources implementing `Source` interface
- Dynamic PV registration
- Priority-based ordering

### Request Handling Flow

```
1. Client connects (TCP)
   └── Server creates connection handler

2. Client sends request (GET/PUT/etc.)
   └── Parse request
   └── Extract PV name and pvRequest

3. Route to appropriate Source
   └── Check Source priority
   └── Call Source::onCreate()

4. Source creates ConnectOp
   └── Validate pvRequest
   └── Return prototype (data type)

5. Operation execution
   └── For GET: Source provides data
   └── For PUT: Source receives data
   └── For MONITOR: Setup subscription

6. Send response
   └── Serialize data
   └── Send to client
```

### SharedPV Modes

**Mailbox Mode:**

- Stores last received value
- Automatically sends updates to subscribers
- Simple PUT handler stores value verbatim

**Custom Handler Mode:**

- User-defined PUT handler
- Validation and processing
- Custom update logic

## IOC Integration

### QSRV 2

QSRV 2 (Quick Server 2) provides high-level IOC integration:

```
IOC Database
    │
    ├── Single PV Access
    │   └── Direct database record access
    │
    ├── Group PV Access
    │   └── JSON-defined groups
    │   └── Efficient batch operations
    │
    └── PVA Links
        └── Link database records via PVAccess
```

**Features:**

- Automatic database record serving
- Group-based operations (reduce network traffic)
- Access security integration
- Support for all database field types

### Integration Points

1. **Database Hooks**
   - Intercepts database record operations
   - Provides PVAccess interface
   - Maintains synchronization

2. **IOC Shell Commands**
   - `pvxsr()` - Server report
   - `pvxsl()` - List PVs
   - `pvxsi()` - Version info
   - `pvxgl()` - Group information

3. **Configuration**
   - Environment variables (`$EPICS_PVA_*`)
   - Database configuration
   - Access security rules

## Threading Model

### Client Threading

**Thread Safety:**

- `Context` is thread-safe for concurrent operations
- Multiple threads can call `get()`, `put()`, etc. simultaneously
- Operations are independent

**Event Loop:**

- Uses libevent for async I/O
- Single event loop per Context (by default)
- Operations complete in event loop thread
- Callbacks execute in event loop thread

**Blocking Operations:**

- `wait()` blocks calling thread
- Suitable for synchronous code
- Use with care in event-driven code

### Server Threading

**Accept Thread:**

- Accepts new connections
- Creates connection handlers

**Worker Threads:**

- Handle client requests
- Execute user callbacks
- Send responses

**Callback Threading:**

- PUT/RPC handlers execute in worker threads
- User code must be thread-safe
- SharedPV access is internally synchronized

### Best Practices

1. **Avoid Blocking in Callbacks**
   - Keep callbacks short
   - Defer heavy work to separate threads

2. **Context Lifetime**
   - Keep Context alive during operations
   - Don't destroy while operations are pending

3. **Value Sharing**
   - Values are not thread-safe by default
   - Copy or synchronize when sharing between threads

## Memory Management

### Smart Pointers

PVXS uses modern C++ memory management:

- `std::shared_ptr` - Shared ownership
- `std::unique_ptr` - Exclusive ownership
- RAII - Automatic cleanup

### Value Storage

**Structure:**

- Values use efficient storage (variant-based)
- Arrays use `shared_array` for zero-copy
- Structures share type definitions

**Ownership:**

- Values can be moved (not copied when possible)
- Arrays use reference counting
- Type definitions are shared/immutable

### Memory Patterns

**Efficient Patterns:**

```cpp
// Move Value (no copy)
Value v1 = ...;
Value v2 = std::move(v1);

// Reuse structure
Value template = ...;
Value instance = template.cloneEmpty();
```

**Avoid:**

```cpp
// Unnecessary copies
Value v2 = v1;  // Prefer std::move(v1) if v1 no longer needed

// Holding references to temporary Values
Value& ref = createValue();  // Dangerous!
```

## Protocol Implementation

### Message Encoding

**Binary Format:**

- Efficient binary encoding
- Network byte order (big-endian)
- Variable-length encoding for integers
- String encoding (UTF-8)

**Message Structure:**

```
Message Header
├── Command ID
├── Payload size
└── Payload
    ├── Request ID
    ├── PV name
    ├── pvRequest
    └── Data (for PUT/RPC)
```

### Field Selection

**pvRequest Format:**

```
field(value)              # Single field
field(value,alarm)        # Multiple fields
field(value)field(extra)  # Multiple selections
```

**Implementation:**

- Parse pvRequest into field mask
- Filter data before encoding
- Reduces network traffic

### Flow Control (Monitor)

**Mechanism:**

- Client specifies queue size
- Server respects queue limits
- Backpressure when queue full

**Implementation:**

- Per-subscription queue
- Drop oldest or reject new (configurable)
- Automatic flow control messages

## Comparison with Other EPICS Modules

### vs. pvDataCPP

**pvDataCPP:**

- Class hierarchy (PVField base class)
- Explicit downcasting required
- Separate BitSet for change tracking
- Interface classes for callbacks

**PVXS:**

- Single Value class
- Type-safe access
- Built-in change tracking
- Functor-based callbacks

### vs. pvAccessCPP

**pvAccessCPP:**

- Interface classes for callbacks
- More verbose code
- Older C++ style

**PVXS:**

- Functor-based (lambdas)
- Builder pattern
- Modern C++ (C++11+)
- Cleaner API

### vs. Channel Access (CA)

**CA:**

- Older protocol
- Less structured data
- Different API model

**PVXS (PVAccess):**

- Modern protocol
- Rich structured data
- More efficient
- Better suited for complex data

## Detailed API Documentation

This architecture document provides a high-level overview. For detailed API documentation, see:

**Core APIs:**

- :doc:`api/value` - Detailed Value class documentation, field lookup, iteration, arrays
- :doc:`api/client` - Detailed Context, GetBuilder, PutBuilder, MonitorBuilder, RPCBuilder documentation
  - :ref:`get-info <api/client:get-info>` - Get/Info Operations
  - :ref:`clientputapi <api/client:clientputapi>` - Put Operations
  - :ref:`clientmonapi <api/client:clientmonapi>` - Monitor Operations
  - :ref:`clientrpcapi <api/client:clientrpcapi>` - RPC Operations
- :doc:`api/server` - Detailed Server, Config, Source documentation
- :doc:`api/sharedpv` - SharedPV and operation handlers

**Comparisons:**

- :ref:`comparison-with-pvdatacpp <api/overview:comparison-with-pvdatacpp>` - Detailed comparison examples
- :ref:`comparison-with-pvaccescpp <api/overview:comparison-with-pvaccescpp>` - API design differences

**Integration:**

- :doc:`api/ioc` - Detailed IOC hooks and integration
- :doc:`reference/qgroup` - Database integration details

**Implementation:**

- :doc:`reference/netconfig` - Network protocol implementation
- :doc:`examples/example` - Source code examples

## Additional Resources

- :doc:`api/overview` - Complete API documentation overview
- [PVAccess Specification](https://epics.anl.gov/base/R3-16/0-docs/EPICS_Network_Protocols.pdf)
- [EPICS Base Documentation](https://epics.anl.gov/base/)
- [Source Code](https://github.com/epics-base/pvxs)

## Acknowledgments

This architecture documentation was created and organized by **K. Gofron**, Oak Ridge National Laboratory, December 28, 2025.

---

**Note:** This architecture document provides a high-level overview. For detailed API documentation, see the [online documentation](https://epics-base.github.io/pvxs/).

