.. _netconfig:

PVA Network Configuration
=========================

Also see Client :ref:`clientconf` and Server :ref:`serverconf`
for full lists of **EPICS_PVA*** environment varables.

Big Picture
-----------

A PV Access network protocol operation proceeds in two phases:
PV name resolution, and data transfer.
Name resolution is the process is determining which PVA server claims to provide each PV name.
Once this is known, a TCP connection is open to that server, and the operation(s) are executed.

The PVA Name resolution process is similar to Channel Access protocol.

When a name needs to be resolved, a PVA client will begin sending UDP search messages to any addresses
listed in **EPICS_PVA_ADDR_LIST** and also via TCP to any servers listed in **EPICS_PVA_NAME_SERVERS**
which can be reached.

UDP searches are by default sent to port **5076**, subject to **EPICS_PVA_BROADCAST_PORT** and
port numbers explicitly given in **EPICS_PVA_ADDR_LIST**.

The addresses in **EPICS_PVA_ADDR_LIST** may include IPv4/6 unicast, multicast, and/or broadcast addresses.
By default (cf. **EPICS_PVA_AUTO_ADDR_LIST**) the address list is automatically populated
with the IPv4 broadcast addresses of all local network interfaces.

Searches will be repeated periodically in perpetuity until a positive response is received,
or the operation is cancelled.

In order to reduce the number of broadcast packets, which every PVA host must process,
the time between searches will initially by short, but gradually increase
as time passes without a positive response.
This interval may be reduced when a new PVA server begins sending Beacon messages,
or when `pvxs::client::Context::hurryUp` is called.

Server beacon destinations are by default configured using the client configuration.
This may be overridden with **EPICS_PVAS_BEACON_ADDR_LIST** and **EPICS_PVAS_AUTO_BEACON_ADDR_LIST**.

.. _addrspec:

Address Spec.
-------------

Entries in **EPICS_PVA*_ADDR_LIST** variables must be in one of the following forms:

* ``<ip4-or-host>[:<port#>][,TTL#][@ifacename]``
* ``"["<ip6-or-host>"]"[:<port#>][,TTL#][@ifacename]``

Examples include:

``myhost``
    Lookup hostname at startup, use default port number.
    Use OS routing table.

``10.1.1.1:5076``
    Explicit IPv4 address and port number.
    Use OS routing table.

``[2600:1234::42]``
    Explicit IPv6 address with default port.
    Use OS routing table.

``224.0.2.3,255@192.168.1.1``
    IPv4 multicast address, with Time To Live set to 255.
    Send via the network interface with address ``192.168.1.1``.
    Use default port number.

``[ff02::42:1],1@br0``
    IPv6 multicast address, with Time To Live set to 1 (roughly equivalent to IPv4 broadcast).
    Send via the network interface named ``br0``.
    Use default port number.
