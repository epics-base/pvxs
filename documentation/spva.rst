.. _secure_pvaccess:

Secure PVAccess
===============

Secure PVAccess (SPVA) enhances the existing PVAccess protocol by integrating :ref:`transport_layer_security` (TLS)
with comprehensive :ref:`certificate_management`, enabling encrypted communication channels and authenticated connections
between EPICS clients and servers (EPICS agents) - see :ref:`authn_and_authz`.

For a glossary of terms see: :ref:`glossary`

Key Features:

- Encrypted communication using ``TLS 1.3``
- Certificate-based authentication
- Comprehensive certificate lifecycle management
- Backward compatibility with existing PVAccess deployments
- Integration with site authentication systems

In SPVA terminology, an `EPICS Agent` refers to any PVAccess network client.

Note: This release requires specific unmerged changes to epics-base.

See :ref:`quick_start` to get started.

.. _transport_layer_security:

Transport Layer Security
------------------------

``SPVA`` uses ``TLS 1.3`` to establish secure connections between EPICS agents. Both client and server
can authenticate their peer using ``X.509`` certificates. Key features of the TLS implementation:

- Mutual authentication when both peers present valid certificates
- Server-only authentication when only the server presents a certificate
- Fallback to ``TCP`` when ``TLS`` is not configured or certificates are invalid
- Certificate status verification during connection establishment

Supported Keychain-File Formats, Encodings and File Types
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

+-----------+----------------------+-----------+-------------------------+------------------------------+-------------------------+
| File Type | Extension            | Encoding  | Includes Private Key?   | Includes Certificate Chain?  |     Common Usage        |
+===========+======================+===========+=========================+==============================+=========================+
|| PKCS#12  || ``.p12``, ``.pfx``  || Binary   || Optional (password)    || Yes                         || Distributing cert key  |
+-----------+----------------------+-----------+-------------------------+------------------------------+-------------------------+

To use any of these formats just use the appropriate file extension when specifying the keychain file.

Unsupported Certificate Formats, Encodings and File Types
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

+-----------+----------------------+-----------+-------------------------+------------------------------+-------------------------+
| File Type | Extension            | Encoding  | Includes Private Key?   | Includes Certificate Chain?  |     Common Usage        |
+===========+======================+===========+=========================+==============================+=========================+
|| PEM      || ``.pem``, ``.crt``, || Base64   || Optional               || Optional (concatenated)     || Web servers, OpenSSL   |
||          || ``.cer``, ``.key``  ||          ||                        ||                             ||                        |
+-----------+----------------------+-----------+-------------------------+------------------------------+-------------------------+
|| JKS      || ``.jks``            || Binary   || Optional               || Yes                         || Java applications      |
+-----------+----------------------+-----------+-------------------------+------------------------------+-------------------------+

TLS encapsulation of the PVAccess protocol
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In network protocols, encapsulation is used to transport a higher layer protocol over a lower layer protocol, e.g., ``TCP`` over ``IP``.
In the context of TLS, PVAccess messages are encapsulated within ``TLS`` records for secure transport.

Encapsulation involves wrapping the higher-layer protocol's data within the lower-layer protocol's format.
TLS is so named because it wraps all data above the ``Transport Layer`` in an impermeable ``Security`` layer.
For SPVA, this means PVAccess messages are wrapped in TLS records that include headers specifying
content type, protocol version, and length, followed by the encrypted PVAccess data as the payload.

.. image:: pvaencapsulation.png
   :alt: TLS Encapsulation of PVAccess
   :align: center

Note: We use ``TLS version 1.3`` for Secure PVAccess. This version deprecates support for connection renegotiation which is a security risk. So any
connections that are established using Secure PVAccess will not be renegotiated but will be closed if a certificate is revoked or needs to be renewed.


.. _environment_variables:

Environment Variables
^^^^^^^^^^^^^^^^^^^^^
The following environment variables control SPVA behavior:

.. note::
   There is an implied hierarchy to the applicability of the environment variables such that
   the PVAS version supersedes a PVA version.
   So, if an EPICS server agent wants to specify its keychain file location it can simply
   provide the ``EPICS_PVA_TLS_KEYCHAIN`` environment variable as long as
   ``EPICS_PVAS_TLS_KEYCHAIN`` is not configured.


+--------------------------+----------------------------+-------------------------------------+---------------------------------------------------------------+
| Name                     | Key                        | Value                               | Description                                                   |
+==========================+============================+=====================================+===============================================================+
| EPICS_PVA_TLS_KEYCHAIN   | {fully qualified path  to keychain file}                         | This is the string that determines the fully qualified path   |
+--------------------------+                                                                  | to the keychain file that contains the certificate,           |
| EPICS_PVAS_TLS_KEYCHAIN  | e.g. ``~/.config/client.p12``,                                   | and private keys used in the TLS handshake.                   |
|                          | ``~/.config/server.p12``                                         | Note: If not specified then TLS is disabled                   |
+--------------------------+------------------------------------------------------------------+---------------------------------------------------------------+
| EPICS_PVA_TLS_KEYCHAIN   | {fully qualified path to keychain password file}                 | This is the string that determines the fully qualified path   |
| _PWD_FILE                |                                                                  | to a file that contains the password that unlocks the         |
+--------------------------+ e.g. ``~/.config/client.pass``,                                  | keychain file.  This is optional.  If not specified, the      |
| EPICS_PVAS_TLS_KEYCHAIN  | ``~/.config/server.pass``                                        | keychain file contents will not be encrypted. It is not       |
| _PWD_FILE                |                                                                  | recommended to not specify a password file.                   |
+--------------------------+----------------------------+-------------------------------------+---------------------------------------------------------------+
| EPICS_PVA_TLS_OPTIONS    | ``client_cert``            | ``optional`` (default)              | Require client certificate to be presented.                   |
|                          |                            |                                     |                                                               |
|                          | Determines whether client  +-------------------------------------+---------------------------------------------------------------+
| Sets the TLS options     | certificates are required  | ``require``                         | Don't require client certificate to be presented.             |
| for clients and servers. +----------------------------+-------------------------------------+---------------------------------------------------------------+
| A string containing      | ``on_expiration``          | ``fallback-to-tcp``  (default)      | For servers only tcp search requests will be responded to.    |
| key/value pairs          |                            |                                     | For clients then no client certificate will be presented      |
| separated by commas,     | Determines what to do when |                                     | in the TLS handshake (but searches will still offer both tls  |
| tabs or newlines         | an EPICS agent's           |                                     | and tcp as supported protocols)                               |
|                          | certificate has expired,   +-------------------------------------+---------------------------------------------------------------+
|                          | and a new one can't be     | ``shutdown``                        | The process will exit gracefully.                             |
|                          | automatically provisioned  +-------------------------------------+---------------------------------------------------------------+
|                          |                            | ``standby``                         | Servers will not respond to any requests until a new          |
|                          |                            |                                     | certificate is successfully provisioned.  It will keep        |
|                          |                            |                                     | retrying the keychain file periodically.  When a valid        |
|                          |                            |                                     | certificate is available it will continue as normal.          |
|                          |                            |                                     |                                                               |
|                          |                            |                                     | For a client standby has the same effect as shutdown.         |
|                          +----------------------------+-------------------------------------+---------------------------------------------------------------+
|                          | ``stop_if_no_cert``        | ``yes``, ``true``, ``1``            | Stop if no certificate is provided                            |
|                          |                            |                                     |                                                               |
|                          | Determines whether server  +-------------------------------------+---------------------------------------------------------------+
|                          | stops if no cert           | ``no``, ``false``, ``0`` (default)  | Don't stop if no certificate is provided                      |
|                          +----------------------------+-------------------------------------+---------------------------------------------------------------+
|                          | ``disable_stapling``       | ``yes``, ``true``, ``1``            | Servers won't staple certificate status, clients won't        |
|                          |                            |                                     | request stapling information during TLS handshake             |
|                          | Determines whether         +-------------------------------------+---------------------------------------------------------------+
|                          | stapling is enabled        | ``no``, ``false``, ``0`` (default)  | Don't disable stapling                                        |
+--------------------------+----------------------------+-------------------------------------+---------------------------------------------------------------+
| EPICS_PVA_TLS_PORT       | {port number} default ``5076``                                   | This is a number that determines the port used for the Secure |
|                          |                                                                  | PVAccess, either as the port on the Secure PVAccess server    |
+--------------------------+ e.g. ``8076``                                                    | for clients to connect to - PVA, or as the local port number  |
| EPICS_PVAS_TLS_PORT      |                                                                  | for Secure PVAccess servers to listen on - PVAS.              |
|                          |                                                                  |                                                               |
+--------------------------+------------------------------------------------------------------+---------------------------------------------------------------+
| SSLKEYLOGFILE            | {fully qualified path to key log file}                           | This is the path to the SSL key log file that, in conjunction |
|                          |                                                                  | with the build-time macro `PVXS_ENABLE_SSLKEYLOGFILE`,        |
|                          | e.g. ``~/.config/keylog``                                        | controls where and whether we store the session key for TLS   |
|                          |                                                                  | sessions in a file.  If it is defined, then the code will     |
|                          |                                                                  | contain the calls to save the keys in the file specified      |
|                          |                                                                  | by this variable.                                             |
+--------------------------+------------------------------------------------------------------+---------------------------------------------------------------+

.. _configuration:

API Configuration Options
^^^^^^^^^^^^^^^^^^^^^^^^^

The following are new configuration options now available
in both the `pvxs::server::Config` and `pvxs::client::Config` classes,
via their public base `pvxs::impl::ConfigCommon` class:

- `pvxs::impl::ConfigCommon::expiration_behaviour` - Set the certificate expiration behavior
- `pvxs::impl::ConfigCommon::tls_keychain_file` - Set keychain file path
- `pvxs::impl::ConfigCommon::tls_keychain_pwd` - Set keychain file password
- `pvxs::impl::ConfigCommon::tls_client_cert_required` - Control client certificate requirements
- `pvxs::impl::ConfigCommon::tls_disable_stapling` - Disable certificate status stapling
- `pvxs::impl::ConfigCommon::tls_disable_status_check` - Disable certificate status checking
- `pvxs::impl::ConfigCommon::tls_disabled` - Disable TLS
- `pvxs::impl::ConfigCommon::tls_port` - Set TLS port number
- `pvxs::impl::ConfigCommon::tls_throw_if_cant_verify` - Control verification failure behavior

Here are server-specific configuration options:

- `pvxs::server::Config::tls_stop_if_no_cert` - Stop server if certificate unavailable
- `pvxs::server::Config::tls_throw_if_no_cert` - Throw exception if certificate unavailable


API Additions for Secure PVAccess
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Runtime Reconfiguration
~~~~~~~~~~~~~~~~~~~~~~~

Allows runtime reconfiguration of a TLS connection.  It does this by dropping all TLS connections and
then re-initialising them using the given configuration.  This means checking if the certificates
and keys exist, loading and verifying them, checking for status and status of peers, etc.

`pvxs::client::Context::reconfigure` and `pvxs::server::Server::reconfigure` allow runtime TLS configuration updates:

    .. code-block:: c++

        // Initial client setup with certificate
        auto cli_conf(serv.clientConfig());
        cli_conf.tls_keychain_file = "client1.p12";
        auto cli(cli_conf.build());

        // Later reconfiguration with new certificate
        cli_conf = cli.config();
        cli_conf.tls_keychain_file = "client2.p12";
        cli_conf.tls_keychain_pwd = "pwd";
        cli.reconfigure(cli_conf);

Creation of client to PVACMS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Internally SPVA needs to create a special client when it is connecting to :ref:`pvacms` to check status.  This
client can't work in the normal way, checking for certificate status because it would become
endlessly recursive,

 - An EPICS agent creating a new connection would try try to verify its certificate

   - so it would open a connection to :ref:`pvacms` to try to check status of that certificate,
   - but that connection would need to have its certificate verified

     - so it would open a connection to :ref:`pvacms` to try to check status of that certificate,
     - but that connection would need to have its certificate verified

       - so it would open a connection to :ref:`pvacms` to try to check status of that certificate,
       - ... infinitely

To avoid this a special client can be created with this API.  Normally you won't need to check
certificate status yourself but if you do use this API to create the client context.

`pvxs::client::Context::forCMS` creates an isolated client context appropriately configured to access :ref:`pvacms` without recursion:

    .. code-block:: c++

        Value getPVAStatus(const std::string cert_status_uri) {
            auto client(client::Context::forCMS());
            Value result = client.get(cert_status_uri).exec()->wait();
            client.close();
            return result;
        }

Wildcard PV Support
~~~~~~~~~~~~~~~~~~~

This addition is based on the Wildcard PV support included in epics-base since version 3.  It
extends this support to pvxs allowing PVs to be specified as wildcard patterns.  We use this
to provide individualised PVs for each certificate's status management.

`pvxs::server::SharedWildcardPV` support for pattern-matched PV names:

    .. code-block:: c++

        // Define a server that responds to any SEARCH request with WILDCARD:PV:<4-characters>:<any-string>
        // It will extract the 4-character part of the PV name as the `id` and
        // the last string as the `name`

        SharedWildcardPV wildcard_pv(SharedWildcardPV::buildMailbox());
        wildcard_pv.onFirstConnect([](SharedWildcardPV &pv, const std::string &pv_name,
                                    const std::list<std::string> &parameters) {
            // Extract id and name from parameters
            auto it = parameters.begin();
            const std::string &id = *it;
            const std::string &name = *++it;

            // Process and post value
            if (pv.isOpen(pv_name)) {
                pv.post(pv_name, value);
            } else {
                pv.open(pv_name, value);
            }
        });
        wildcard_pv.onLastDisconnect([](SharedWildcardPV &pv, const std::string &pv_name,
                                    const std::list<std::string> &parameters) {
            pv.close(pv_name);
        });

        // Add wildcard PV to server
        serv.addPV("WILDCARD:PV:????:*", wildcard_pv);

.. _protocol_operation:

Protocol Operation
------------------

.. _connection_establishment:

Connection Establishment
^^^^^^^^^^^^^^^^^^^^^^^^

Connections are established using TLS if at least the server side is configured for TLS.

Prior to the TLS handshake:

- Certificates are loaded and validated
- CA trust is verified all the way down the chain
- Both sides subscribe to certificate status where configured for their own certificate and all those in the chain
- All certificate statues are cached

During the TLS handshake:

- Certificates are exchanged
- Servers staple cached certificate status in handshake
- Both sides validate and verify their peer certificate against trusted root certificates

After the TLS handshake:

- Both sides subscribe to peer certificate status where configured
- Clients may use OCSP stapled status immediately before waiting for status monitoring results

.. _state_machines:

State Machines
^^^^^^^^^^^^^^

*Server TLS Context State Machine:*

The server transitions based on:

- Certificate validity
- CA trust status
- Certificate status monitoring results
- :ref:`configuration` options (e.g., stop_if_no_cert)

States:

- ``Init``: Initial state, loads and validates certificates
- ``TcpReady``: Responds to TCP protocol requests when certificates are valid
- ``TlsReady``: Responds to both TCP and TLS protocol requests
- ``DegradedMode``: Fallback state for invalid certificates or missing TLS configuration

.. image:: spva_tls_context_state_machine.png
   :alt: SPVA Server TLS Context State Machine
   :align: center


*Client TLS Context State Machine:*

Similar to server state machine but

- Never exits on TLS configuration issues
- Moves to ``DEGRADED`` state and continues with TCP protocol if needed

.. image:: spva_tls_client_context_state_machine.png
   :alt: SPVA Client TLS Context State Machine
   :align: center


.. _tls_context_search_state_machine:

Search Handler State Machines
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

*Server Search Handler:*

States:

- ``DegradedMode``: Responds only to TCP protocol requests
- ``TcpReady``: Responds only to TCP protocol requests, ignores TLS
- ``TlsReady``: Responds to both TCP and TLS protocol requests

.. image:: spva_tls_context_search_states.png
   :alt: SPVA Server TLS Context Search Handler State Machine
   :align: center

*Client Search Handler:*

- Similar to server but from client perspective
- Executes ``TLS_CONNECTOR`` on successful TLS handshake
- Falls back to ``TCP_CONNECTOR`` otherwise

.. image:: spva_tls_client_context_search_states.png
   :alt: SPVA Client TLS Context Search Handler State Machine
   :align: center

.. _connection_state_machine:

Connection State Machines
~~~~~~~~~~~~~~~~~~~~~~~~~

*Server Connection:*

- Manages TLS handshake and certificate validation
- Monitors peer certificate status
- Continues normal operation only after successful validation

.. image:: spva_connection_state_machines.png
   :alt: SPVA Connection State Machines
   :align: center


*Client Connection:*

- Similar to server but verifies stapled certificates
- Destroys connection on completion

.. image:: spva_client_connection_state_machines.png
   :alt: SPVA Client Connection State Machine
   :align: center


.. _tls_handshake:

TLS Handshake
~~~~~~~~~~~~~

The following diagram shows the simplified TLS handshake sequence between server and client:

.. image:: spvaseqdiag.png
   :alt: SPVA Sequence Diagram
   :align: center

1. Each agent uses an ``X.509`` certificate for peer authentication
2. During handshake:

   - Certificates are exchanged
   - Both sides verify peer certificates against trusted root certificates
   - Multiple certificates may be verified in the chain to trusted CA
   - Local verification checks signature, expiration, and usage flags

3. SPVA certificates may include status monitoring extension requiring:

   - Subscription to certificate status from issuing CA's service (:ref:`pvacms`)
   - Receipt of GOOD status before trust

4. Agents subscribe to:

   - Peer's certificate status
   - Own certificate status and certificate chain

5. Servers cache and staple certificate status in handshake

.. _online_certificate_status_protocol_OCSP:

OCSP and Status Verification
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. _ocsp_stapling:

OCSP Stapling
^^^^^^^^^^^^^

OCSP Stapling optimizes certificate status verification during TLS handshake:

.. figure:: images/ocsp_stapling.png
    :width: 800px
    :align: center
    :name: ocsp-stapling

- Enabled by default with status monitoring extension
- Disable using EPICS_PVAS_TLS_OPTIONS="disable_stapling"

.. _status_verification:

Status Verification
^^^^^^^^^^^^^^^^^^^

Certificate status verification occurs at several points:

1. Initial Connection

   - Certificates are verified during TLS handshake
   - Both peers verify against trusted root certificates
   - Basic checks include:

     - Signature validation
     - Expiration dates
     - Usage flags

2. Runtime Monitoring

   - EPICS agents subscribe to:

     - Their own certificate status
     - Their certificate chain status
     - Peer certificate status
     - Peer certificate chain status

3. Status Response Handling

   - If status not received:

     - Search requests are ignored
     - Client retries later

   - If status not GOOD:

     - Server offers only TCP protocol
     - Client fails connection validation

   - If status GOOD:

     - Server offers both TCP and TLS
     - Connection proceeds normally

4. Optimization

   - Servers cache status for stapling
   - Clients can use stapled status
   - Reduces initial :ref:`pvacms` requests

.. _status_caching:

Status Caching
^^^^^^^^^^^^^^

- Agents subscribe to peer certificate and chain status
- Status transitions trigger connection status re-evaluation
- Cached status used within validity period to reduce :ref:`pvacms` requests
- Servers staple cached status in handshake
- Clients may skip initial :ref:`pvacms` request using stapled status

Beacons
^^^^^^^

PVAccess Beacon Messages have not been upgraded to TLS support. Important considerations:

1. Historical Use:
   - Previously used to trigger resend of unanswered Search Messages
   - This practice is now discouraged
   - Other methods should be used to determine server status

2. Current Behavior:
   - Servers broadcast on any configured port
   - Clients should not use ports directly
   - Use only as server availability indicator

3. Security Implications:
   - Beacons remain unencrypted
   - Do not contain sensitive information
   - Cannot be used for secure discovery

.. _protocol_debugging:

Protocol Debugging
------------------

TLS Packet Inspection
^^^^^^^^^^^^^^^^^^^^^

For detailed TLS traffic analysis:

1. Enable key logging at build time:

   - Set PVXS_ENABLE_SSLKEYLOGFILE during compilation

2. Configure runtime logging:

    .. code-block:: sh

        export SSLKEYLOGFILE=/tmp/sslkeylog.log

3. Configure Wireshark:

   - Edit > Preferences > Protocols > TLS
   - Set "(Pre)-Master-Secret log filename" to match SSLKEYLOGFILE path
   - TLS traffic will now be decrypted in Wireshark

Debug Logging
^^^^^^^^^^^^^

Enable detailed PVXS debug logging:

1. Environment variable method:

    .. code-block:: sh

        export PVXS_LOG="pvxs.stapling*=DEBUG"

1. Command line option with pvxcert:

    .. code-block:: sh

        pvxcert -d ...

New Debug Categories:

- ``pvxs.certs.auth``          - Authentication mechanisms
- ``pvxs.auth.cfg``            - Authn configuration
- ``pvxs.auth.cms``            - CMS authentication
- ``pvxs.auth.jwt``            - JWT authentication mechanism
- ``pvxs.auth.krb``            - Kerberos authentication mechanism
- ``pvxs.auth.mon``            - Authn monitoring
- ``pvxs.auth.stat``           - Authn status
- ``pvxs.auth.std``            - Basic credentials authentication mechanism
- ``pvxs.auth.tool``           - Authn tools (``pvacert``)
- ``pvxs.certs.status``        - Certificate management
- ``pvxs.ossl.init``           - TLS initialization
- ``pvxs.ossl.io``             - TLS I/O
- ``pvxs.stapling``            - OCSP stapling

Connection Tracing
^^^^^^^^^^^^^^^^^^

Monitor connection state transitions:

1. Enable connection tracing:

   .. code-block:: sh

       export PVXS_LOG="pvxs.connection=DEBUG"

2. Trace output includes:

   - Connection establishment
   - State transitions
   - Certificate verification
   - Error conditions

.. _network_deployment:

Network Deployment
------------------

Deployment Patterns
^^^^^^^^^^^^^^^^^^^

1. Standard Network Deployment

   - Agents run on networked hosts with local storage
   - Certificates stored in local protected directories
   - Standard TLS configuration applies

2. Diskless Network Deployment

   - Agents run on hosts without local storage
   - Certificates stored on network-mounted storage
   - Special considerations for certificate protection

3. Hybrid Deployment

   - Mix of standard and diskless nodes
   - Common trust anchor required
   - Consistent :ref:`certificate_management` across node types

Certificate Storage
^^^^^^^^^^^^^^^^^^^

Standard Nodes:

- Store certificates in local protected directory
- Automatic reconfiguration on certificate updates

Diskless Nodes:

- Use network-mounted storage (NFS, SMB/CIFS, AFP)
- Protected certificate storage location
- Optional password protection via diskless server

Trust Establishment
^^^^^^^^^^^^^^^^^^^

1. Root Certificate Distribution:

   - Install during node boot process, or
   - Use publicly signed root certificates
   - Consistent across all deployment types

2. Certificate Authority:

   - :ref:`pvacms` serves as site CA
   - Common trust anchor for all nodes
   - Handles certificate lifecycle management

