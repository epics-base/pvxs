.. _authn_and_authz:

|security| AuthN & AuthZ
=====================================

:ref:`Authentication and Authorization<glossary_auth_vs_authz>` with Secure PVAccess

- **Authentication** (AuthN) determines and verifies the identity of a client or server.
- **Authorization** (AuthZ) defines and enforces access rights to PV resources.

Secure PVAccess enhances :ref:`epics_security` with fine-grained control based on:

- Authentication Mode
- Authentication Method
- Certifying Authority
- Protocol

.. _authentication_modes:

Authentication Modes
------------------------

- ``Mutual``: Both client and server are authenticated via certificates (spva: ``METHOD`` is ``x509``)
- ``Server-only``: Only server is authenticated via certificate (spva: ``METHOD`` is ``ca`` or ``anonymous``, but ``PROTOCOL`` is ``tls``)
- ``Un-authenticated``: Credentials supplied in ``AUTHZ`` message (legacy: ``METHOD`` is ``ca``)
- ``Unknown``: No credentials (legacy: ``METHOD`` is ``anonymous``)

.. _determining_identity:

Legacy Authentication Mode
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Methods:

- ``anonymous`` - ``Unknown``
- ``ca`` - ``Un-authenticated``

.. image:: pvaident.png
   :alt: Identity in PVAccess
   :align: center

1. Optional ``AUTHZ`` message from client:

.. code-block:: shell

    AUTHZ method: ca
    AUTHZ user: george
    AUTHZ host: McInPro.level-n.com

2. Server uses PeerInfo structure:

- :ref:`peer_info`

3. PeerInfo fields map to `asAddClient()` parameters ...
4. for authorization through the ``ACF`` definitions of ``UAG`` and ``ASG`` ...
5. to control access to PVs

Secure PVAccess Authentication Mode
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Methods:

- server: ``x509`` / client: ``x509`` - ``Mutual``
- server: ``x509`` - ``Server-Only``

.. image:: spvaident.png
   :alt: Identity in Secure PVAccess
   :align: center

1. Client Identity optionally established via X.509 certificate during TLS handshake:

.. code-block:: shell

    CN: greg
    O: SLAC.stanford.edu
    OU: SLAC National Accelerator Laboratory
    C: US

2. EPICS agent optionally verifies certificate via trust chain

3. PeerCredentials structure provides peer information:

- :ref:`peer_credentials`

4. Extended ``asAddClientIdentity()`` function provides

- :ref:`identity_structure`

5. Secure authorization control enhanced with:

- ``METHOD``
- ``AUTHORITY``
- ``PROTOCOL``

through the ACF definitions of ASGs ...

6. to control access to PVs


.. _site_authentication_methods:

Authentication Method
-----------------------

anonymous Method
^^^^^^^^^^^^^^^^^^

No credentials are supplied.

ca Method
^^^^^^^^^^

Unauthenticated credentials are supplied in ``AUTHZ`` message.

x509 Method
^^^^^^^^^^^^

A new Authentication Method is added with Secure PVAccess - ``x509``.
With ``x509`` EPICS clients provde authenticated credentials in the form of an X.509 certificate.

Optionally EPICS clients can use a variety of Site Authenticators that can create an X.509 certificate from a variety of sources including

- Kerberos
- LDAP
- Standard Authenticator (Just provide a username and optional organization)

The x509 authentication method integrates with Secure PVAccess via a PKCS#12 keychain file
using the certificates and keys that it contains.


Certifying Authority
--------------------

The Certifying Authority is the entity that vouches for the identity of the EPICS agent.

The identity of Secure PVAccess servers and clients are attested to by a Certifying Authority.
This is known as the Certificate Authority or Trust Anchor.

A client and server must agree on the Certifying Authority that vouches for the identity of their peer.
Certificates that are delivered by the PVACMS service are signed by a common Certificate Authority so
clients and servers implicitly agree.  If you provide your own certificates then you must share the trust anchor certificate
between all clients and servers that need to communicate.


Protocol
--------

The Protocol is the method used to transport the identity of an EPICS agent to its peer.

- ``TLS`` - Transport Layer Security (Secure PVAccess)
- ``TCP`` - Transmission Control Protocol (Legacy)

The TLS protocol is negotiated during the TLS handshake using the X.509 certificate provided by
the server and optionally by the client.

.. _site_authenticators:

Site Authenticators
--------------------

Authenticators are ways of generating the certificate and placing it in the PKCS#12 keychain file,
using credentials (tickets, tokens, or other identity-affirming methods) from existing authentication methods
that may be in use at a particular site.  The simplest is called "Standard Authenticator" (``std``) and it
allows a user to create an arbitrary x509 certificate that has to be ``APPROVED`` by a network administrator before
it is allowed on the network.

Tools that start with ``authn`` e.g. ``authnstd`` are the commandline interfaces to these Authenticators.

Reference Authenticators
^^^^^^^^^^^^^^^^^^^^^^^^^

.. _pvacms_type_0_auth_methods:

TYPE ``0`` - Basic Credentials
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Uses basic information:

  - CN: Common name

    - Commandline flag: ``-n`` ``--name``
    - Username

  - O: Organisation

    - Commandline flag: ``-o`` ``--organization``
    - Hostname
    - IP address

  - OU: Organisational Unit

    - Commandline flag: ``--ou``

  - C: Country

    - Commandline flag: ``-c`` ``--country``
    - Locale (not reliable)
    - Default = "US"

- No verification performed
- Certificates start in ``PENDING_APPROVAL`` state
- Requires administrator approval

.. _pvacms_type_1_auth_methods:

TYPE ``1`` - Independently Verifiable Tokens
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Tokens verified independently or via endpoint (e.g., JWT)
- Verification methods:

  - Token signature verification
  - Token payload validation
  - Verification endpoint calls

.. _pvacms_type_2_auth_methods:

TYPE ``2`` - Source Verifiable Tokens
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Requires programmatic API integration (e.g., Kerberos)
- Adds verifiable data to :ref:`certificate_creation_request_CCR` message
- :ref:`pvacms` uses method-specific libraries for verification


Common Environment Variables for all Authenticators
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Configuration options for Standard Authenticator**

+----------------------+------------------------------------+-----------------------------------------------------------------------+
| Name                 | Keys and Values                    | Description                                                           |
+======================+====================================+=======================================================================+
|| EPICS_PVA_AUTH_     || <number of minutes>               || Amount of minutes before the certificate expires.                    |
|| _CERT_VALIDITY_MINS || e.g. ``1y`` for 1 year            || e.g. 1d or 1y 2w 1d or 24h                                           |
||                     ||                                   || Where:                                                               |
||                     ||                                   ||   1y = 365 days                                                      |
||                     ||                                   ||   1M = 30 days                                                       |
||                     ||                                   ||   1w = 7 days                                                        |
+----------------------+------------------------------------+-----------------------------------------------------------------------+
|| EPICS_PVA_AUTH      || {name to use}                     || Name to use in new certificates                                      |
|| _NAME               || e.g. ``archiver``                 ||                                                                      |
+----------------------+  e.g. ``IOC1``                     ||                                                                      |
|| EPICS_PVAS_AUTH     || e.g. ``greg``                     ||                                                                      |
|| _NAME               ||                                   ||                                                                      |
+----------------------+------------------------------------+-----------------------------------------------------------------------+
|| EPICS_PVA_AUTH      || {organization to use}             || Organization to use in new certificates                              |
|| _ORGANIZATION       || e.g. ``site.epics.org``           ||                                                                      |
+----------------------+  e.g. ``SLAC.STANFORD.EDU``        ||                                                                      |
|| EPICS_PVAS_AUTH     || e.g. ``KLYS:LI01:101``            ||                                                                      |
|| _ORGANIZATION       || e.g. ``centos07``                 ||                                                                      |
+----------------------+------------------------------------+-----------------------------------------------------------------------+
|| EPICS_PVA_AUTH_     || {organization unit to use}        || Organization Unit to use in new certificates                         |
|| ORGANIZATIONAL_UNIT || e.g. ``data center``              ||                                                                      |
+----------------------+  e.g. ``ops``                      ||                                                                      |
|| EPICS_PVAS_AUTH_    || e.g. ``prod``                     ||                                                                      |
|| ORGANIZATIONAL_UNIT || e.g. ``remote``                   ||                                                                      |
+----------------------+------------------------------------+-----------------------------------------------------------------------+
|| EPICS_PVA_AUTH      || {country to use}                  || Country to use in new certificates.                                  |
|| _COUNTRY            || e.g. ``US``                       || Must be a two digit country code                                     |
+----------------------+  e.g. ``CA``                       ||                                                                      |
|| EPICS_PVAS_AUTH     ||                                   ||                                                                      |
|| _COUNTRY            ||                                   ||                                                                      |
+----------------------+------------------------------------+-----------------------------------------------------------------------+
|| EPICS_PVA_AUTH      || {issuer of cert. mgmt. service}   || The issuer ID to contact for any certificate operation.              |
|| _ISSUER             || e.g. ``f0a9e1b8``                 || Must be am 8 character SKID                                          |
+----------------------+                                    ||                                                                      |
|| EPICS_PVAS_AUTH     ||                                   || If there are PVACMS's from different certificate authorities         |
|| _ISSUER             ||                                   || on the network, this allows you to specify the one you want          |
+----------------------+------------------------------------+-----------------------------------------------------------------------+
|| EPICS_PVA_CERT      || {certificate mgnt. prefix}        || Specify the prefix for the PVACMS PV to contact for new certificates |
|| _PV_PREFIX          || e.g. ``SLAC_CERTS``               || default ``CERT``                                                     |
+----------------------+                                    ||                                                                      |
|| EPICS_PVAS_CERT     ||                                   ||                                                                      |
|| _PV_PREFIX          ||                                   ||                                                                      |
+----------------------+------------------------------------+-----------------------------------------------------------------------+

Included Reference Authenticators
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Though it is recommended that you create your own site-specific Authenticators PVXS provides four reference implementations:

- ``authnstd`` : Standard Authenticator - Uses explicitly specified and unverified credentials
- ``authnkrb`` : Kerberos Authenticator - Kerberos credentials verified by the KDC
- ``authnldap``: LDAP Authenticator     - Login to LDAP directory to establish identity

authstd Configuration and Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This Authenticator is used for explicitly specified and unverified credentials.
It can be used to create a certificate with a username and hostname.

- `CN` field in the certificate will be the logged in username

  - unless the ``-n`` ``--name`` commandline option is set
  - unless the ``EPICS_PVA_AUTH_NAME``, ``EPICS_PVAS_AUTH_NAME`` environment variable is set

- `O` field in the certificate will be the hostname or ip address

  - unless the ``-o`` ``--organization``  commandline option is set
  - unless the ``EPICS_PVA_AUTH_ORGANIZATION``, ``EPICS_PVAS_AUTH_ORGANIZATION`` environment variable is set

- `OU` field in the certificate will not be set

  - unless the ``--ou``  commandline option is set
  - unless the ``EPICS_PVA_AUTH_ORGANIZATIONAL_UNIT``, ``EPICS_PVAS_AUTH_ORGANIZATIONAL_UNIT`` environment variable is set

- `C` field in the certificate will be set to the local country code

  - unless the ``-c`` ``--country``  commandline option is set
  - unless the ``EPICS_PVA_AUTH_COUNTRY``, ``EPICS_PVAS_AUTH_COUNTRY`` environment variable is set

**usage**

Uses the standard ``EPICS_PVA_TLS_<name>`` environment variables to determine the keychain,
and password file locations.

.. code-block:: shell

    authnstd - Secure PVAccess Standard Authenticator

    Generates client, server, or ioc certificates based on the Standard Authenticator.
    Uses specified parameters to create certificates that require administrator APPROVAL before becoming VALID.

    usage:
      authnstd [options]                         Create certificate in PENDING_APPROVAL state
      authnstd (-h | --help)                     Show this help message and exit
      authnstd (-V | --version)                  Print version and exit

    options:
      (-u | --cert-usage) <usage>                Specify the certificate usage.  client|server|ioc.  Default `client`
      (-n | --name) <name>                       Specify common name of the certificate. Default <logged-in-username>
      (-o | --organization) <organization>       Specify organisation name for the certificate. Default <hostname>
            --ou <org-unit>                      Specify organisational unit for the certificate. Default <blank>
      (-c | --country) <country>                 Specify country for the certificate. Default locale setting if detectable otherwise `US`
      (-t | --time) <minutes>                    Duration of the certificate in minutes.  e.g. 30 or 1d or 1y3M2d4m
      (-D | --daemon)                            Start a daemon that re-requests a certificate on expiration`
            --cert-pv-prefix <cert_pv_prefix>     Specifies the pv prefix to use to contact PVACMS.  Default `CERT`
            --add-config-uri                      Add a config uri to the generated certificate
            --force                               Force overwrite if certificate exists
      (-a | --trust-anchor)                       Download Trust Anchor into keychain file.  Do not create a certificate
      (-s | --no-status)                          Request that status checking not be required for this certificate
      (-i | --issuer) <issuer_id>                 The issuer ID of the PVACMS service to contact.  If not specified (default) broadcast to any that are listening
      (-v | --verbose)                            Verbose mode
      (-d | --debug)                              Debug mode


**Examples**

.. code-block:: shell

    # create a client certificate for greg@slac.stanford.edu
    authnstd -u client -n greg -o slac.stanford.edu

.. code-block:: shell

    # create a server certificate for IOC1
    authnstd -u server -n IOC1 -o "KLI:LI01:10" --ou "FACET"

.. code-block:: shell

    # create a client certificate for current user with no status monitoring
    authnstd --no-status


.. code-block:: shell

    # create a ioc certificate for gateway1
    authnstd -u ioc -n gateway1 -o bridge.ornl.gov --ou "Networking"


.. code-block:: shell

    # Download the Trust Anchor into your keychain file for server-only authenticated connections
    authnstd --trust-anchor


**Setup of standard authenticator in Docker Container for testing**

In the source code under ``/examples/docker/spva_std`` you'll find a Dockerfile and supporting resources for creating an environment
that contains a working Secure PVAccess with the following characteristics:

- users (unix)

  - ``pvacms`` - service
  - ``admin`` - principal with password "secret" (includes a configured PVACMS administrator certificate)
  - ``softioc`` - service principal with password "secret"
  - ``client`` - principal with password "secret"

- services

  - PVACMS


authkrb Configuration and Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This Authenticator is a TYPE ``2`` Authenticator.
It can be used to create a certificate from a Kerberos ticket.

A user will need to have a Kerberos ticket to use this Authenticator typically
using the ``kinit`` command.

.. code-block:: shell

    kinit -l 24h greg@SLAC.STANFORD.EDU

- `CN` field in the certificate will be kerberos username
- `O` field in the certificate will be the kerberos realm
- `OU` field in the certificate will not be set
- `C` field in the certificate will be set to the local country code


**usage**

Uses the standard ``EPICS_PVA_TLS_<name>`` environment variables to determine the keychain,
and password file locations.

.. code-block::

    authnkrb - Secure PVAccess Kerberos Authenticator

    Generates client, server, or ioc certificates based on the kerberos Authenticator.
    Uses current kerberos ticket to create certificates with the same validity as the ticket.

    usage:
      authnkrb [options]                         Create certificate
      authnkrb (-h | --help)                     Show this help message and exit
      authnkrb (-V | --version)                  Print version and exit

    options:
      (-u | --cert-usage) <usage>                Specify the certificate usage.  client|server|ioc.  Default ``client``
            --krb-validator <service-name>       Specify kerberos validator name.  Default ``pvacms``
            --krb-realm <krb-realm>              Specify the kerberos realm.  If not specified we'll take it from the ticket
      (-D | --daemon)                            Start a daemon that re-requests a certificate on expiration`
            --cert-pv-prefix <cert_pv_prefix>    Specifies the pv prefix to use to contact PVACMS.  Default `CERT`
            --add-config-uri                     Add a config uri to the generated certificate
            --force                              Force overwrite if certificate exists
      (-s | --no-status)                         Request that status checking not be required for this certificate
      (-i | --issuer) <issuer_id>                The issuer ID of the PVACMS service to contact.  If not specified (default) broadcast to any that are listening
      (-v | --verbose)                           Verbose mode
      (-d | --debug)                             Debug mode

**Extra options that are available in PVACMS**

.. code-block:: shell

    usage:
      pvacms [kerberos options]                  Run PVACMS.  Interrupt to quit

    kerberos options
            --krb-keytab <keytab file>           kerberos keytab file for non-interactive login`
            --krb-realm <realm>                  kerberos realm.  Default ``EPICS.ORG``
            --krb-validator <validator-service>  pvacms kerberos service name.  Default ``pvacms``

**Environment Variables for PVACMS AuthnKRB Verifier**

The environment variables and parameters in the following table configure the Kerberos
Credentials Verifier for :ref:`pvacms` at runtime.

+----------------------+---------------------+--------------------------+----------------------+--------------------------------------+-----------------------------------------------------------------------+
| Env. *authnkrb*      | Env. *pvacms*       | Params. *authkrb*        | Params. *pvacms*     | Keys and Values                      | Description                                                           |
+======================+=====================+==========================+======================+======================================+=======================================================================+
||                     || KRB5_KTNAME        ||                         || ``--krb-keytab``    || {string location of keytab file}    || This is the keytab file shared with :ref:`pvacms` by the KDC so      |
||                     ||                    ||                         ||                     ||                                     || that it can verify kerberos tickets                                  |
||                     +---------------------+|                         ||                     ||                                     ||                                                                      |
||                     || KRB5_CLIENT_KTNAME ||                         ||                     ||                                     ||                                                                      |
||                     ||                    ||                         ||                     ||                                     ||                                                                      |
+----------------------+---------------------+--------------------------+----------------------+--------------------------------------+-----------------------------------------------------------------------+
|| EPICS_AUTH_KRB_VALIDATOR_SERVICE          || ``--krb-validator``                            || {this is validator service name}    || The name of the service user created in the KDC that the pvacms      |
||                                           ||                                                || e.g. ``pvacms``                     || service will log in as.  ``/cluster@{realm}`` will be added          |
+--------------------------------------------+-------------------------------------------------+--------------------------------------+-----------------------------------------------------------------------+
|| EPICS_AUTH_KRB_REALM                      || ``--krb-realm``                                || e.g. ``EPICS.ORG``                  || Kerberos REALM to authenticate against                               |
+--------------------------------------------+-------------------------------------------------+--------------------------------------+-----------------------------------------------------------------------+

**Setup of Kerberos in Docker Container for testing**

In the source code under ``/examples/docker/spva_krb`` you'll find a Dockerfile and supporting resources for creating an environment
that contains a working kerberos KDC with the following characteristics:

- users (both unix and kerberos principals)

  - ``pvacms`` - service principal with private keytab file for authentication in ``~/.config/pva/1.3/pvacms.keytab``
  - ``admin`` - principal with password "secret" (includes a configured PVACMS administrator certificate)
  - ``softioc`` - service principal with password "secret"
  - ``client`` - principal with password "secret"

- services

  - KDC
  - kadmin Daemon
  - PVACMS


authldap Configuration and Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This Authenticator is a TYPE ``2`` Authenticator.
It can be used to create a certificate by logging in to the LDAP directory service.

A user will be prompted to log in to the LDAP directory service to verify their identity.

- `CN` field in the certificate will be LDAP username
- `O` field in the certificate will be the LDAP domain parts concatenated with "."
- `OU` field in the certificate will not be set
- `C` field in the certificate will be set to the local country code


**usage**

Uses the standard ``EPICS_PVA_TLS_<name>`` environment variables to determine the keychain,
and password file locations.

.. code-block:: shell

    authnldap - Secure PVAccess LDAP Authenticator

    Generates client, server, or ioc certificates based on the LDAP credentials.

    usage:
      authnldap [options]                        Create certificate in PENDING_APPROVAL state
      authnldap (-h | --help)                    Show this help message and exit
      authnldap (-V | --version)                 Print version and exit

    options:
      (-u | --cert-usage) <usage>                Specify the certificate usage.  client|server|ioc.  Default `client`
      (-n | --name) <name>                       Specify LDAP username for common name in the certificate.
                                                 e.g. name ==> LDAP: uid=name, ou=People ==> Cert: CN=name
                                                 Default <logged-in-username>
      (-o | --organization) <organization>       Specify LDAP org for organization in the certificate.
                                                 e.g. epics.org ==> LDAP: dc=epics, dc=org ==> Cert: O=epics.org
                                                 Default <hostname>
      (-p | --password) <name>                   Specify LDAP password. If not specified will prompt for password
            --ldap-host <hostname>               LDAP server host
            --ldap-port <port>                   LDAP serever port
      (-D | --daemon)                            Start a daemon that re-requests a certificate on expiration`
            --cert-pv-prefix <cert_pv_prefix>    Specifies the pv prefix to use to contact PVACMS.  Default `CERT`
            --add-config-uri                     Add a config uri to the generated certificate
            --force                              Force overwrite if certificate exists
      (-s | --no-status)                         Request that status checking not be required for this certificate
      (-i | --issuer) <issuer_id>                The issuer ID of the PVACMS service to contact.  If not specified (default) broadcast to any that are listening
      (-v | --verbose)                           Verbose mode
      (-d | --debug)                             Debug mode


**Extra options that are available in PVACMS**

.. code-block:: shell

    usage:
      pvacms [ldap options]                      Run PVACMS.  Interrupt to quit

    ldap options
            --ldap-host <host>                   LDAP Host.  Default localhost
            --ldap-port <port>                   LDAP port.  Default 389


**Environment Variables for authnldap and PVACMS AuthnLDAP Verifier**

The environment variables and parameters in the following table configure the authnldap client and
LDAP Credentials Verifier for :ref:`pvacms` at runtime.

+--------------------+--------------------------+--------------------------+--------------------------+---------------------------------------+------------------------------------------------------------+
| Env. *authnldap*   | Env. *pvacms*            | Params. *authldap*       | Params. *pvacms*         | Keys and Values                       | Description                                                |
+====================+==========================+==========================+==========================+=======================================+============================================================+
|| EPICS_AUTH_LDAP   ||                         ||                         ||                         || {location of password file}          || file containing password for the given LDAP user account  |
|| _ACCOUNT_PWD_FILE ||                         ||                         ||                         || e.g. ``~/.config/ldap.pass/``        ||                                                           |
+--------------------+--------------------------+--------------------------+--------------------------+---------------------------------------+------------------------------------------------------------+
||                   ||                         || ``-p``                  ||                         || {LDAP account password}              || password for the given LDAP user account                  |
||                   ||                         || ``--password``          ||                         || e.g. ``secret``                      ||                                                           |
+--------------------+--------------------------+--------------------------+--------------------------+---------------------------------------+------------------------------------------------------------+
|| EPICS_AUTH_LDAP_HOST                         ||                                                    || {hostname of LDAP server}            || Trusted hostname of the LDAP server                       |
||                                              || ``--ldap-host``                                    || e.g. ``ldap.stanford.edu``           ||                                                           |
+-----------------------------------------------+-----------------------------------------------------+---------------------------------------+------------------------------------------------------------+
|| EPICS_AUTH_LDAP_PORT                         ||                                                    || <port_number>                        || LDAP server port number. Default is 389                   |
||                                              || ``--ldap-port``                                    || e.g. ``389``                         ||                                                           |
+-----------------------------------------------+-----------------------------------------------------+---------------------------------------+------------------------------------------------------------+

**Setup of LDAP in Docker Container for testing**

In the source code under ``/examples/docker/spva_ldap`` you'll find a Dockerfile and supporting resources for creating an environment
that contains a working LDAP with the following characteristics:

- users (both unix and LDAP users)

  - ``pvacms`` - service with verifier for LDAP service
  - ``admin`` - principal with password "secret" (includes a configured PVACMS administrator certificate)
  - ``softioc`` - service principal with password "secret"
  - ``client`` - principal with password "secret"

- services

  - LDAP service + example schemas
  - PVACMS

.. _epics_security:

Long Running Certificates
--------------------------

In Experimental Physics and Industrial Control Systems, maintaining uninterrupted connections is critical. Even a microsecond break can trigger fail-safety mechanisms that might disrupt experiments.

With TLS 1.3 (implemented in OpenSSL), renegotiation has been completely removed from the protocol due to serious security vulnerabilities. Previous versions of TLS allowed session
renegotiation, which permitted changing security parameters (including certificates) without closing the connection. However, this feature was exploited in
several attacks, including the "Triple Handshake Attack" and "Secure Renegotiation" vulnerabilities.

This means that once a TLS connection has been established with an IOC over Secure PVAccess, we cannot change the certificate without breaking and re-establishing the connection. Our solution to this problem involves:

- Creating very long running certificates (decades)
- Allowing them to be `REVOKED` by administrators when necessary
- Implementing a kind of "soft-expiration" tied to authenticator configuration
- Providing the ability to renew certificates without breaking existing connections

Specifying long running certificates
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Common to all Authenticators - commandline parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use the `-t,--time` flag to specify a duration for the certificate using these components:

- `y` - Years (e.g., `2y` for two years)
- `M` - Months (e.g., `6M` for six months)
- `w` - Weeks (e.g., `1w` for one week)
- `d` - Days (e.g., `15d` for 15 days)
- `h` - Hours (e.g., `12h` for 12 hours)
- `m` - Minutes (e.g., `30m` for 30 minutes, or simply `30`)
- `s` - Seconds (e.g., `45s` for 45 seconds)

Examples:

- `1y and 6M` - one year and six months
- `2y3M15d` - two years, three months, and 15 days

The system uses natural time understanding, accounting for daylight savings, leap years, etc. For example, if you specify 1
year, the certificate will expire on the same calendar day next year, regardless of leap years.

Common to all Authenticators - environment variables
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

`EPICS_AUTH_CERT_VALIDITY_MINS` - sets a global duration for any Authenticator using the same format as the commandline parameter.

PVACMS Defaults - Parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PVACMS defaults to 6 months for certificate duration unless overridden by:

- `--cert_validity <duration>` - default duration for all certificates
- `--cert_validity-client <duration>` - default for client certificates
- `--cert_validity-server <duration>` - default for server certificates
- `--cert_validity-ioc <duration>` - default for IOC certificates
- `--disallow-custom-durations` - prevents clients from specifying durations for any certificates
- `--disallow-custom-durations-client` - restricts custom durations for client certificates
- `--disallow-custom-durations-server` - restricts custom durations for server certificates
- `--disallow-custom-durations-ioc` - restricts custom durations for IOC certificates

PVACMS Defaults - Environment Variables
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Values can also be set using environment variables:

- `EPICS_PVACMS_CERT_VALIDITY` - default duration for all certificates
- `EPICS_PVACMS_CERT_VALIDITY_CLIENT` - default for client certificates
- `EPICS_PVACMS_CERT_VALIDITY_SERVER` - default for server certificates
- `EPICS_PVACMS_CERT_VALIDITY_IOC` - default for IOC certificates
- `EPICS_PVACMS_DISALLOW_CUSTOM_DURATION` - YES/NO to prevent custom durations for any certificates
- `EPICS_PVACMS_DISALLOW_CLIENT_CUSTOM_DURATION` - YES/NO for client certificates
- `EPICS_PVACMS_DISALLOW_SERVER_CUSTOM_DURATION` - YES/NO for server certificates
- `EPICS_PVACMS_DISALLOW_IOC_CUSTOM_DURATION` - YES/NO for IOC certificates

The Authenticator Controls the Certificate Renewal Date
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The actual time before a certificate needs renewal is determined by the Authenticator (and by extension, the network administrators controlling the authentication methods).

This is known as the **Authenticated Expiration Date**:

- **Standard Authenticator**: Default is 6 months with no upper limit (subject to admin approval)
- **Kerberos**: Limited by service ticket lifetime (typically 1 day)
- **LDAP**: Limited by server default (typically 1 day)

Mapping requested duration to certificate expiration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Two critical dates govern certificate lifecycle:

- **Requested Duration → Certificate Expiration Date**: When the certificate becomes invalid
- **Authenticated Expiration → Certificate Renew-By Date**: When the certificate should be renewed

The PVACMS will change a certificate's status from `VALID` to `PENDING_RENEWAL` when it reaches the
renew-by date. Certificates in this state can't establish new connections, but existing connections
can continue until the certificate is renewed.

How do we enforce Renew By dates
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

All certificates with renew-by dates must have certificate status monitoring enabled. If status
monitoring is disabled for the PVACMS server, generating certificates with renew-by dates will be forbidden.

Secure PVAccess monitors certificate status and reacts to state changes:

- `VALID`: Certificate is operational
- `PENDING_RENEWAL`: Certificate needs renewal but isn't revoked
- `REVOKED` / `EXPIRED`: Certificate is permanently invalidated

When a certificate transitions to `PENDING_RENEWAL`:

- IOCs/servers will only accept TCP connections (no TLS)
- Clients won't search for TLS protocol services
- Monitoring consoles will pause until certificate renewal

Renewing certificates
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To renew a certificate, simply perform the same action used to get the original certificate. PVACMS will:

1. Recognize that the certificate is for the same subject
2. Automatically renew it
3. Keep both the new certificate and the original one active

This means:

- Existing connections using the long-running certificate continue without interruption
- New connections will use the newer certificate

You can renew certificates multiple times, and the system will always keep the last certificate obtained as well as the original, renewed one.

Best practice: Renew before the certificate enters `PENDING_RENEWAL` state to maintain uninterrupted service. If renewal occurs after the renew-by date, the certificate will automatically transition back to `VALID` upon successful renewal.


Authorization
-------------

Secure PVAccess' authentication mechanisms integrate with EPICS Security's authorization system
to provide fine-grained access control options. These improvements enable robust
security while maintaining backward compatibility with legacy systems.

- **Certificate-based Identity**:

  - Authentication using X.509 certificates provides stronger identity verification than legacy username/host identification.
- **Expanded Access Control Rules**:

  - New rule elements for ``METHOD``, ``AUTHORITY``, and ``PROTOCOL`` enable precise permission definitions.
- **Enhanced Permission Types**:

  - Addition of ``RPC`` permission supports fine-grained control over remote procedure calls.
- **Protocol-aware Security**:

  - Permissions can be granted based on encrypted (``TLS``) or unencrypted (``TCP``) connections.
- **API Extensions**:

  - New APIs for client identity management and auditing security events with enhanced identity data.

New Security Features
^^^^^^^^^^^^^^^^^^^^^^

1. **Identity Verification**:

   - Certificates provide cryptographically secure identity verification
2. **Fine-grained Control**:

   - Combine authentcation ``METHOD``, certifying ``AUTHORITY``, and transport ``PROTOCOL`` for precise access control
3. **Connection Security**:

   - Control access based on encrypted (``TLS``) vs. unencrypted (``TCP``) connections
4. **Defense in Depth**:

   - Layer multiple security rules for comprehensive protection
5. **Backward Compatibility**:

   - Support legacy clients while providing enhanced security for modern clients
6. **Centralized Management**:

   - Revocation of permisions now managed through PVACMS with immediate effect
7. **Scalable Architecture**:

   - Support for multiple authentication methods via Authenticators

By leveraging these enhanced security features, Secure PVAccess provides a robust
security model that can meet the requirements of modern control systems while
maintaining compatibility with existing EPICS deployments.


EPICS Security Access Control File (ACF) Extensions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Secure PVAccess extends the Access Control File (ACF) syntax with new rule predicates:

METHOD
~~~~~~~

Defines access permissions based on authentication method:

- ``x509``: Certificate-based authentication
- ``ca``: Legacy PVAccess AUTHZ with user-specified account
- ``anonymous``: Access without specified name

Can be provided as quoted or unquoted strings.

Example:

.. code-block:: text

   RULE(1,READ) {
       METHOD("x509")
   }

The above rule will match any client that presents an x509 certificate to assert its identity.

AUTHORITY
~~~~~~~~~

1. A new top level item in ACF files AUTHORITY declares the heirarchy of Certificate Authorities that can be
referenced, going all the way back to the Root Certificate Authority.

  - Specifies Certifying Authority:

    - Uses name from ``CN`` field of certificate authority certificate's subject
    - The whole chain must be specified back to the root certificate
    - Not all nodes need to be named especially if they are intermediate certificates

Example:

.. code-block:: text

    AUTHORITY(AUTH_EPICS_ROOT, "EPICS Root Certificate Authority") {
        AUTHORITY("SNS Intermediate CA") {
            AUTHORITY(AUTH_SNS_CTRL, "SNS Control Systems CA")
            AUTHORITY(AUTH_BEAMLINE, "SNS Beamline Operations CA")
       }
    }

    AUTHORITY(AUTH_EPICS_IT_ROOT, "EPICS IT Root Certificate Authority") {
    	AUTHORITY(AUTH_EPICS_USERS, "EPICS Users Certificate Authority")
    }

2. A new AUTHORITY predicate in ASG RULES references the top level AUTHORITY to constrain rules

  - References the Top Level Authority definition:

    - Only applicable for X.509 certificate authentication
    - Multiple authorities can be specified and any one of them will be accepted

Example:

.. code-block:: text

   RULE(1,READ) {
       AUTHORITY(AUTH_EPICS_USERS, AUTH_EPICS_ROOT)
   }

The above rule will match any client that presents an x509 certificate
that is signed by the EPICS Root Certificate Authority or the
EPICS Users Certificate Authority.

.. code-block:: text

   RULE(1,WRITE) {
       AUTHORITY(AUTH_SNS_CTRL)
   }

The above rule will match any client that presents an x509 certificate
that is signed by the SNS Control Systems CA.

PROTOCOL
~~~~~~~~

Specifies the connection protocol requirement:

- ``TCP``: Default unencrypted connection
- ``TLS``: Encrypted connection

Can be provided as quoted or unquoted strings.  Upper or lower case is accepted.

Example:

.. code-block:: text

   RULE(1,READ) {
       PROTOCOL("TLS")
   }

The above rule will match any client that connects using an encrypted (TLS) connection.
This is always the case for when clients provide an x509 certificate to assert their identity,
however it can also be the case for server-only authenticated connections.  In the later case
the connection METHOD could be ``ca`` or ``anonymous`` but the PROTOCOL will be ``TLS``.

Note that you can also specify ``TCP`` to define a rule that matches only unencrypted (TCP) connections.

Example:

.. code-block:: text

   RULE(1,NONE) {
       PROTOCOL("TCP")
   }

The above rule will explicitly prohibit any client that connects using an unencrypted (TCP) connection.

RPC Permission
~~~~~~~~~~~~~~~

New rule permission for RPC message access control:

- Supplements existing ``NONE``, ``READ`` (`GET`), and ``WRITE`` (`PUT`)
- Controls access to `RPC` PVAccess messages

Note: The syntax has been implemented for ACF files but control of RPC access is not yet available.

Example:

.. code-block:: text

   RULE(1,RPC) {
       UAG(admins)
   }

Full ACF Examples
~~~~~~~~~~~~~~~~~

These examples demonstrate combining security features for granular access control:

*Authorization based on PROTOCOL, METHOD, and AUTHORITY*

.. code-block:: text

    UAG(operators) {greg, karen, ralph}
    UAG(engineers) {kay, george, michael}
    UAG(admins) {aqeel, earnesto, pierrick}

    AUTHORITY(AUTH_EPICS_ROOT, "EPICS Root Certificate Authority") {
        AUTHORITY("Intermediate CA") {
            AUTHORITY(AUTH_LBNL_CTRL, "LBNL Certificate Authority")
        }
        AUTHORITY(AUTH_SLAC_ROOT, "SLAC Certificate Authority") {
            AUTHORITY(AUTH_EPICS_USERS, "EPICS Users Certificate Authority")
        }
    }


    ASG(DEFAULT) {
    # Default - No access
       RULE(0,NONE)

    # Read-only access for operators, requiring TLS
       RULE(1,READ) {
           UAG(operators,engineers,admins)
           PROTOCOL(tls)
       }

    # Write access for engineers from SLAC or LBNL using x509 auth
       RULE(2,WRITE) {
           UAG(engineers,admins)
           METHOD(x509)
           AUTHORITY(AUTH_LBNL_CTRL, AUTH_SLAC_ROOT)
       }

    # RPC access for admins using specific Cert Auth and TLS
       RULE(3,RPC) {
           UAG(admins)
           METHOD("x509")
           AUTHORITY(AUTH_EPICS_ROOT)
       }
    }

*Legacy compatible with Enhanced Security*

.. code-block:: text

    AUTHORITY(AUTH_EPICS_ROOT, "EPICS Root Certificate Authority")

    # Support both legacy and SPVA clients
    ASG(backward_compatible) {
       RULE(0,NONE)
       # Legacy access - read only
       RULE(1,READ) {
           METHOD("ca", "anonymous")
           PROTOCOL(tcp)
       }
       # Enhanced access - write with secure authentication
       RULE(2,WRITE) {
           UAG(operators)
           METHOD("x509")
           AUTHORITY(AUTH_EPICS_ROOT)
           PROTOCOL("tls")
       }
    }

Authenticator Development
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To implement a new Authenticator requires the following steps:

1. Source Code
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create under ``/certs/authn/<name>``:

- ``authn<name>main.cpp``

  - Main runner (copy from template)
- ``authn<name>.cpp``

  - Main implementation subclassing ``Authn``,
  - includes registration and PVACMS extensions & verifier
- ``authn<name>.h``

  - Header file
- ``config<name>.cpp``

  - Configuration interface subclassing ``AuthnConfig``
- ``config<name>.h``

  - Header file
- ``Makefile``

  - Build configuration
- ``README.md``

  - Documentation

2. Build flag to enable code to be compiled in
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- choose a make flag name of the form ``PVXS_ENABLE_<NAME>_AUTH`` where ``NAME``
  is a three or four letter acronynm. e.g. ``KRB``
- update ``/certs/authn/Makefile`` to add a line at the end similar to the following:

.. code-block:: make

    #--------------------------------------------
    #  ADD AUTHENTICATOR PLUGINS AFTER THIS LINE

    ifeq ($(PVXS_ENABLE_KRB_AUTH),YES)
    include $(AUTHN)/krb/Makefile
    endif

- Sites compiling PVXS will set these macros in their private ``CONFIG_SITE.local`` stored one level above
  the root of the source tree.  e.g.

.. code-block:: make

    PVXS_ENABLE_KRB_AUTH = YES
    PVXS_ENABLE_LDAP_AUTH = YES

- To build PVACMS add the following, by default it will not be built

.. code-block:: make

    PVXS_ENABLE_PVACMS = YES


3. Extra options for PVACMS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you need to add some options to the commandline for PVACMS for your
Authenticator just override these methods in the base ``Auth`` class.  e.g. for LDAP
below:

.. code-block:: c++

    class AuthNLdap final : public Auth {
      public:
        // Copy config settings into the Authenticator
        void configure(const client::Config &config) override {
            auto &config_ldap = dynamic_cast<const ConfigLdap &>(config);
            ldap_server = config_ldap.ldap_host;
            ldap_port = config_ldap.ldap_port;
        };

        // Define placeholder text e.g. `command [placeholder] [options] positional parameters`
        std::string getOptionsPlaceholderText() override { return " [ldap options]"; }

        // Define the help text for the options
        std::string getOptionsHelpText() override {
            return "\n"
                   "ldap options\n"
                   "        --ldap-host <host>                   LDAP Host.  Default localhost\n"
                   "        --ldap-port <port>                   LDAP port.  Default 389\n";
        }

        // Add options to given commandline parser
        void addOptions(CLI::App &app, std::map<const std::string, std::unique_ptr<client::Config>> &authn_config_map) override {
            auto &config = authn_config_map.at(PVXS_LDAP_AUTH_TYPE);
            auto config_ldap = dynamic_cast<const ConfigLdap &>(*config);
            app.add_option("--ldap-host", config_ldap.ldap_host, "Specify LDAP hostname or IP address");
            app.add_option("--ldap-port", config_ldap.ldap_port, "Specify LDAP port number");
        }
    };


4. Extra environment variables for PVACMS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you need to add some environment variables for PVACMS for your Authenticator
just override these methods in the base ``Auth`` and ``ConfigAuthN`` classes.
e.g. for Kerberos shown below.

.. code-block:: c++

    class AuthNKrb final : public Auth {
      public:
        // Copy config settings into the Authenticator
        void configure(const client::Config &config) override {
            auto &config_krb = dynamic_cast<const ConfigKrb &>(config);
            krb_validator_service_name = SB() << config_krb.krb_validator_service << PVXS_KRB_DEFAULT_VALIDATOR_CLUSTER_PART << config_krb.krb_realm;
            krb_realm = config_krb.krb_realm;
            krb_keytab_file = config_krb.krb_keytab;
        }

        // Update the definitions map for display of effective config
        void updateDefs(client::Config::defs_t &defs) const override {
            defs["KRB5_KTNAME"] = krb_keytab_file;
            defs["KRB5_CLIENT_KTNAME"] = krb_keytab_file;
            defs["EPICS_AUTH_KRB_VALIDATOR_SERVICE"] = krb_validator_service_name;
            defs["EPICS_AUTH_KRB_REALM"] = krb_realm;
        }

        // Construct a new AuthNKrb, configured from the environment
        void fromEnv(std::unique_ptr<client::Config> &config) override { config.reset(new ConfigKrb(ConfigKrb::fromEnv())); }
    };

    class ConfigKrb final : public ConfigAuthN {
      public:
        ConfigKrb& applyEnv() {
            Config::applyEnv(true, CLIENT);
            return *this;
        }

        // Make a new config containing the base classes environment settings plus any
        // environment variables for this Authenticator
        static ConfigKrb fromEnv() {
            auto config = ConfigKrb{}.applyEnv();
            const auto defs = std::map<std::string, std::string>();
            config.fromAuthEnv(defs);
            config.fromKrbEnv(defs);
            return config;
        }

        void ConfigKrb::fromKrbEnv(const std::map<std::string, std::string>& defs) {
            PickOne pickone{defs, true};

            // KRB5_KTNAME
            // This is the environment variable defined by krb5
            if (pickone({"KRB5_KTNAME", "KRB5_CLIENT_KTNAME"})) {
                krb_keytab = pickone.val;
            }

            // EPICS_AUTH_KRB_REALM
            if (pickone({"EPICS_AUTH_KRB_VALIDATOR_SERVICE"})) {
                krb_validator_service = pickone.val;
            }

            // EPICS_AUTH_KRB_REALM
            if (pickone({"EPICS_AUTH_KRB_REALM"})) {
                krb_realm = pickone.val;
            }
        }
    };


New APIs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Secure PVAccess introduces new APIs for programatically managing security with authenticated identities:

.. _peer_info:

Legacy ``PeerInfo`` Structure
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c++

    struct PeerInfo {
        std::string peer;      // network address
        std::string transport; // protocol (e.g., "pva")
        std::string authority; // auth mechanism
        std::string realm;     // authority scope
        std::string account;   // user name
    }


.. _peer_credentials:

New ``PeerCredentials`` Structure
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c++

    struct PeerCredentials {
        std::string peer;      // network address
        std::string iface;     // network interface
        std::string method;    // "anonymous", "ca", or "x509"
        std::string authority; // Certificate Authority common name for x509 if mode is `Mutual` or blank
        std::string account;   // User account if mode is `Mutual` or blank
        bool isTLS;            // Secure transport status.  True is mode is `Mutual` or `Server-Only`
    };


Enhanced Client Management
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c

   long epicsStdCall asAddClientIdentity(
        ASCLIENTPVT *pasClientPvt, ASMEMBERPVT asMemberPvt, int asl,
        ASIDENTITY identity);

   long epicsStdCall asChangeClientIdentity(
        ASCLIENTPVT asClientPvt, int asl,
        ASIDENTITY identity);

Enhanced Auditing
~~~~~~~~~~~~~~~~~

.. code-block:: c

   void * epicsStdCall asTrapWriteBeforeWithIdentityData(
        ASIDENTITY identity,
        dbChannel *addr, int dbrType, int no_elements, void *data);

.. _identity_structure:

Identity Structure for APIs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This unified structure replaces separate user/host parameters:

.. code-block:: c

   typedef struct asIdentity {
       const char *user;         // User identifier (CN from certificate)
       char *host;               // Host identifier (O from certificate)
       const char *method;       // Authentication method ("ca", "x509", "anonymous")
       const char *authority;    // Certificate authority
       enum AsProtocol protocol; // Connection protocol (TCP/TLS)
   } ASIDENTITY;

Protocol Enumeration
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c

   enum AsProtocol {
       AS_PROTOCOL_TCP = 0,     // Unencrypted connection
       AS_PROTOCOL_TLS = 1      // Encrypted connection
   };

