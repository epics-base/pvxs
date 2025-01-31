.. _authn_and_authz:

SPVA AuthN and AuthZ
=====================

`AutheNtication` and `AuthoriZation` with Secure PVAccess.

*Authentication* determines the identity of a client or server. *Authorization* determines access rights to PV resources.
SPVA enhances :ref:`epics_security` with fine-grained control based on:

- *Authentication Mode* - choose between `server-only`, `mutual`, or `none`
- *Authentication Method* - either legacy (`ca`), spva (`x509`), or none (`anonymous`)
- *Certificate Authority* - Only allow authorised access matching `Common Name` of Certificate Authority
- *Transport Type* - for unauthenticated clients provide access based on transport - legacy (not `isTLS`), or tls encapsulated (`isTLS`)
- *Encapsulation Mode* - packets are encrypted (`tls`),  or unencrypted (`tcp`)


.. _authentication_modes:

Authentication Modes
--------------------

- `Mutual`: Both client and server are authenticated via certificates (spva: Method is `x509`)
- `Server-only`: Only server is authenticated via certificate (hybrid: Method is `ca` or `anonymous`, but `isTLS` flag is true)
- `Un-authenticated`: Credentials supplied in AUTHZ message (legacy: Method is `ca`)
- `Unknown`: No credentials (legacy: Method is `anonymous`)


.. _determining_identity:

Legacy Authentication Mode
^^^^^^^^^^^^^^^^^^^

- `Un-authenticated`
- `Unknown`


.. image:: pvaident.png
   :alt: Identity in PVAccess
   :align: center

1. Optional AUTHZ message from client:

    .. code-block:: sh

        AUTHZ method: ca
        AUTHZ user: george
        AUTHZ host: McInPro.level-n.com

2. Server uses PeerInfo structure:

    .. code-block:: c++

        struct PeerInfo {
            std::string peer;      // network address
            std::string transport; // protocol (e.g., "pva")
            std::string authority; // auth mechanism
            std::string realm;     // authority scope
            std::string account;   // user name
        }

3. PeerInfo fields map to `asAddClient()` parameters ...
4. for authorization through the ACF definitions of UAGs and ASGs ...
5. to control access to PVs

Secure PVAccess Authentication Mode
^^^^^^^^^^^^^^^^^^^

- `Mutual`
- `Server-only`

.. image:: spvaident.png
   :alt: Identity in Secure PVAccess
   :align: center

1. Client Identity optionally established via X.509 certificate during TLS handshake:

    .. code-block:: sh

        CN: greg
        O: SLAC.stanford.edu
        OU: SLAC National Accelerator Laboratory
        C: US

2. EPICS agent optionally verifies certificate via trust chain

3. PeerCredentials structure provides peer information:

    .. code-block:: c++

        struct PeerCredentials {
            std::string peer;      // network address
            std::string iface;     // network interface
            std::string method;    // "anonymous", "ca", or "x509"
            std::string authority; // CA common name for x509 if mode is `Mutual` or blank
            std::string account;   // User account if mode is `Mutual` or blank
            bool isTLS;            // Secure transport status.  True is mode is `Mutual` or `Server-Only`
        };

4. Extended ``asAddClientX()`` function provides ...
5. authorization control (enhanced with `isTls`, `METHOD`, and `AUTHORITY`) through the ACF definitions of UAGs and ASGs ...
6. to control access to PVs (enhanced with addition of `RPC`)


.. _site_authentication_methods:

Authentication Methods
--------------------

A new authentication method is added with SPVA - `x509`.  This supercedes the legacy `ca`, and
`anonymous` authentication methods.  With `x509` EPICS clients can use a variety of Site Authentication Methods that
all integrate with Secure PVAccess via a PKCS#12 keychain file ( :ref:`glossary_pkcs12` ) and the certificate and keys that it contains.

**Site Authentication Methods**:

Site Authentication Methods are ways of generating the PKCS#12 keychain file by
using credentials (tickets, tokens, or other identity-affirming methods) from existing authentication methods
that may be in use in a particular installation site.  The simplest is called "Standard" (`std`) and it
allows a user to create an arbitrary x509 certificate that has to be approved by a network administrator before
it is allowed on the network.

Tools that start with `authn` e.g. `authnstd` are the commandline interfaces to these site authentication methods.

Implementing a new site authentication method requires:

Site Authentication Method Implementation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Create under ``/certs/authn/<name>``:

- `authnmain.cpp` - Main runner (copy from template)
- `authn<name>.cpp` - Main implementation subclassing ``Authn``
- `authn<name>.h` - Header file
- `config<name>.cpp` - Configuration interface subclassing ``AuthnConfig``
- `config<name>.h` - Header file
- `Makefile` - Build configuration
- `README.md` - Documentation

CCR Message Verifier
^^^^^^^^^^^^^^^^^^^^

Create under `/certs/authn/<name>`:

- `<name>verifier.cpp` - Verifier implementation for :ref:`pvacms`
- `<name>verifier.h` - Header file with required macros/constants
- `<name>VERIFIER_RULES` - Makefile rules for :ref:`pvacms` integration
- `<name>VERIFIER_CONFIG` - Makefile configuration for :ref:`pvacms`


Site Authentication Method Types
^^^^^^^^^^^^^^^^^^^^^^^^^

.. _pvacms_type_0_auth_methods:

TYPE ``0`` - Basic Credentials
~~~~~~~~~~~~~~~~~~~~~~~

- Uses basic information:

  - Username
  - Hostname
  - Process name
  - Device name
  - IP address
  - Commandline Parameters

- No verification performed
- Certificates start in ``PENDING_APPROVAL`` state
- Requires administrator approval

.. _pvacms_type_1_auth_methods:

TYPE ``1`` - Independently Verifiable Tokens
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Tokens verified independently or via endpoint (e.g., JWT)
- Verification methods:

  - Token signature verification
  - Token payload validation
  - Verification endpoint calls

.. _pvacms_type_2_auth_methods:

TYPE ``2`` - Source Verifiable Tokens
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Requires programmatic API integration (e.g., Kerberos)
- Adds verifiable data to :ref:`certificate_creation_request_CCR` message
- :ref:`pvacms` uses method-specific libraries for verification


Included Reference Site Authentication Methods
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Though it is recommended that you create your own site-specific authentication methods PVXS provides four reference implementations:

- ``authnstd`` : Standard - Basic credentials
- ``authnkrb`` : Kerberos - Kerberos credentials
- ``authnldap``: LDAP     - Kerberos credentials verified in LDAP directory
- ``authnjwt`` : JWT      - JWT tokens

As a norm you should generate certificates in the ``PENDING_APPROVAL`` state unless the authentication mechanism includes
a verifier.


authstd Configuration and Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This authentication method is used for basic credentials.
It can be used to create a certificate with a username and hostname.

- `CN` field in the certificate will be the logged in username

  - unless the `-N` commandline option is set
  - unless the `EPICS_PVA_AUTH_STD_NAME`, `EPICS_PVAS_AUTH_STD_NAME` environment variable is set

- `O` field in the certificate will be the hostname

  - unless the `-O`  commandline option is set
  - unless the `EPICS_PVA_AUTH_STD_ORG`, `EPICS_PVAS_AUTH_STD_ORG` environment variable is set

- `OU` field in the certificate will not be set

  - unless the `-o`  commandline option is set
  - unless the `EPICS_PVA_AUTH_STD_ORG_UNIT`, `EPICS_PVAS_AUTH_STD_ORG_UNIT` environment variable is set

- `C` field in the certificate will be set to the local country code

  - unless the `-C`  commandline option is set
  - unless the `EPICS_PVA_AUTH_STD_COUNTRY`, `EPICS_PVAS_AUTH_STD_COUNTRY` environment variable is set

**usage**

Uses the standard ``EPICS_PVA_TLS_<name>`` environment variables to determine the keychain,
and password file locations.

    .. code-block:: sh

        Usage: authnstd <opts>

          -v         Make more noise.
          -h         Show this help message and exit
          -d         Shorthand for $PVXS_LOG="pvxs.*=DEBUG".  Make a lot of noise.
          -V         Show version and exit
          -u <use>   Usage. client, server, or gateway
          -N <name>  Name override the CN subject field
          -O <name>  Org override the O subject field
          -o <name>  Override the OU subject field

        ENVIRONMENT VARIABLES: at least one mandatory variable must be set
            EPICS_PVA_TLS_KEYCHAIN              Set name and location of client keychain file (mandatory for clients)
            EPICS_PVAS_TLS_KEYCHAIN             Set name and location of server keychain file (mandatory for server)
            EPICS_PVA_TLS_KEYCHAIN_PWD_FILE     Set name and location of client keychain password file (optional)
            EPICS_PVAS_TLS_KEYCHAIN_PWD_FILE    Set name and location of server keychain password file (optional)

**Environment Variables for authnstd**

+----------------------+------------------------------------+-----------------------------------------------------------------------+
| Name                 | Keys and Values                    | Description                                                           |
+======================+====================================+=======================================================================+
|| EPICS_AUTH_STD      || <number of minutes>               || Amount of minutes before the certificate expires.                    |
|| _CERT_VALIDITY_MINS || e.g. ``525960`` for 1 year        ||                                                                      |
+----------------------+------------------------------------+-----------------------------------------------------------------------+
|| EPICS_PVA_AUTH_STD  || {name to use}                     || Name to use in new certificates                                      |
|| _NAME               || e.g. ``archiver``                 ||                                                                      |
+----------------------+  e.g. ``IOC1``                     ||                                                                      |
|| EPICS_PVAS_AUTH_STD || e.g. ``greg``                     ||                                                                      |
|| _NAME               ||                                   ||                                                                      |
+----------------------+------------------------------------+-----------------------------------------------------------------------+
|| EPICS_PVA_AUTH_STD  || {organization to use}             || Organization to use in new certificates                              |
|| _ORG                || e.g. ``site.epics.org``           ||                                                                      |
+----------------------+  e.g. ``SLAC.STANFORD.EDU``        ||                                                                      |
|| EPICS_PVAS_AUTH_STD || e.g. ``KLYS:LI01:101``            ||                                                                      |
|| _ORG                || e.g. ``centos07``                 ||                                                                      |
+----------------------+------------------------------------+-----------------------------------------------------------------------+
|| EPICS_PVA_AUTH_STD  || {organization unit to use}        || Organization Unit to use in new certificates                         |
|| _ORG_UNIT           || e.g. ``data center``              ||                                                                      |
+----------------------+  e.g. ``ops``                      ||                                                                      |
|| EPICS_PVAS_AUTH_STD || e.g. ``prod``                     ||                                                                      |
|| _ORG_UNIT           || e.g. ``remote``                   ||                                                                      |
+----------------------+------------------------------------+-----------------------------------------------------------------------+
|| EPICS_PVA_AUTH_STD  || {country to use}                  || Country to use in new certificates.                                  |
|| _COUNTRY            || e.g. ``US``                       || Must be a two digit country code                                     |
+----------------------+  e.g. ``CA``                       ||                                                                      |
|| EPICS_PVAS_AUTH_STD ||                                   ||                                                                      |
|| _COUNTRY            ||                                   ||                                                                      |
+----------------------+------------------------------------+-----------------------------------------------------------------------+
|| EPICS_PVA_TLS       || <path to the keychain file>       || The location of the keychain file for client or server.  The file    |
|| _TLS_KEYCHAIN       ||                                   || will be created here                                                 |
+----------------------+                                    ||                                                                      |
|| EPICS_PVAS_TLS      ||                                   ||                                                                      |
|| _TLS_KEYCHAIN       ||                                   ||                                                                      |
+----------------------+------------------------------------+-----------------------------------------------------------------------+
|| EPICS_PVA_TLS       || <cert password file path>         || The location of the file containing the password for the keychain    |
|| _KEYCHAIN_PWD_FILE  ||                                   || file.                                                                |
+----------------------+                                    ||                                                                      |
|| EPICS_PVAS_TLS      ||                                   ||                                                                      |
|| _KEYCHAIN_PWD_FILE  ||                                   ||                                                                      |
+----------------------+------------------------------------+-----------------------------------------------------------------------+

**Examples**

    .. code-block:: sh

        # create a client certificate for greg@slac.stanford.edu
        authnstd -u client -N greg -O slac.stanford.edu

    .. code-block:: sh

        # create a server certificate for IOC1
        authnstd -u server -N IOC1 -O "KLI:LI01:10" -o "FACET"


    .. code-block:: sh

        # create a gateway certificate for gateway1
        authnstd -u gateway -N gateway1 -O bridge.ornl.gov -o "Networking"


authkrb Configuration and Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This authentication method is a TYPE ``2`` authentication method.
It can be used to create a certificate from a Kerberos ticket.

A user will need to have a Kerberos ticket to use this authentication method typically
using the ``kinit`` command.

    .. code-block:: sh

        kinit -l 24h greg@SLAC.STANFORD.EDU

- `CN` field in the certificate will be kerberos username
- `O` field in the certificate will be the kerberos realm
- `OU` field in the certificate will not be set
- `C` field in the certificate will be set to the local country code


**usage**

Uses the standard ``EPICS_PVA_TLS_<name>`` environment variables to determine the keychain,
and password file locations.

    .. code-block:: sh

        authnkrb <opts>

        Options:
        -h show help
        -v verbose output
        -t {client | server}     Client or server certificate certificate type
        -C                       Create a certificate and exit



**Environment Variables for PVACMS AuthnKRB Verifier**

The environment variables in the following table configure the Kerberos
Credentials Verifier for :ref:`pvacms` at runtime.


+-----------------+--------------------------------------+---------------------------------------------------------------------+
| Name            | Keys and Values                      | Description                                                         |
+=================+======================================+=====================================================================+
|| EPICS_AUTH_KRB || {string location of keytab file}    || This is the keytab file shared with :ref:`pvacms` by the KDC so .  |
|| _KEYTAB        || e.g. ``/etc/security/keytab``       || that it can verify kerberos tickets                                |
+-----------------+--------------------------------------+---------------------------------------------------------------------+
|| EPICS_AUTH_KRB || {this is the kerberos realm to use} || This is the kerberos realm to use when verifying kerberos tickets. |
|| _REALM         || e.g. ``SLAC.STANFORD.EDU``          || Overrides the verifier fields if specified.                        |
+-----------------+--------------------------------------+---------------------------------------------------------------------+

**Setup of Kerberos in Docker Container for testing**

In the source code under /examples/docker/spva_krb you'll find a Dockerfile and supporting resources for creating an environment
that contains a working kerberos KDC with the following characteristics:

- users (both unix and kerberos principals)

  - pvacms - service principal with private keytab file for authentication in ~/.config
  - admin - principal with password "secret" (includes a configured PVACMS administrator certificate)
  - softioc - service principal with password "secret"
  - client - principal with password "secret"

- services

  - KDC
  - kadmin Daemon
  - PVACMS


authldap Configuration and Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This authentication method is a TYPE ``2`` authentication method.
It can be used to create a certificate from a Kerberos ticket that is
verified against an LDAP server.

A user will need to have a Kerberos ticket to use this authentication method typically
using the ``kinit`` command.

    .. code-block:: sh

        kinit -l 24h greg@SLAC.STANFORD.EDU

- `CN` field in the certificate will be kerberos username
- `O` field in the certificate will be the kerberos realm
- `OU` field in the certificate will not be set
- `C` field in the certificate will be set to the local country code


**usage**

Uses the standard ``EPICS_PVA_TLS_<name>`` environment variables to determine the keychain,
and password file locations.

    .. code-block:: sh

        authnkrb <opts>

    Options:
    -h show help
    -v verbose output
    -t {client | server}     Client or server certificate certificate type
    -C                       Create a certificate and exit


**Environment Variables for PVACMS AuthnLDAP Verifier**

The environment variables in the following table configure the
LDAP Credentials Verifier for :ref:`pvacms` at runtime in addition to the AuthnKrb environment variables.

+--------------------+---------------------------------------+------------------------------------------------------------+
| Name               | Keys and Values                       | Description                                                |
+====================+=======================================+============================================================+
|| EPICS_AUTH_LDAP   || <account>                            || The admin account to use to access the LDAP server.       |
|| _ACCOUNT          || e.g. ``admin``                       || when verifying LDAP credentials.                          |
+--------------------+---------------------------------------+------------------------------------------------------------+
|| EPICS_AUTH_LDAP   || {location of password file}          || file containing password for the given LDAP admin account |
|| _ACCOUNT_PWD_FILE || e.g. ``~/.config/ldap.pass/``        ||                                                           |
+--------------------+---------------------------------------+------------------------------------------------------------+
|| EPICS_AUTH_LDAP   || {hostname of LDAP server}            || Trusted hostname of the LDAP server                       |
|| _HOST             || e.g. ``ldap.stanford.edu``           ||                                                           |
+--------------------+---------------------------------------+------------------------------------------------------------+
|| EPICS_AUTH_LDAP   || <port_number>                        || LDAP server port number. Default is 389                   |
|| _PORT             || e.g. ``389``                         ||                                                           |
+--------------------+---------------------------------------+------------------------------------------------------------+
|| EPICS_AUTH_LDAP   || {LDAP directory name to search from} || LDAP directory name to search from.                       |
|| _SEARCH_ROOT      || e.g. ``dc=slac,dc=stanford,dc=edu``  ||                                                           |
+--------------------+---------------------------------------+------------------------------------------------------------+


authjwt Configuration and Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This authentication method is a TYPE ``1`` authentication method.
It can be used to create a certificate from a JWT token.

The daemon will create a rest service that will allow posting of JWT tokens
and create a certificate based on the token's credentials.

Verification of the JWT token is performed by :ref:`pvacms` before exchanging for a certificate.

**JWT Token Post Request**
A web application, python script, java application, etc. can post a JWT token to the authentication daemon
whenever it gets a new token from an authentication service.   The authentication daemon will send
a :ref:`certificate_creation_request_CCR` to :ref:`pvacms` to create a certificate based on the JWT token.  :ref:`pvacms` will verify the token based
on the configuration of the authnjwt verifier.

You could test this by posting a JWT token to the authentication daemon as follows:

    .. code-block:: sh

        authnjwt -D &

        curl -X POST http://localhost:8080 \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE"

.. note::

    No body is sent in this POST request.

- `CN` field in the certificate will be the username from the JWT token
- `O` field in the certificate will be the issuer from the JWT token
- `OU` field in the certificate will not be set
- `C` field in the certificate will be set to the local country code


**usage**

Uses the standard ``EPICS_PVA_TLS_<name>`` environment variables to determine the keychain,
and password file locations.

    .. code-block:: sh

        authnjwt <opts>

        Options:
        -h show help
        -v verbose output
        -t {client | server}     Client or server certificate certificate type
        -C                       Create a certificate and exit
        -D                       Start authentication daemon web service to receive
                                JWT tokens and create certificates.

**Environment Variables for PVACMS AuthnJWT Verifier**

The environment variables in the following table configure the JWT
Credentials Verifier for :ref:`pvacms` at runtime.

+---------------------+---------------------------------------------------+-------------------------------------------------------------------------------------+
| Name                | Keys and Values                                   | Description                                                                         |
+=====================+===================================================+=====================================================================================+
|| EPICS_AUTH_JWT     || {string format for verification request payload} || Used to create the verification request payload by substituting the #token#        |
|| _REQUEST_FORMAT    || e.g. ``{ "token": "#token#" }``                  || for the token value, and #kid# for the key id. This is used when the               |
||                    || e.g. ``#token#``                                 || verification server requires a formatted payload for the verification request.     |
+---------------------+---------------------------------------------------+-------------------------------------------------------------------------------------+
|| EPICS_AUTH_JWT     || {string format for verification response value}  || A pattern string that we can use to decode the response from a verification        |
|| _RESPONSE_FORMAT   ||                                                  || endpoint if the response is formatted text. All white space is removed in the      |
||                    ||                                                  || given string and in the response. Then all the text prior to #response# is matched |
||                    ||                                                  || and removed from the response and all the text after the response is likewise      |
||                    ||                                                  || removed, what remains is the response value. An asterisk in the string matches     |
||                    ||                                                  || any sequence of characters in the response. It is converted to lowercase and       |
||                    ||                                                  || interpreted as valid if it equals valid, ok, true, t, yes, y, or 1.                |
+---------------------+---------------------------------------------------+-------------------------------------------------------------------------------------+
|| EPICS_AUTH_JWT     || {uri of JWT validation endpoint}                 || Trusted URI of the validation endpoint – the substring that starts the URI         |
|| _TRUSTED_URI       ||                                                  || including the http://, https:// and port number.                                   |
+---------------------+---------------------------------------------------+-------------------------------------------------------------------------------------+
|| EPICS_AUTH_JWT_USE || case insensitive: ``YES``, ``TRUE``, or ``1``    || If set this tells :ref:`pvacms` that when it receives a 200 HTTP-response from     |
|| _RESPONSE_CODE     ||                                                  || the HTTP request then the token is valid, and invalid for any other response code. |
+---------------------+---------------------------------------------------+-------------------------------------------------------------------------------------+
|| EPICS_AUTH_JWT     || {``POST`` (default) or ``GET``}                  || This determines whether the endpoint will be called with HTTP GET or POST.         |
|| _REQUEST_METHOD    ||                                                  ||                                                                                    |
+---------------------+---------------------------------------------------+-------------------------------------------------------------------------------------+


.. _epics_security:

EPICS Security
--------------

New AUTHORIZATION mechanisms integrate with EPICS Security through four access control mechanisms:

METHOD
^^^^^^

Defines access permissions based on authentication method:

- ``x509``: Certificate-based authentication
- ``ca``: Legacy PVAccess AUTHZ with user-specified account
- ``anonymous``: Access without specified name

AUTHORITY
^^^^^^^^^

Defines access permissions based on certificate authority:

- Uses CA name from ``CN`` field of CA certificate's subject
- Only applicable for X.509 certificate authentication

RPC Permission
^^^^^^^^^^^^^^^

New rule permission for RPC message access control:

- Supplements existing ``NONE``, ``READ`` (`GET`), and ``WRITE`` (`PUT`)
- Controls access to `RPC` PVAccess messages

ISTLS Option
^^^^^^^^^^^^^

New rule option for TLS-based access control:

- Requires server connection with trusted CA-signed certificate
- Enables READ access restriction to certified PVs only

.. _access_control_file_ACF:

Access Control File (ACF)
^^^^^^^^^^^^^^^^^^^^^^^^^

Example ACF showing new security features:

    .. code-block:: text

        UAG(bar) {boss}
        UAG(foo) {testing}
        UAG(ops) {geek}

        ASG(DEFAULT) {
            RULE(0,NONE,NOTRAPWRITE)
        }

        ASG(ro) {
            RULE(0,NONE,NOTRAPWRITE)
            RULE(1,READ,ISTLS) {
                UAG(foo,ops)
                METHOD("ca")
            }
        }

        ASG(rw) {
            RULE(0,NONE,NOTRAPWRITE)
            RULE(1,WRITE,TRAPWRITE) {
                UAG(foo)
                METHOD("x509")
                AUTHORITY("Epics Org CA")
            }
        }

        ASG(rwx) {
            RULE(0,NONE,NOTRAPWRITE)
            RULE(1,RPC,NOTRAPWRITE) {
                UAG(bar)
                METHOD("x509")
                AUTHORITY("Epics Org CA","ORNL Org CA")
            }
        }

.. _new_epics_yaml_acf_file_format:

EPICS YAML ACF Format
^^^^^^^^^^^^^^^^^^^

Alternative YAML format for improved readability:

    .. code-block:: yaml

        # EPICS YAML
        version: 1.0

        uags:
          - name: bar
            users:
              - boss
          - name: foo
            users:
              - testing
          - name: ops
            users:
              - geek

        asgs:
          - name: ro
            rules:
              - level: 0
                access: NONE
                trapwrite: false
              - level: 1
                access: READ
                isTLS: true
                uags:
                  - foo
                  - ops
                methods:
                  - ca

          - name: rw
            rules:
              - level: 0
                access: NONE
                trapwrite: false
              - level: 1
                access: WRITE
                trapwrite: true
                uags:
                  - foo
                methods:
                  - x509
                authorities:
                  - SLAC Certificate Authority

          - name: rwx
            rules:
              - level: 0
                access: NONE
                trapwrite: false
              - level: 1
                access: RPC
                trapwrite: true
                uags:
                  - bar
                methods:
                  - x509
                authorities:
                  - SLAC Certificate Authority
                  - ORNL Org CA


