.. _quick_start_ldap:

|guide| Quick Start LDAP
===============================

This section contains a Quick Start |guide| for the Secure PVAccess *LDAP Authenticator*.

    The LDAP Authenticator is an Authenticator that creates an X.509
    certificate from LDAP credentials.

    It prompts the user to log in to the LDAP directory service.
    It then signs a certificate creation request with its private key and passes
    it to the PVACMS, which decodes it with the public key that
    it finds in the LDAP directory entry for the user.  If this succeeds it means that the
    requester holds the matching private key and so the certificate is generated.

    It uses the LDAP username as the ``common name`` and then concatenates all the ``dc`` components it finds
    to create the organisation while leaving the ``organizational unit`` blank.
    e.g. ``dn: uid=admin,dc=epics,dc=org`` becomes ``CN=admin``, ``O=epics.org``.

Our starting point for this Quick Start Guide is the end of the :ref:`quick_start_std` so if you haven't gone through it yet
do that now then come back here.  You need to have user's configured (``pvacms``, ``admin``, ``softioc``, and ``client``).
We will set up a containerised LDAP Service and configure it so that the users can log in.

When to use the LDAP Authenticator?

- Your network uses Kerberos for login

  If, as is normally the case, you use Kerberos for authentication and
  LDAP for user profile information - *group*, *contact details*, etc - then
  use the Kerberos Authenticator.

- Your network clients login directly to LDAP

  If you've configured your LDAP server for user login then we will
  show how you could use LDAP login credentials to get
  an X.509 certificate.

See :ref:`secure_pvaccess` for general documentation on Secure PVAccess.

Other Quick Start Guides:

- :ref:`quick_start`
- :ref:`quick_start_std`
- :ref:`quick_start_krb`

|learn| You will learn:
******************************

- :ref:`Creating a containerised LDAP Service <spva_qs_ldap_ldap>`,
- :ref:`Building PVXS with LDAP Authenticator support <spva_qs_ldap_build>`,
- :ref:`Configuring the LDAP schema to support the LDAP Authenticator <spva_qs_ldap_pvacms>`,
- :ref:`Creating certificates using the LDAP Authenticator<spva_qs_ldap_server>` and
- :ref:`Connecting a LDAP Client to an SPVA Server<spva_qs_ldap_client>`

|pre-packaged|\Prepackaged
*********************************

If you want a prepackaged environment, try the following.  You will need three terminal sessions.

|1| Load image
------------------------------

- |terminal|\¹
- start new container with Prepackaged Secure PVAccess with LDAP Authenticator and 4 Users

.. code-block:: shell

    docker run -it --name spva_ldap georgeleveln/spva_ldap:latest

.. code-block:: console

    2025-03-08 19:53:45,557 CRIT Supervisor is running as root.  Privileges were not dropped because no user is specified in the config file.  If you intend to run as root, you can set user=root in the config file to avoid this message.
    2025-03-08 19:53:45,557 INFO Included extra file "/etc/supervisor/conf.d/ldap.conf" during parsing
    2025-03-08 19:53:45,557 INFO Included extra file "/etc/supervisor/conf.d/pvacms.conf" during parsing
    2025-03-08 19:53:45,557 INFO Included extra file "/etc/supervisor/conf.d/sssd.conf" during parsing
    2025-03-08 19:53:45,559 INFO supervisord started with pid 1
    2025-03-08 19:53:46,568 INFO spawned: 'ldap' with pid 7
    2025-03-08 19:53:46,573 INFO spawned: 'pvacms' with pid 8
    2025-03-08 19:53:46,574 INFO spawned: 'sssd' with pid 9
    2025-03-08 19:53:47,688 INFO success: ldap entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
    2025-03-08 19:53:47,688 INFO success: pvacms entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
    2025-03-08 19:53:47,688 INFO success: sssd entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)

|2| Service
------------------------------

- |terminal|\²
- log in as softioc service account

.. code-block:: shell

    docker exec -it --user softioc spva_ldap /bin/bash

create a server certificate using the LDAP Authenticator, enter ``secret`` when prompted for LDAP password

.. code-block:: shell

    authnldap -u server

.. code-block:: console

    Enter password for softioc@ca130cc9b352:
    Keychain file created   : /home/softioc/.config/pva/1.3/server.p12
    Certificate identifier  : 47530d89:12147807175996825338


.. code-block:: shell

    pvxcert -f ~/.config/pva/1.3/server.p12

.. code-block:: console

    Certificate Details:
    ============================================
    Certificate ID : 47530d89:12147807175996825338
    Entity Subject : CN=softioc, O=epics.org
    Issuer Subject : CN=EPICS Root Certificate Authority, C=US, O=certs.epics.org, OU=EPICS Certificate Authority
    Valid From     : Sat Mar 08 19:56:17 2025 UTC
    Expires On     : Sun Mar 08 19:56:17 2026 UTC
    --------------------------------------------

    Certificate Status:
    ============================================
    Certificate ID: 47530d89:12147807175996825338
    Status        : VALID
    Status Issued : Sat Mar 08 19:57:22 2025 UTC
    Status Expires: Sat Mar 08 20:27:22 2025 UTC
    --------------------------------------------

|3| Client
------------------------------

- |terminal|\³
- log in as a Secure PVAccess client

.. code-block:: shell

    docker exec -it --user client spva_ldap /bin/bash

- create a client certificate using the LDAP Authenticator, enter ``secret`` when prompted for LDAP password

.. code-block:: shell

    authnldap

.. code-block:: console

    Enter password for client@epics.org:
    Keychain file created   : /home/client/.config/pva/1.3/client.p12
    Certificate identifier  : 47530d89:11547935522995899879

.. code-block:: shell

    pvxcert -f ~/.config/pva/1.3/client.p12

.. code-block:: console

    Certificate Details:
    ============================================
    Certificate ID : 47530d89:11547935522995899879
    Entity Subject : CN=client, O=epics.org
    Issuer Subject : CN=EPICS Root Certificate Authority, C=US, O=certs.epics.org, OU=EPICS Certificate Authority
    Valid From     : Sat Mar 08 20:00:41 2025 UTC
    Expires On     : Sun Mar 08 20:00:41 2026 UTC
    --------------------------------------------

    Certificate Status:
    ============================================
    Certificate ID: 47530d89:11547935522995899879
    Status        : VALID
    Status Issued : Sat Mar 08 20:01:59 2025 UTC
    Status Expires: Sat Mar 08 20:31:59 2025 UTC
    --------------------------------------------


|4| Start SoftIOC
------------------------------

- |terminal|\²
- start SoftIOC

.. code-block:: shell

    softIocPVX \
        -m user=test,N=tst,P=tst \
        -d ${PROJECT_HOME}/pvxs/test/testioc.db \
        -d ${PROJECT_HOME}/pvxs/test/testiocg.db \
        -d ${PROJECT_HOME}/pvxs/test/image.db \
        -G ${PROJECT_HOME}/pvxs/test/image.json \
        -a ${PROJECT_HOME}/pvxs/test/testioc.acf

.. code-block:: console

    INFO: PVXS QSRV2 is loaded, permitted, and ENABLED.
    2025-03-08T20:02:23.012770920 WARN pvxs.tcp.init Server unable to bind TCP port 5075, falling back to [::]:40965
    2025-03-08T20:02:23.012856587 WARN pvxs.tcp.init Server unable to bind TLS port 5076, falling back to [::]:35255
    Starting iocInit
    ############################################################################
    ## EPICS R7.0.8.2-DEV
    ## Rev. R7.0.8.1-123-g48607a42586b1a316cd6
    ## Rev. Date Git: 2024-11-29 17:08:28 +0000
    ############################################################################
    iocRun: All initialization complete
    epics>

|5| Get PV value
------------------------------

- |terminal|\³
- get a PV ``test:enumExample`` value from the SoftIOC

.. code-block:: shell

    pvxinfo -v test:enumExample

.. code-block:: console

    Effective config
    EPICS_PVA_AUTO_ADDR_LIST=YES
    EPICS_PVA_BROADCAST_PORT=5076
    EPICS_PVA_CONN_TMO=30
    EPICS_PVA_SERVER_PORT=5075
    EPICS_PVA_TLS_KEYCHAIN=/home/client/.config/pva/1.3/client.p12
    EPICS_PVA_TLS_OPTIONS=on_expiration=fallback-to-tcp on_no_cms=fallback-to-tcp
    EPICS_PVA_TLS_PORT=5076
    XDG_CONFIG_HOME=/home/client/.config/pva/1.3
    XDG_DATA_HOME=/home/client/.local/share/pva/1.3
    # TLS x509:47530d89:12147807175996825338:EPICS Root Certificate Authority/softioc@172.17.0.2:35255
    test:enumExample from 172.17.0.2:35255
    struct "epics:nt/NTEnum:1.0" {
        struct "enum_t" {
            int32_t index
            string[] choices
        } value
        struct "alarm_t" {
            int32_t severity
            int32_t status
            string message
        } alarm
        struct "time_t" {
            int64_t secondsPastEpoch
            int32_t nanoseconds
            int32_t userTag
        } timeStamp
        struct {
            string description
        } display
    }

- verify that connection is TLS

- ``TLS x509:47530d89:12147807175996825338:EPICS Root Certificate Authority/softioc @ 172.17.0.2`` indicates that:

  - The connection is ``TLS``,
  - The Server end of the channel has been authenticated by the Root Certificate Authority ``EPICS Root Certificate Authority``
  - The Server end of the channel's name has been authenticated as ``softioc`` and is connecting from host ``172.17.0.2``

|step-by-step| Step-By-Step
********************************

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


|step| Docker Image
------------------------------------------

|1| Use a Prepackaged spva_std image
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\¹
- open a terminal and load pre-built image
- don't forget to add /bin/bash at the end to suppress running the pvacms

.. code-block:: shell

    docker run -it --name spva_ldap georgeleveln/spva_std:latest /bin/bash

.. _spva_qs_ldap_kdc:

|step| LDAP Service
------------------------------------------

This section shows how to install and configure a LDAP Service.  This
is included to enable you to test the LDAP Authenticator before deploying it
into your network.  It will enable you to configure EPICS agents to
log in to the LDAP service using the LDAP Authenticator to authenticate and
then generate X.509 certificates.


|1| Install prerequisites
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- pre-seed debconf for slapd so that it uses our desired domain and organization

  - domain: ``epics.org``
  - organization: ``EPICS``

.. code-block:: shell

    export PROJECT_HOME=/opt/epics
    export DEBIAN_FRONTEND=noninteractive

    echo "slapd slapd/no_configuration boolean false" | debconf-set-selections && \
    echo "slapd slapd/domain string epics.org" | debconf-set-selections && \
    echo "slapd shared/organization string EPICS" | debconf-set-selections && \
    echo "slapd slapd/password1 password secret" | debconf-set-selections && \
    echo "slapd slapd/password2 password secret" | debconf-set-selections && \
    echo "slapd slapd/backend string MDB" | debconf-set-selections && \
    echo "slapd slapd/purge_database boolean true" | debconf-set-selections && \
    echo "slapd slapd/move_old_database boolean true" | debconf-set-selections

- Add LDAP dependencies

  - ``slapd`` - LDAP service
  - ``ldap-utils`` - LDAP utilities
  - ``sssd`` - sssd daemon for centralised identity service access
  - ``libldap2-dev`` - development library for compiling pvxs with LDAP Authenticator support
  - ``libnss`` and ``libpam`` - development libraries that integrate ``sssd`` with ``LDAP``

.. code-block:: shell

    apt-get update && \
    apt-get install -y --no-install-recommends \
        slapd \
        ldap-utils \
        sssd \
        libldap2-dev \
        libnss-sss \
        libpam-sss && \
    rm -rf /var/lib/apt/lists/*

.. code-block:: console

    Hit:1 http://ports.ubuntu.com/ubuntu-ports noble InRelease
    Get:2 http://ports.ubuntu.com/ubuntu-ports noble-updates InRelease [126 kB]
    Get:3 http://ports.ubuntu.com/ubuntu-ports noble-backports InRelease [126 kB]
    Get:4 http://ports.ubuntu.com/ubuntu-ports noble-security InRelease [126 kB]
    Get:5 http://ports.ubuntu.com/ubuntu-ports noble-updates/main arm64 Packages [1147 kB]
    Get:6 http://ports.ubuntu.com/ubuntu-ports noble-updates/multiverse arm64 Packages [32.7 kB]
    Get:7 http://ports.ubuntu.com/ubuntu-ports noble-updates/restricted arm64 Packages [1076 kB]
    Get:8 http://ports.ubuntu.com/ubuntu-ports noble-updates/universe arm64 Packages [1305 kB]
    Get:9 http://ports.ubuntu.com/ubuntu-ports noble-security/universe arm64 Packages [1028 kB]
    ...
    warn: The home directory `/var/lib/sss' already exists.  Not touching this directory.
    warn: Warning: The home directory `/var/lib/sss' does not belong to the user you are currently creating.
    invoke-rc.d: could not determine current runlevel
    invoke-rc.d: policy-rc.d denied execution of start.
    Setting up sssd-proxy (2.9.4-1.1ubuntu6.2) ...
    Setting up sssd-ad-common (2.9.4-1.1ubuntu6.2) ...
    Setting up sssd-krb5-common (2.9.4-1.1ubuntu6.2) ...
    Setting up sssd-krb5 (2.9.4-1.1ubuntu6.2) ...
    Setting up sssd-ldap (2.9.4-1.1ubuntu6.2) ...
    Setting up sssd-ad (2.9.4-1.1ubuntu6.2) ...
    Setting up sssd-ipa (2.9.4-1.1ubuntu6.2) ...
    Setting up sssd (2.9.4-1.1ubuntu6.2) ...
    Processing triggers for libc-bin (2.39-0ubuntu8.4) ...

.. _spva_qs_ldap_build:

|2| Rebuild pvxs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- enable LDAP Authenticator by updating ``CONFIG_SITE.local``
- do a clean rebuild of pvxs

.. code-block:: shell

    cd ${PROJECT_HOME}

    cat >> CONFIG_SITE.local <<EOF
    EVENT2_HAS_OPENSSL = YES
    PVXS_ENABLE_PVACMS = YES
    PVXS_ENABLE_LDAP_AUTH = YES
    EOF

    cd pvxs && \
    make distclean && \
    make -j10 all

.. code-block:: console

    make -C ./configure realclean
    make[1]: Entering directory '/opt/epics/pvxs/configure'
    rm -rf O.*
    make[1]: Leaving directory '/opt/epics/pvxs/configure'
    make -C ./setup realclean
    make[1]: Entering directory '/opt/epics/pvxs/setup'
    rm -rf O.*
    make[1]: Leaving directory '/opt/epics/pvxs/setup'
    make -C ./src realclean
    make[1]: Entering directory '/opt/epics/pvxs/src'
    rm -rf O.*
    make[1]: Leaving directory '/opt/epics/pvxs/src'
    make -C ./tools realclean
    make[1]: Entering directory '/opt/epics/pvxs/tools'
    ...
    perl -CSD /opt/epics/epics-base/bin/linux-aarch64/makeTestfile.pl linux-aarch64 linux-aarch64 testtls.t testtls
    /usr/bin/g++ -o testtlswithcmsandstapling  -L/opt/epics/epics-base/lib/linux-aarch64 -L/opt/epics/pvxs/lib/linux-aarch64 -Wl,-rpath,/opt/epics/epics-base/lib/linux-aarch64 -Wl,-rpath,/opt/epics/pvxs/lib/linux-aarch64     -Wl,--as-needed -Wl,--compress-debug-sections=zlib      -rdynamic         testtlswithcmsandstapling.o certstatusfactory.o certstatusmanager.o certstatus.o    -lpvxs -lCom  -levent_openssl -levent_core -levent_pthreads -lssl -lcrypto
    perl -CSD /opt/epics/epics-base/bin/linux-aarch64/makeTestfile.pl linux-aarch64 linux-aarch64 testtlswithcmsandstapling.t testtlswithcmsandstapling
    /usr/bin/g++ -o testtlswithcms  -L/opt/epics/epics-base/lib/linux-aarch64 -L/opt/epics/pvxs/lib/linux-aarch64 -Wl,-rpath,/opt/epics/epics-base/lib/linux-aarch64 -Wl,-rpath,/opt/epics/pvxs/lib/linux-aarch64     -Wl,--as-needed -Wl,--compress-debug-sections=zlib      -rdynamic         testtlswithcms.o certstatusfactory.o certstatusmanager.o certstatus.o    -lpvxs -lCom  -levent_openssl -levent_core -levent_pthreads -lssl -lcrypto
    perl -CSD /opt/epics/epics-base/bin/linux-aarch64/makeTestfile.pl linux-aarch64 linux-aarch64 testtlswithcms.t testtlswithcms
    make[2]: Leaving directory '/opt/epics/pvxs/test/O.linux-aarch64'
    make[1]: Leaving directory '/opt/epics/pvxs/test'

|3| Configure LDAP
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Remove the default LDAP configuration and reconfigure slapd non-interactively

.. code-block:: shell

    rm -rf /etc/ldap/slapd.d && \
    dpkg-reconfigure -f noninteractive slapd

.. code-block:: console

    invoke-rc.d: could not determine current runlevel
    invoke-rc.d: policy-rc.d denied execution of stop.
    invoke-rc.d: could not determine current runlevel
    invoke-rc.d: policy-rc.d denied execution of stop.
      Moving old database directory to /var/backups:
      - directory unknown... done.
      Creating initial configuration... done.
      Creating LDAP directory... done.
    invoke-rc.d: could not determine current runlevel
    invoke-rc.d: policy-rc.d denied execution of start.

- create epics custom schema addition to enable LDAP Authenticator

  - this schema addition will hold the public key for each LDAP user
  - acl protects it so that only the user themselves can write to it but it is readable by anyone

.. code-block:: shell

    cat > /tmp/epics-schema.ldif <<EOF
    dn: cn=epics,cn=schema,cn=config
    objectClass: olcSchemaConfig
    cn: epics
    olcAttributeTypes: ( 1.3.6.1.4.1.99999.1
        NAME 'epicsPublicKey'
        DESC 'Public key EPICS Agents'
        EQUALITY caseExactMatch
        SUBSTR caseExactSubstringsMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
        SINGLE-VALUE )
    olcObjectClasses: ( 1.3.6.1.4.1.99999.2
        NAME 'epicsAuxiliary'
        DESC 'Auxiliary object class to allow storage of a public key'
        SUP top
        AUXILIARY
        MAY ( epicsPublicKey ) )
    EOF

.. code-block:: shell

    cat > /tmp/epics-acl.ldif <<EOF
    dn: olcDatabase={1}mdb,cn=config
    changetype: modify
    add: olcAccess
    olcAccess: {0}to attrs=epicsPublicKey by self write by users read by anonymous read
    EOF

.. code-block:: shell

    /usr/sbin/slapd -h "ldap:/// ldapi:///" -u openldap & \
    sleep 5 && \
    ldapadd -Y EXTERNAL -H ldapi:/// -f /tmp/epics-schema.ldif && \
    ldapmodify -Y EXTERNAL -H ldapi:/// -f /tmp/epics-acl.ldif && \
    pkill slapd && \
    sleep 2 && \
    rm -f /tmp/epics-schema.ldif /tmp/epics-acl.ldif

.. code-block:: console

    [1] 2802

    [1]+  Done                    /usr/sbin/slapd -h "ldap:/// ldapi:///" -u openldap
    SASL/EXTERNAL authentication started
    SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
    SASL SSF: 0
    adding new entry "cn=epics,cn=schema,cn=config"

    SASL/EXTERNAL authentication started
    SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
    SASL SSF: 0
    modifying entry "olcDatabase={1}mdb,cn=config"


|4| Configure LDAP Users
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- create LDAP users

  - base dn: ``dc=epics``, ``dc=org``
  - users: ``admin``, ``pvacms``, ``softioc``, ``client``
  - posix groups: ``admin``, ``pvacms``, ``softioc``, ``client``
  - groups: ``users``, ``servers``, ``clients``, ``services``
  - linux mappings: home directory, shell
  - password: "secret"

.. code-block:: shell

    cat > /tmp/ldap-data.ldif <<EOF
    dn: dc=epics,dc=org
    objectClass: dcObject
    objectClass: organization
    dc: epics
    o: EPICS

    # Base organizational units
    dn: ou=People,dc=epics,dc=org
    objectClass: organizationalUnit
    ou: People

    dn: ou=Groups,dc=epics,dc=org
    objectClass: organizationalUnit
    ou: Groups

    # Create users
    dn: uid=admin,dc=epics,dc=org
    objectClass: inetOrgPerson
    objectClass: posixAccount
    objectClass: shadowAccount
    objectClass: epicsAuxiliary
    cn: admin
    sn: admin
    uid: admin
    uidNumber: 1001
    gidNumber: 1001
    homeDirectory: /home/admin
    loginShell: /bin/bash
    userPassword: {SSHA}rDsYFPnFI8zidqcImBer6BGBULvgxjo0
    # epicsPublicKey: <base64-encoded public key string>

    dn: uid=pvacms,ou=People,dc=epics,dc=org
    objectClass: inetOrgPerson
    objectClass: posixAccount
    objectClass: shadowAccount
    objectClass: epicsAuxiliary
    cn: pvacms
    sn: pvacms
    uid: pvacms
    uidNumber: 1002
    gidNumber: 1002
    homeDirectory: /home/pvacms
    loginShell: /bin/bash
    userPassword: {SSHA}rDsYFPnFI8zidqcImBer6BGBULvgxjo0
    # epicsPublicKey: <base64-encoded public key string>

    dn: uid=softioc,ou=People,dc=epics,dc=org
    objectClass: inetOrgPerson
    objectClass: posixAccount
    objectClass: shadowAccount
    objectClass: epicsAuxiliary
    cn: softioc
    sn: softioc
    uid: softioc
    uidNumber: 1003
    gidNumber: 1003
    homeDirectory: /home/softioc
    loginShell: /bin/bash
    userPassword: {SSHA}rDsYFPnFI8zidqcImBer6BGBULvgxjo0
    # epicsPublicKey: <base64-encoded public key string>

    dn: uid=client,ou=People,dc=epics,dc=org
    objectClass: inetOrgPerson
    objectClass: posixAccount
    objectClass: shadowAccount
    objectClass: epicsAuxiliary
    cn: client
    sn: client
    uid: client
    uidNumber: 1004
    gidNumber: 1004
    homeDirectory: /home/client
    loginShell: /bin/bash
    userPassword: {SSHA}rDsYFPnFI8zidqcImBer6BGBULvgxjo0
    # epicsPublicKey: <base64-encoded public key string>

    # Create groups and add members
    dn: cn=admin,ou=Groups,dc=epics,dc=org
    objectClass: posixGroup
    cn: admin
    gidNumber: 1001
    memberUid: admin

    dn: cn=pvacms,ou=Groups,dc=epics,dc=org
    objectClass: posixGroup
    cn: pvacms
    gidNumber: 1002
    memberUid: pvacms

    dn: cn=softioc,ou=Groups,dc=epics,dc=org
    objectClass: posixGroup
    cn: softioc
    gidNumber: 1003
    memberUid: softioc

    dn: cn=client,ou=Groups,dc=epics,dc=org
    objectClass: posixGroup
    cn: client
    gidNumber: 1004
    memberUid: client

    dn: cn=users,ou=Groups,dc=epics,dc=org
    objectClass: groupOfUniqueNames
    cn: users
    uniqueMember: uid=admin,ou=People,dc=epics,dc=org
    uniqueMember: uid=client,ou=People,dc=epics,dc=org

    dn: cn=servers,ou=Groups,dc=epics,dc=org
    objectClass: groupOfUniqueNames
    cn: servers
    uniqueMember: uid=softioc,ou=People,dc=epics,dc=org
    uniqueMember: uid=pvacms,ou=People,dc=epics,dc=org

    dn: cn=clients,ou=Groups,dc=epics,dc=org
    objectClass: groupOfUniqueNames
    cn: clients
    uniqueMember: uid=softioc,ou=People,dc=epics,dc=org
    uniqueMember: uid=client,ou=People,dc=epics,dc=org

    dn: cn=services,ou=Groups,dc=epics,dc=org
    objectClass: groupOfUniqueNames
    cn: services
    uniqueMember: uid=pvacms,ou=People,dc=epics,dc=org
    EOF

- remove any existing LDAP database contents
- load the LDAP entries using slapadd
- fix ownership
- clean up

.. code-block:: shell

    rm -rf /var/lib/ldap/* && \
    slapadd -l /tmp/ldap-data.ldif && \
    chown -R openldap:openldap /var/lib/ldap && \
    rm -f /tmp/ldap-data.ldif

.. code-block:: console

    Closing DB...

.. _spva_qs_ldap_pvacms:

|5| Configure SSSD (optional)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- sssd configuration

  - LDAP set as identity provider

.. code-block:: shell

    cat > /etc/sssd/sssd.conf <<EOF
    [sssd]
    services = nss, pam
    domains = epics
    config_file_version = 2

    [domain/epics]
    id_provider = ldap
    auth_provider = ldap
    ldap_uri = ldap://localhost
    ldap_search_base = dc=epics,dc=org
    # leave these unset for anonymous access.
    ldap_default_bind_dn =
    ldap_default_authtok =

    # Cache credentials so that user information is available even if LDAP temporarily becomes unavailable.
    cache_credentials = True

    # If a user entry does not specify a home directory, use this pattern.
    fallback_homedir = /home/%u

    # Use the RFC2307 schema for standard POSIX attributes.
    ldap_schema = rfc2307

    # enable enumeration (listing all users) for testing.
    enumerate = True

    debug_level = 0
    EOF

- secure the SSSD configuration

.. code-block:: shell

    chmod 600 /etc/sssd/sssd.conf && \
    chown root:root /etc/sssd/sssd.conf

- update /etc/nsswitch.conf to use SSSD for passwd, group, and shadow

.. code-block:: shell

    sed -i 's/^passwd:.*/passwd:        files sss/' /etc/nsswitch.conf && \
    sed -i 's/^group:.*/group:          files sss/' /etc/nsswitch.conf && \
    sed -i 's/^shadow:.*/shadow:        files sss/' /etc/nsswitch.conf

|6| Configure Supervisor to run LDAP and SSSD
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- configure LDAP supervisord

.. code-block:: shell

    cat > /etc/supervisor/conf.d/ldap.conf <<EOF
    [program:ldap]
    command=/usr/sbin/slapd -h "ldap:///" -d 1
    autostart=true
    autorestart=true
    stdout_logfile=/var/log/supervisor/ldap.out.log
    stderr_logfile=/var/log/supervisor/ldap.err.log
    EOF

- configure SSSD supervisord

.. code-block:: shell

    cat > /etc/supervisor/conf.d/sssd.conf <<EOF
    [program:sssd]
    command=/usr/sbin/sssd -i
    autostart=true
    autorestart=true
    stdout_logfile=/var/log/supervisor/sssd.out.log
    stderr_logfile=/var/log/supervisor/sssd.err.log
    EOF

|7| Start Services
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- start LDAP, sssd, and pvacms with LDAP Authenticator support

.. code-block:: shell

    /usr/bin/supervisord -c /etc/supervisor/supervisord.conf

.. code-block:: console

    2025-03-10 12:42:04,390 INFO Included extra file "/etc/supervisor/conf.d/ldap.conf" during parsing
    2025-03-10 12:42:04,390 INFO Included extra file "/etc/supervisor/conf.d/pvacms.conf" during parsing
    2025-03-10 12:42:04,390 INFO Included extra file "/etc/supervisor/conf.d/sssd.conf" during parsing
    2025-03-10 12:42:04,390 INFO Set uid to user 0 succeeded
    2025-03-10 12:42:04,391 INFO supervisord started with pid 2830
    2025-03-10 12:42:05,403 INFO spawned: 'ldap' with pid 2831
    2025-03-10 12:42:05,412 INFO spawned: 'pvacms' with pid 2832
    2025-03-10 12:42:05,413 INFO spawned: 'sssd' with pid 2833
    2025-03-10 12:42:06,717 INFO success: ldap entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
    2025-03-10 12:42:06,717 INFO success: pvacms entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
    2025-03-10 12:42:06,717 INFO success: sssd entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)

.. _spva_qs_ldap_server:

|step| Run SoftIOC
------------------------------------------

|1| Login as softioc in a new shell
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\²

.. code-block:: shell

    docker exec -it --user softioc spva_ldap /bin/bash

|2| Verify LDAP config
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- read out entry for softioc from LDAP directory

.. code-block:: shell

    ldapsearch -x -LLL -b "ou=People,dc=epics,dc=org" "(uid=softioc)"

.. code-block:: console

    dn: uid=softioc,ou=People,dc=epics,dc=org
    objectClass: inetOrgPerson
    objectClass: posixAccount
    objectClass: shadowAccount
    objectClass: epicsAuxiliary
    cn: softioc
    sn: softioc
    uid: softioc
    uidNumber: 1003
    gidNumber: 1003
    homeDirectory: /home/softioc
    loginShell: /bin/bash

.. code-block:: shell

    ldapsearch -x -LLL -b "ou=People,dc=epics,dc=org" "(uid=softioc)"

.. code-block:: console

    dn: uid=softioc,ou=People,dc=epics,dc=org
    objectClass: inetOrgPerson
    objectClass: posixAccount
    objectClass: shadowAccount
    objectClass: epicsAuxiliary
    cn: softioc
    sn: softioc
    uid: softioc
    uidNumber: 1003
    gidNumber: 1003
    homeDirectory: /home/softioc
    loginShell: /bin/bash

|3| Get Certificate
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- create a softioc server certificate.  Enter "secret" when prompted for password

  - creates softioc server certificate
  - at location specified by ``EPICS_PVAS_TLS_KEYCHAIN`` or ``${XDG_CONFIG_HOME}/pva/1.3/server.p12`` by default

.. code-block:: shell

    authnldap -u server

.. code-block:: console

    Enter password for softioc@c6e116778b71:
    Keychain file created   : /home/softioc/.config/pva/1.3/server.p12
    Certificate identifier  : b271f07a:13935791733272200197

|4| Check the certificate status is VALID
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- check that the generated certificate is ``VALID``
- note that the *name* is ``softioc`` - verified against LDAP
- note that the *organization* is ``epics.org`` - picked up from LDAP
- note that the *expiration date* is one day in the future, picked up from default LDAP Authenticator config
- note that the *start date* is set to the date of certificate issuance

.. code-block:: shell

    pvxcert -f ~/.config/pva/1.3/server.p12

.. code-block:: console

    Certificate Details:
    ============================================
    Certificate ID : b271f07a:13935791733272200197
    Entity Subject : CN=softioc, O=epics.org
    Issuer Subject : CN=EPICS Root Certificate Authority, C=US, O=certs.epics.org, OU=EPICS Certificate Authority
    Valid From     : Mon Mar 10 12:48:26 2025 UTC
    Expires On     : Tue Mar 10 12:48:26 2026 UTC
    --------------------------------------------

    Certificate Status:
    ============================================
    Certificate ID: b271f07a:13935791733272200197
    Status        : VALID
    Status Issued : Mon Mar 10 12:49:37 2025 UTC
    Status Expires: Mon Mar 10 13:19:37 2025 UTC
    --------------------------------------------

|5| Run Secure PVAccess Service
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- start the service

.. code-block:: shell

    softIocPVX \
        -m user=test,N=tst,P=tst \
        -d ${PROJECT_HOME}/pvxs/test/testioc.db \
        -d ${PROJECT_HOME}/pvxs/test/testiocg.db \
        -d ${PROJECT_HOME}/pvxs/test/image.db \
        -G ${PROJECT_HOME}/pvxs/test/image.json \
        -a ${PROJECT_HOME}/pvxs/test/testioc.acf

.. code-block:: console

    INFO: PVXS QSRV2 is loaded, permitted, and ENABLED.
    2025-03-10T12:51:26.189013708 WARN pvxs.tcp.init Server unable to bind TCP port 5075, falling back to [::]:38601
    2025-03-10T12:51:26.189087208 WARN pvxs.tcp.init Server unable to bind TLS port 5076, falling back to [::]:37623
    Starting iocInit
    ############################################################################
    ## EPICS R7.0.8.2-DEV
    ## Rev. R7.0.8.1-123-g48607a42586b1a316cd6
    ## Rev. Date Git: 2024-11-29 17:08:28 +0000
    ############################################################################
    iocRun: All initialization complete
    epics>

.. _spva_qs_ldap_client:

|step| SPVA Client
------------------------------------------

|1| Login as client in a new shell
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\³

.. code-block:: shell

    docker exec -it --user client spva_ldap /bin/bash

|2| Verify LDAP config
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- read out entry for client from LDAP directory

.. code-block:: shell

    ldapsearch -x -LLL -b "ou=People,dc=epics,dc=org" "(uid=client)"

.. code-block:: console

    dn: uid=client,ou=People,dc=epics,dc=org
    objectClass: inetOrgPerson
    objectClass: posixAccount
    objectClass: shadowAccount
    objectClass: epicsAuxiliary
    cn: client
    sn: client
    uid: client
    uidNumber: 1004
    gidNumber: 1004
    homeDirectory: /home/client
    loginShell: /bin/bash

.. code-block:: shell

    ldapsearch -x -LLL -b "ou=People,dc=epics,dc=org" "(uid=client)"

.. code-block:: console

    dn: cn=client,ou=Groups,dc=epics,dc=org
    objectClass: posixGroup
    cn: client
    gidNumber: 1004
    memberUid: client

|3| Get Certificate
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- create a client certificate.  Enter "secret" when prompted for a password

  - creates a client certificate
  - at location specified by ``EPICS_PVA_TLS_KEYCHAIN`` or ``${XDG_CONFIG_HOME}/pva/1.3/client.p12`` by default

.. code-block:: shell

    authnldap

.. code-block:: console

    Enter password for client@epics.org:
    Keychain file created   : /home/client/.config/pva/1.3/client.p12
    Certificate identifier  : b271f07a:4841285184560088877

|4| Check the certificate status is VALID
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- check that the generated certificate is ``VALID``
- note that the *name* is ``client`` - verified against LDAP
- note that the *organization* is ``epics.org`` - picked up from LDAP
- note that the *expiration date* is one day in the future, picked up from default LDAP Authenticator config
- note that the *start date* is set to the date of certificate issuance

.. code-block:: shell

    pvxcert -f ~/.config/pva/1.3/client.p12

.. code-block:: console

    Certificate Details:
    ============================================
    Certificate ID : b271f07a:1204731550645534180
    Entity Subject : CN=client, O=EPICS.ORG
    Issuer Subject : CN=EPICS Root Certificate Authority, C=US, O=certs.epics.org, OU=EPICS Certificate Authority
    Valid From     : Mon Mar 10 03:32:57 2025 UTC
    Expires On     : Tue Mar 11 03:30:32 2025 UTC
    --------------------------------------------

    Certificate Status:
    ============================================
    Certificate ID: b271f07a:1204731550645534180
    Status        : VALID
    Status Issued : Mon Mar 10 03:33:58 2025 UTC
    Status Expires: Mon Mar 10 04:03:58 2025 UTC
    --------------------------------------------

|5| Test TLS client operations
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

    pvxget -F tree test:structExample

.. code-block:: console

    test:structExample
    ...

- show that TLS is being used

.. code-block:: shell

    pvxinfo -v test:enumExample

.. code-block:: console

    Effective config
    EPICS_PVA_AUTO_ADDR_LIST=YES
    EPICS_PVA_BROADCAST_PORT=5076
    EPICS_PVA_CONN_TMO=30
    EPICS_PVA_SERVER_PORT=5075
    EPICS_PVA_TLS_KEYCHAIN=/home/client/.config/pva/1.3/client.p12
    EPICS_PVA_TLS_OPTIONS=on_expiration=fallback-to-tcp on_no_cms=fallback-to-tcp
    EPICS_PVA_TLS_PORT=5076
    XDG_CONFIG_HOME=/home/client/.config/pva/1.3
    XDG_DATA_HOME=/home/client/.local/share/pva/1.3
    # TLS x509:b271f07a:13935791733272200197:EPICS Root Certificate Authority/softioc@172.17.0.2:37623
    test:enumExample from 172.17.0.2:37623
    struct "epics:nt/NTEnum:1.0" {
        struct "enum_t" {
            int32_t index
            string[] choices
        } value
        struct "alarm_t" {
            int32_t severity
            int32_t status
            string message
        } alarm
        struct "time_t" {
            int64_t secondsPastEpoch
            int32_t nanoseconds
            int32_t userTag
        } timeStamp
        struct {
            string description
        } display
    }

.. note::

  - ``TLS x509:b271f07a:13935791733272200197:EPICS Root Certificate Authority/softioc @ 172.17.0.2`` indicates that:

    - The connection is ``TLS``,
    - The Server end of the channel has been authenticated by the Root Certificate Authority ``EPICS Root Certificate Authority``
    - The Server end of the channel's name has been authenticated as ``softioc`` and is connecting from host ``172.17.0.2``

