.. _quick_start_krb:

|guide| Quick Start KRB
==================================================

This section contains a Quick Start |guide| for the Secure PVAccess *Kerberos Authenticator*.

    The Kerberos Authenticator is an Authenticator that uses a kerberos ticket to create an X.509
    certificate.

    It takes the ``PRINCIPAL`` from the ticket and splits it up on '@' to extract the
    ``common name``, and ``organization`` for the certificate's
    subject while leaving the ``organizational unit`` blank.

    The information
    is sent to the PVACMS which validates that the request is authentic and the credentials
    correct by contacting the KDC.  If all checks-out then certificates are generated in the ``VALID`` state.

Our starting point for this Quick Start Guide is the end of the :ref:`quick_start_std` so if you haven't gone through it yet
do that now then come back here.  You need to have users's configured (``pvacms``, ``admin``, ``softioc``, and ``client``).
We will set up a containerised KDC and configure it so that the users can get tickets.  We will create
a pvacms Kerberos service and provide PVACMS a keytab for passwordless authentication so that it can verify CCRs presented
by clients requesting new certificates.

See :ref:`secure_pvaccess` for general documentation on Secure PVAccess.

Other Quick Start Guides:

- :ref:`quick_start`
- :ref:`quick_start_std`
- :ref:`quick_start_ldap`

|learn| You will learn:
******************************

- :ref:`Creating a containerised KDC <spva_qs_krb_kdc>`,
- :ref:`Building PVXS with Kerberos Authenticator support <spva_qs_krb_build>`,
- :ref:`Exporting pvacms keytab from KDC and configuring pvacms to use it <spva_qs_krb_pvacms>`,
- :ref:`Creating certificates using the Kerberos Authenticator<spva_qs_krb_server>` and
- :ref:`Connecting a Kerberos Client to an SPVA Server<spva_qs_krb_client>`

|pre-packaged|\Prepackaged
******************************

If you want a prepackaged environment, try the following.  You will need three terminal sessions.

|1| Load image
------------------------------

- |terminal|\¹
- start new container with Prepackaged Secure PVAccess with Kerberos Authenticator and 4 Users

.. code-block:: shell

    docker run -it --name spva_krb georgeleveln/spva_krb:latest

.. code-block:: console

    2025-03-08 14:40:43,319 CRIT Supervisor is running as root.  Privileges were not dropped because no user is specified in the config file.  If you intend to run as root, you can set user=root in the config file to avoid this message.
    2025-03-08 14:40:43,319 INFO Included extra file "/etc/supervisor/conf.d/kadmind.conf" during parsing
    2025-03-08 14:40:43,319 INFO Included extra file "/etc/supervisor/conf.d/krb5kdc.conf" during parsing
    2025-03-08 14:40:43,319 INFO Included extra file "/etc/supervisor/conf.d/pvacms.conf" during parsing
    2025-03-08 14:40:43,322 INFO supervisord started with pid 1
    2025-03-08 14:40:44,334 INFO spawned: 'krb5-admin-server' with pid 7
    2025-03-08 14:40:44,338 INFO spawned: 'krb5-kdc' with pid 8
    2025-03-08 14:40:44,346 INFO spawned: 'pvacms' with pid 9
    2025-03-08 14:40:45,589 INFO success: krb5-admin-server entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
    2025-03-08 14:40:45,589 INFO success: krb5-kdc entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
    2025-03-08 14:40:45,589 INFO success: pvacms entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)

|2| Service
------------------------------

- |terminal|\²
- log in as softioc service account

.. code-block:: shell

    docker exec -it --user softioc spva_krb /bin/bash

- get a kerberos ticket.  Enter "secret" as the password when prompted

.. code-block:: shell

    kinit

.. code-block:: console

    Password for softioc@EPICS.ORG:

.. code-block:: shell

    klist

.. code-block:: console

    Ticket cache: FILE:/tmp/krb5cc_1003
    Default principal: softioc@EPICS.ORG

    Valid starting     Expires            Service principal
    03/08/25 15:23:09  03/09/25 15:23:09  krbtgt/EPICS.ORG@EPICS.ORG
    	renew until 03/08/25 15:23:09
    03/08/25 15:23:21  03/09/25 15:23:09  pvacms/cluster@EPICS.ORG
    	renew until 03/08/25 15:23:09

- create a server certificate using the Kerberos Authenticator

.. code-block:: shell

    authnkrb -u server

.. code-block:: console

    Keychain file created   : /home/softioc/.config/pva/1.3/server.p12
    Certificate identifier  : 47530d89:3826361579604613181

.. code-block:: shell

    pvxcert -f ~/.config/pva/1.3/server.p12

.. code-block:: console

    Certificate Details:
    ============================================
    Certificate ID : 47530d89:3826361579604613181
    Entity Subject : CN=softioc, O=EPICS.ORG
    Issuer Subject : CN=EPICS Root Certificate Authority, C=US, O=certs.epics.org, OU=EPICS Certificate Authority
    Valid From     : Sat Mar 08 15:23:21 2025 UTC
    Expires On     : Sun Mar 09 15:23:09 2025 UTC
    --------------------------------------------

    Certificate Status:
    ============================================
    Certificate ID: 47530d89:3826361579604613181
    Status        : VALID
    Status Issued : Sat Mar 08 15:47:14 2025 UTC
    Status Expires: Sat Mar 08 16:17:14 2025 UTC
    --------------------------------------------

|3| Client
------------------------------

- |terminal|\³
- log in as a Secure PVAccess client

.. code-block:: shell

    docker exec -it --user client spva_krb /bin/bash

- get a kerberos ticket.  Enter "secret" as the password when prompted

.. code-block:: shell

    kinit

.. code-block:: console

    Password for client@EPICS.ORG:

.. code-block:: shell

    klist

.. code-block:: console

    Ticket cache: FILE:/tmp/krb5cc_1004
    Default principal: client@EPICS.ORG

    Valid starting     Expires            Service principal
    03/08/25 15:27:50  03/09/25 15:27:50  krbtgt/EPICS.ORG@EPICS.ORG
    	renew until 03/08/25 15:27:50

- create a client certificate using the Kerberos Authenticator

.. code-block:: shell

    authnkrb

.. code-block:: console

    Keychain file created   : /home/client/.config/pva/1.3/client.p12
    Certificate identifier  : 47530d89:15177030356392297708

.. code-block:: shell

    pvxcert -f ~/.config/pva/1.3/client.p12

.. code-block:: console

    Certificate Details:
    ============================================
    Certificate ID : 47530d89:15177030356392297708
    Entity Subject : CN=client, O=EPICS.ORG
    Issuer Subject : CN=EPICS Root Certificate Authority, C=US, O=certs.epics.org, OU=EPICS Certificate Authority
    Valid From     : Sat Mar 08 15:31:44 2025 UTC
    Expires On     : Sun Mar 09 15:27:50 2025 UTC
    --------------------------------------------

    Certificate Status:
    ============================================
    Certificate ID: 47530d89:15177030356392297708
    Status        : VALID
    Status Issued : Sat Mar 08 15:40:20 2025 UTC
    Status Expires: Sat Mar 08 16:10:20 2025 UTC
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
    2025-03-08T15:36:11.265341125 WARN pvxs.tcp.init Server unable to bind TCP port 5075, falling back to [::]:39377
    2025-03-08T15:36:11.265436375 WARN pvxs.tcp.init Server unable to bind TLS port 5076, falling back to [::]:34381
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
    # TLS x509:47530d89:3826361579604613181:EPICS Root Certificate Authority/softioc@172.17.0.2:34381
    test:enumExample from 172.17.0.2:34381
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

- ``TLS x509:47530d89:3826361579604613181:EPICS Root Certificate Authority/softioc @ 172.17.0.2`` indicates that:

  - The connection is ``TLS``,
  - The Server end of the channel has been authenticated by the Root Certificate Authority ``EPICS Root Certificate Authority``
  - The Server end of the channel's name has been authenticated as ``softioc`` and is connecting from host ``172.17.0.2``

|step-by-step| Step-By-Step
********************************

+----------------------+---------------------+--------------------------+----------------------+--------------------------------------+-----------------------------------------------------------------------+
| Env. *authnkrb*      | Env. *pvacms*       | Params. *authkrb*        | Params. *pvacms*     | Keys and Values                      | Description                                                           |
+======================+=====================+==========================+======================+======================================+=======================================================================+
||                     || KRB5_KTNAME        ||                         || ``--krb-keytab``    || {string location of keytab file}    || This is the keytab file shared with :ref:`pvacms` by the KDC so      |
||                     ||                    ||                         ||                     || e.g. ``/etc/security/keytab``       || that it can verify kerberos tickets                                  |
||                     +---------------------+|                         ||                     ||                                     ||                                                                      |
||                     || KRB5_CLIENT_KTNAME ||                         ||                     ||                                     ||                                                                      |
||                     ||                    ||                         ||                     ||                                     ||                                                                      |
+----------------------+---------------------+--------------------------+----------------------+--------------------------------------+-----------------------------------------------------------------------+
|| EPICS_AUTH_KRB_VALIDATOR_SERVICE          || ``--krb-validator``                            || {this is validator service name}    || The name of the service user created in the KDC that the pvacms      |
||                                           ||                                                || e.g. ``pvacms``                     || service will log in as.  `/cluster@{realm}` will be added            |
+--------------------------------------------+-------------------------------------------------+--------------------------------------+-----------------------------------------------------------------------+
|| EPICS_AUTH_KRB_REALM                      || ``--krb-realm``                                || e.g. ``EPICS.ORG``                  || Kerberos REALM to authenticate against                               |
+--------------------------------------------+-------------------------------------------------+--------------------------------------+-----------------------------------------------------------------------+


|step| Docker Image
------------------------------------------

|1| Use a Prepackaged spva_std image
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\¹
- open a terminal and load pre-built image
- don't forget to add /bin/bash at the end to suppress running the pvacms

.. code-block:: shell

    docker run -it --name spva_krb georgeleveln/spva_std:latest /bin/bash

.. _spva_qs_krb_kdc:

|step| KDC & KAdmin
------------------------------------------

This section shows how to install and configure a Kerberos KDC and kadmin.  This
is included to enable you to test the Kerberos Authenticator before deploying it
into your network.  It will enable you to configure EPICS agents that
have valid kerberos tickets that can be exchanged for X.509 certificates
using the Kerberos Authenticator.


|1| Install prerequisites
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Add kerberos dependencies

  - krb5 admin server (kadmin)
  - krb5 KDC
  - libkrb5 development library for compiling pvxs with Kerberos Authenticator support

.. code-block:: shell

    apt-get update && \
    apt-get -y install \
            --no-install-recommends \
            krb5-admin-server \
            krb5-kdc \
            libkrb5-dev

.. code-block:: console

    Hit:1 http://ports.ubuntu.com/ubuntu-ports noble InRelease
    Get:2 http://ports.ubuntu.com/ubuntu-ports noble-updates InRelease [126 kB]
    Get:3 http://ports.ubuntu.com/ubuntu-ports noble-backports InRelease [126 kB]
    Get:4 http://ports.ubuntu.com/ubuntu-ports noble-security InRelease [126 kB]
    ...
    invoke-rc.d: policy-rc.d denied execution of start.
    Setting up krb5-admin-server (1.20.1-6ubuntu2.5) ...
    invoke-rc.d: could not determine current runlevel
    invoke-rc.d: policy-rc.d denied execution of start.
    Processing triggers for libc-bin (2.39-0ubuntu8.4) ...

.. _spva_qs_krb_build:

|2| Rebuild pvxs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- enable Kerberos Authenticator by updating ``CONFIG_SITE.local``
- do a clean rebuild of pvxs

.. code-block:: shell

    export PROJECT_HOME=/opt/epics
    cd ${PROJECT_HOME}

    cat >> CONFIG_SITE.local <<EOF
    EVENT2_HAS_OPENSSL = YES
    PVXS_ENABLE_PVACMS = YES
    PVXS_ENABLE_KRB_AUTH = YES
    EOF

    cd pvxs && \
    make distclean && make -j10 all

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
    rm -rf O.*
    make[1]: Leaving directory '/opt/epics/pvxs/tools'
    ...
    /usr/bin/g++ -o testtlswithcms  -L/opt/epics/epics-base/lib/linux-aarch64 -L/opt/epics/pvxs/lib/linux-aarch64 -Wl,-rpath,/opt/epics/epics-base/lib/linux-aarch64 -Wl,-rpath,/opt/epics/pvxs/lib/linux-aarch64     -Wl,--as-needed -Wl,--compress-debug-sections=zlib      -rdynamic         testtlswithcms.o certstatusfactory.o certstatusmanager.o certstatus.o    -lpvxs -lCom  -levent_openssl -levent_core -levent_pthreads -lssl -lcrypto
    perl -CSD /opt/epics/epics-base/bin/linux-aarch64/makeTestfile.pl linux-aarch64 linux-aarch64 testtlswithcms.t testtlswithcms
    make[2]: Leaving directory '/opt/epics/pvxs/test/O.linux-aarch64'
    make[1]: Leaving directory '/opt/epics/pvxs/test'


|3| Configure KDC and KAdmin
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- configure the KDC

  - set standard ports (as its in the container it won't interact with your local network)
  - define the realm as ``EPICS.ORG``

.. code-block:: shell

    cat > /etc/krb5kdc/kdc.conf <<EOF
    [kdcdefaults]
    kdc_ports = 88,750
    kdc_tcp_ports = 88
    kadmind_port = 749
    kpasswd_port = 464

    [realms]
        EPICS.ORG = {
            dict_file = /etc/krb5kdc/badpass.txt
            kdc_ports = 88,750
            kdc_tcp_ports = 88
            kadmind_port = 749
            kpasswd_port = 464
        }

    [logging]
    default = FILE:/var/log/krb5kdc.log
    admin_server = FILE:/var/log/kadmin.log
    EOF

- set kadmin access control list

  - set administrator user to ``admin@EPICS.ORG``

.. code-block:: shell

    cat > /etc/krb5kdc/kadm5.acl <<EOF
    admin@EPICS.ORG *
    EOF

- set the KDC bad password file

.. code-block:: shell

    cat > /etc/krb5kdc/badpass.txt <<EOF
    password
    123456
    letmein
    admin
    kerberos
    EOF

|4| Configure Kerberos Users
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- set default kerberos user configuration

  - default realm ``EPICS.ORG``
  - don't lookup DNS (this is v.important)
  - ticket lifetime 1 day and renewable up to 1 week

.. code-block:: shell

    cat > /etc/krb5.conf <<EOF
    [libdefaults]
    default_realm = EPICS.ORG
    dns_lookup_kdc = false
    dns_lookup_realm = false
    dns_canonicalize_hostname = false
    forwardable = yes
    proxiable = yes
    ticket_lifetime = 24h
    renew_lifetime = 7d

    [realms]
    EPICS.ORG = {
        kdc = localhost:88
        admin_server = localhost:749
        kpasswd_server = localhost:464
        default_domain = epics.org
    }

    [domain_realm]
        .epics.org = EPICS.ORG
        epics.org = EPICS.ORG
    EOF

.. _spva_qs_krb_pvacms:

|5| Make and Install Keytab for PVACMS
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- establish master password for kerberos database

.. code-block:: shell

    kdb5_util create -s -P secret

.. code-block:: console

    Initializing database '/var/lib/krb5kdc/principal' for realm 'EPICS.ORG',
    master key name 'K/M@EPICS.ORG'

- start KDC and kadmin server temporarily to allow creation of various principals

.. code-block:: shell

    service krb5-kdc start && \
    service krb5-admin-server start

.. code-block:: console

     * Starting Kerberos KDC krb5kdc                      [ OK ]
     * Starting Kerberos administrative servers kadmind   [ OK ]

- create kerberos principals

  - ``admin`` user
  - ``pvacms/cluster`` user

    - note that this is created as a user (not a service)
    - allocated a random password which is exported to the keytab and shared with pvacms user

  - ``softioc`` user allowed to act as a server
  - ``client`` user

.. code-block:: shell

    kadmin.local -q 'addprinc -pw secret -allow_svr admin' && \
    kadmin.local -q 'addprinc -randkey pvacms/cluster@EPICS.ORG' && \
    kadmin.local -q 'addprinc -pw secret -allow_svr softioc' && \
    kadmin.local -q 'addprinc -pw secret client'

.. code-block:: console

    Authenticating as principal root/admin@EPICS.ORG with password.
    No policy specified for admin@EPICS.ORG; defaulting to no policy
    Principal "admin@EPICS.ORG" created.
    Authenticating as principal root/admin@EPICS.ORG with password.
    No policy specified for pvacms/cluster@EPICS.ORG; defaulting to no policy
    Principal "pvacms/cluster@EPICS.ORG" created.
    Authenticating as principal root/admin@EPICS.ORG with password.
    No policy specified for softioc@EPICS.ORG; defaulting to no policy
    Principal "softioc@EPICS.ORG" created.
    Authenticating as principal root/admin@EPICS.ORG with password.
    No policy specified for client@EPICS.ORG; defaulting to no policy
    Principal "client@EPICS.ORG" created.

- export the pvacms keytab that will allow it to log in without a password
- copy it to the pvacms configuration directory and lock down access to it

.. code-block:: shell

    kadmin.local -q 'ktadd -k /home/pvacms/.config/krb5/pvacms.keytab pvacms/cluster@EPICS.ORG' && \
    chown pvacms:pvacms /home/pvacms/.config/krb5/pvacms.keytab && \
    chmod 600 /home/pvacms/.config/krb5/pvacms.keytab

.. code-block:: console

    Authenticating as principal root/admin@EPICS.ORG with password.
    Entry for principal pvacms/cluster@EPICS.ORG with kvno 2, encryption type aes256-cts-hmac-sha1-96 added to keytab WRFILE:/home/pvacms/.config/krb5/pvacms.keytab.
    Entry for principal pvacms/cluster@EPICS.ORG with kvno 2, encryption type aes128-cts-hmac-sha1-96 added to keytab WRFILE:/home/pvacms/.config/krb5/pvacms.keytab.

|6| Configure PVACMS for Kerberos Authenticator
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- set up environment for pvacms

  - location of keytab file.  Note that this uses the krb5 environment variable, not a Secure PVAccess specific one
  - default realm name ``EPICS.ORG``

.. code-block:: shell

    cat >> /home/pvacms/.bashrc <<EOF
    export KRB5_KTNAME=/home/pvacms/.config/krb5/pvacms.keytab
    export KRB5_CLIENT_KTNAME=/home/pvacms/.config/krb5/pvacms.keytab
    export EPICS_AUTH_KRB_REALM=EPICS.ORG
    EOF


|7| Configure Supervisor to run KDC and KAdmin
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- configure kadmin supervisord

.. code-block:: shell

    cat > /etc/supervisor/conf.d/kadmind.conf <<EOF
    [program:krb5-admin-server]
    command=/usr/sbin/kadmind -nofork
    autostart=true
    autorestart=true
    stderr_logfile=/var/log/supervisor/kadmind.err.log
    stdout_logfile=/var/log/supervisor/kadmind.out.log
    EOF

- configure KDC supervisord

.. code-block:: shell

    cat > /etc/supervisor/conf.d/krb5kdc.conf <<EOF
    [program:krb5-kdc]
    command=/usr/sbin/krb5kdc -n
    autostart=true
    autorestart=true
    stderr_logfile=/var/log/supervisor/krb5kdc.err.log
    stdout_logfile=/var/log/supervisor/krb5kdc.out.log
    EOF


|8| Start Services
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- make sure config dir exists in pvacms home before starting service

.. code-block:: shell

    mkdir -p /home/pvacms/.config/krb5/

- update pvacms supervisor config to include Kerberos Authenticator configuration

.. code-block:: shell

    cat >> /etc/supervisor/conf.d/pvacms.conf <<EOF
    environment=KRB5_KTNAME="/home/pvacms/.config/krb5/pvacms.keytab",KRB5_CLIENT_KTNAME="/home/pvacms/.config/krb5/pvacms.keytab",EPICS_AUTH_KRB_REALM="EPICS.ORG"
    EOF

- start KDC, kadmin daemon, and pvacms with Kerberos Authenticator support

.. code-block:: shell

    /usr/bin/supervisord -c /etc/supervisor/supervisord.conf

.. code-block:: console

    2025-03-10 02:31:38,694 INFO Included extra file "/etc/supervisor/conf.d/kadmind.conf" during parsing
    2025-03-10 02:31:38,694 INFO Included extra file "/etc/supervisor/conf.d/krb5kdc.conf" during parsing
    2025-03-10 02:31:38,694 INFO Included extra file "/etc/supervisor/conf.d/pvacms.conf" during parsing
    2025-03-10 02:31:38,694 INFO Set uid to user 0 succeeded
    2025-03-10 02:31:38,695 INFO supervisord started with pid 2275
    2025-03-10 02:31:39,708 INFO spawned: 'krb5-admin-server' with pid 2276
    2025-03-10 02:31:39,711 INFO spawned: 'krb5-kdc' with pid 2277
    2025-03-10 02:31:39,719 INFO spawned: 'pvacms' with pid 2278
    2025-03-10 02:31:40,825 INFO success: krb5-admin-server entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
    2025-03-10 02:31:40,825 INFO success: krb5-kdc entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
    2025-03-10 02:31:40,825 INFO success: pvacms entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)

.. _spva_qs_krb_server:

|step| Run SoftIOC
------------------------------------------

|1| Login as softioc in a new shell
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\²

.. code-block:: shell

    docker exec -it --user softioc spva_krb /bin/bash

|3| kerberos login
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- do a kerberos login to get a kerberos ticket.  Enter "secret" as the password when prompted

.. code-block:: shell

    kinit

.. code-block:: console

    Password for softioc@EPICS.ORG:

.. code-block:: shell

    klist

.. code-block:: console

    Ticket cache: FILE:/tmp/krb5cc_1003
    Default principal: softioc@EPICS.ORG

    Valid starting     Expires            Service principal
    03/10/25 03:16:25  03/11/25 03:16:25  krbtgt/EPICS.ORG@EPICS.ORG
    	renew until 03/10/25 03:16:25

|3| Get Certificate
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- create a softioc server certificate

  - creates softioc server certificate
  - at location specified by ``EPICS_PVAS_TLS_KEYCHAIN`` or ``${XDG_CONFIG_HOME}/pva/1.3/server.p12`` by default

.. code-block:: shell

    authnkrb -u server

.. code-block:: console

    Keychain file created   : /home/softioc/.config/pva/1.3/server.p12
    Certificate identifier  : b271f07a:12421554925305118824

|4| Check the certificate status is VALID
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- check that the generated certificate is ``VALID``
- note that the *name* is ``softioc`` - picked up from ``principal`` in kerberos ticket
- note that the *organization* is ``EPICS.ORG`` - picked up from ``REALM`` in kerberos ticket
- note that the *expiration date* is the same as the expiration of the kerberos ticket
- note that the *start date* is set to the date of certificate issuance

.. code-block:: shell

    pvxcert -f ~/.config/pva/1.3/server.p12

.. code-block:: console

    Certificate Details:
    ============================================
    Certificate ID : b271f07a:12421554925305118824
    Entity Subject : CN=softioc, O=EPICS.ORG
    Issuer Subject : CN=EPICS Root Certificate Authority, C=US, O=certs.epics.org, OU=EPICS Certificate Authority
    Valid From     : Mon Mar 10 03:20:05 2025 UTC
    Expires On     : Tue Mar 11 03:16:25 2025 UTC
    --------------------------------------------

    Certificate Status:
    ============================================
    Certificate ID: b271f07a:12421554925305118824
    Status        : VALID
    Status Issued : Mon Mar 10 03:22:14 2025 UTC
    Status Expires: Mon Mar 10 03:52:14 2025 UTC
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
    2025-03-10T03:28:17.264206926 WARN pvxs.tcp.init Server unable to bind TCP port 5075, falling back to [::]:46831
    2025-03-10T03:28:17.264284426 WARN pvxs.tcp.init Server unable to bind TLS port 5076, falling back to [::]:37027
    Starting iocInit
    ############################################################################
    ## EPICS R7.0.8.2-DEV
    ## Rev. R7.0.8.1-123-g48607a42586b1a316cd6
    ## Rev. Date Git: 2024-11-29 17:08:28 +0000
    ############################################################################
    iocRun: All initialization complete
    epics>

.. _spva_qs_krb_client:

|step| SPVA Client
------------------------------------------

|1| Login as client in a new shell
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\³

.. code-block:: shell

    docker exec -it --user client spva_krb /bin/bash


|2| kerberos login
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- do a kerberos login to get a kerberos ticket.  Enter "secret" as the password when prompted

.. code-block:: shell

    kinit

.. code-block:: console

    Password for client@EPICS.ORG:

.. code-block:: shell

    klist

.. code-block:: console

    Ticket cache: FILE:/tmp/krb5cc_1004
    Default principal: client@EPICS.ORG

    Valid starting     Expires            Service principal
    03/10/25 03:30:32  03/11/25 03:30:32  krbtgt/EPICS.ORG@EPICS.ORG
    	renew until 03/10/25 03:30:32


|3| Get Certificate
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- create a client certificate

  - creates a client certificate
  - at location specified by ``EPICS_PVA_TLS_KEYCHAIN`` or ``${XDG_CONFIG_HOME}/pva/1.3/client.p12`` by default

.. code-block:: shell

    authnkrb

.. code-block:: console

    Keychain file created   : /home/client/.config/pva/1.3/client.p12
    Certificate identifier  : b271f07a:1204731550645534180

|4| Check the certificate status is VALID
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- check that the generated certificate is ``VALID``
- note that the *name* is ``client`` - picked up from ``principal`` in kerberos ticket
- note that the *organization* is ``EPICS.ORG`` - picked up from ``REALM`` in kerberos ticket
- note that the *expiration date* is the same as the expiration of the kerberos ticket
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
    # TLS x509:b271f07a:12421554925305118824:EPICS Root Certificate Authority/softioc@172.17.0.2:37027
    test:enumExample from 172.17.0.2:37027
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

  - ``TLS x509:b271f07a:12421554925305118824:EPICS Root Certificate Authority/softioc @ 172.17.0.2`` indicates that:

    - The connection is ``TLS``,
    - The Server end of the channel has been authenticated by the Root Certificate Authority ``EPICS Root Certificate Authority``
    - The Server end of the channel's name has been authenticated as ``softioc`` and is connecting from host ``172.17.0.2``


