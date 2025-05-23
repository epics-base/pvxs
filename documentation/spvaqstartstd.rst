.. _quick_start_std:

|guide| Quick Start Std
========================================

This section contains a Quick Start |guide| for the Secure PVAccess *Standard Authenticator*.

    Standard Authenticator is the default form of authentication supported by Secure PVAccess.
    It takes the ``username``, ``organization``, ``organizational unit``, and ``country`` and uses them,
    without verification, to create X.509 certificates.  These certificates are generated in the ``PENDING_APPROVAL`` state, so
    an SPVA network Administrator needs to ``APPROVE`` them before they will work.

Our starting point for this Quick Start Guide is the end of the :ref:`quick_start` so if you haven't gone through it yet
do that now then come back here.  The main difference here is that we'll create users for the different
roles we'll be testing.

Other Quick Start Guides:

- :ref:`quick_start`
- :ref:`quick_start_krb`
- :ref:`quick_start_ldap`

|learn| You will learn
*********************************

- :ref:`Configuring a Secure PVAccess network administrator<spva_qs_std_admin>`
- Configuration of EPICS agents: :ref:`Client<spva_qs_std_client>` and :ref:`Server<spva_qs_std_server>`
- :ref:`Creating Certificates using the Standard Authenticator<spva_qs_std_create_cert>`

|pre-packaged|\Prepackaged
************************************

If you want a prepackaged environment, try the following.  You will need four terminal sessions.


|1| Load image
-------------------------------------
- |terminal|\¹
- start new container with Prepackaged Secure PVAccess and 4 Users
.. code-block:: shell

    docker run -it --name spva_std georgeleveln/spva_std:latest

.. code-block:: console

    2025-03-04 20:41:23,799 INFO Included extra file "/etc/supervisor/conf.d/pvacms.conf" during parsing
    2025-03-04 20:41:23,802 INFO supervisord started with pid 1
    2025-03-04 20:41:24,820 INFO spawned: 'pvacms' with pid 7
    2025-03-04 20:41:25,957 INFO success: pvacms entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)

|2| Administrator
-------------------------------------
- |terminal|\²
- log in as pre-configured Admin User, certificate is already configured
.. code-block:: shell

    docker exec -it --user admin spva_std /bin/bash

.. code-block:: console

    To run a command as administrator (user "root"), use "sudo <command>".
    See "man sudo_root" for details.

|3| Service
-------------------------------------
- |terminal|\³
- log in as softioc service account
.. code-block:: shell

    docker exec -it --user softioc spva_std /bin/bash

- create a server certificate using the Standard Authenticator
.. code-block:: shell

    authnstd -u server

.. code-block:: console

    Keychain file created   : /home/softioc/.config/pva/1.3/server.p12
    Certificate identifier  : 47530d89:15756710596521133410

|4| Client
-------------------------------------
- |terminal|\⁴
- log in as a Secure PVAccess client
.. code-block:: shell

    docker exec -it --user client spva_std /bin/bash

- create a client certificate using the Standard Authenticator
.. code-block:: shell

    authnstd

.. code-block:: console

    Keychain file created   : /home/client/.config/pva/1.3/client.p12
    Certificate identifier  : 47530d89:7450074183745406049


|5| Approve Certs
-------------------------------------
- |terminal|\²
- approve the server certificate
.. code-block:: shell

    pvxcert --approve 47530d89:15756710596521133410

.. code-block:: console

    Approve ==> CERT:STATUS:47530d89:15756710596521133410 ==> Completed Successfully

- approve the client certificate
.. code-block:: shell

    pvxcert --approve 47530d89:7450074183745406049

.. code-block:: console

    Approve ==> CERT:STATUS:47530d89:7450074183745406049 ==> Completed Successfully


|6| Start SoftIOC
-------------------------------------
- |terminal|\³
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
    2025-03-04T20:51:56.413890180 WARN pvxs.tcp.init Server unable to bind TCP port 5075, falling back to [::]:41807
    2025-03-04T20:51:56.413970847 WARN pvxs.tcp.init Server unable to bind TLS port 5076, falling back to [::]:33809
    Starting iocInit
    ############################################################################
    ## EPICS R7.0.8.2-DEV
    ## Rev. R7.0.8.1-123-g48607a42586b1a316cd6
    ## Rev. Date Git: 2024-11-29 17:08:28 +0000
    ############################################################################
    iocRun: All initialization complete
    epics>

|7| Get PV value
-------------------------------------
- |terminal|\⁴
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
    # TLS x509:47530d89:7450074183745406049:EPICS Root Certificate Authority/softioc@172.17.0.2:33809
    test:enumExample from 172.17.0.2:33809
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

  - ``TLS x509:47530d89:7450074183745406049:EPICS Root Certificate Authority/softioc @ 172.17.0.2`` indicates that:

    - The connection is ``TLS``,
    - The Server end of the channel has been authenticated by the Root Certificate Authority ``EPICS Root Certificate Authority``
    - The Server end of the channel's name has been authenticated as ``softioc`` and is connecting from host ``172.17.0.2``

|step-by-step| Step-By-Step
********************************

|step| Docker Image
------------------------------------------

|1| Use a Prepackaged pvxs image compiled with TLS enabled
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\¹
- open a terminal and load pre-built image

.. code-block:: shell

    docker run -it --name spva_std georgeleveln/pvxs:latest


|step| EPICS Agents
-------------------------------------

This section shows you what basic configuration you'll need for each type of EPICS agent.
Look at the environment variable settings and the file locations referenced by
this configuration to understand how to configure EPICS agents in
your environment.


|1| Set up environment
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

    export XDG_DATA_HOME=${XDG_DATA_HOME-~/.local/share}
    export XDG_CONFIG_HOME=${XDG_CONFIG_HOME-~/.config}
    export PVXS_HOST_ARCH=$(${PROJECT_HOME}/epics-base/startup/EpicsHostArch)
    export PATH="${PROJECT_HOME}/pvxs/bin/${PVXS_HOST_ARCH}:$PATH"


.. _spva_qs_std_admin:

|2| Add PVACMS
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- add user and when prompted use "PVACMS" as Full Name

.. code-block:: shell

    adduser pvacms

.. code-block:: console

    info: Adding user `pvacms' ...
    info: Selecting UID/GID from range 1000 to 59999 ...
    info: Adding new group `pvacms' (1001) ...
    info: Adding new user `pvacms' (1001) with group `pvacms (1001)' ...
    info: Creating home directory `/home/pvacms' ...
    info: Copying files from `/etc/skel' ...
    New password:
    Retype new password:
    passwd: password updated successfully
    Changing the user information for pvacms
    Enter the new value, or press ENTER for the default
    	Full Name []: PVACMS
    	Room Number []:
    	Work Phone []:
    	Home Phone []:
    	Other []:
    Is the information correct? [Y/n]
    info: Adding new user `pvacms' to supplemental / extra groups `users' ...
    info: Adding user `pvacms' to group `users' ...

- set up environment for pvacms

.. code-block:: shell

    su - pvacms

.. code-block:: shell

    cat >> ~/.bashrc <<EOF
    export XDG_DATA_HOME=\${XDG_DATA_HOME-~/.local/share}
    export XDG_CONFIG_HOME=\${XDG_CONFIG_HOME-~/.config}
    export PROJECT_HOME=/opt/epics
    export PATH="\$(echo \${PROJECT_HOME}/pvxs/bin/*):$PATH"
    cd ~
    EOF

    exit

.. code-block:: console

    logout

log back in as pvacms with environment set by ``.bashrc``

.. code-block:: shell

    su - pvacms

- create admin certificate:

  - create PVACMS certificate database

    - creates database if does not exist
    - at location pointed to by ``EPICS_PVACMS_DB`` or ``${XDG_DATA_HOME}/pva/1.3/certs.db`` by default

  - creates root Certificate Authority certificate if does not exist

    - creates root Certificate Authority certificate if does not exist,
    - at location specified by ``EPICS_CERT_AUTH_TLS_KEYCHAIN`` or ``${XDG_CONFIG_HOME}/pva/1.3/cert_auth.p12`` by default
    - with ``CN`` specified by ``EPICS_CERT_AUTH_NAME``
    - with  ``O`` specified by ``EPICS_CERT_AUTH_ORGANIZATION``
    - with ``OU`` specified by ``EPICS_CERT_AUTH_ORGANIZATIONAL_UNIT``
    - with  ``C`` specified by ``EPICS_CERT_AUTH_COUNTRY``

  - create the default ACF file that controls permissions for the PVACMS service

    - creates default ACF (or yaml) file
    - at location pointed to by ``EPICS_PVACMS_ACF`` or ``${XDG_CONFIG_HOME}/pva/1.3/pvacms.acf`` by default

  - create the default admin client certificate that can be used to access PVACMS admin functions like ``REVOKE`` and ``APPROVE``

    - creates default admin client certificate
    - at location specified by ``EPICS_ADMIN_TLS_KEYCHAIN`` or ``${XDG_CONFIG_HOME}/pva/1.3/admin.p12`` by default

.. code-block:: shell

    pvacms --admin-keychain-new admin

.. code-block:: console

    Certificate DB created  : /home/pvacms/.local/share/pva/1.3/certs.db
    Keychain file created   : /home/pvacms/.config/pva/1.3/cert_auth.p12
    Created Default ACF file: /home/pvacms/.config/pva/1.3/pvacms.acf
    Keychain file created   : /home/pvacms/.config/pva/1.3/admin.p12

.. code-block:: shell

    exit

.. code-block:: console

    logout

|3| Add an Administrator
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- add user and when prompted use "ADMIN User" as Full Name

.. code-block:: shell

    adduser admin

.. code-block:: console

    info: Adding user `admin' ...
    info: Selecting UID/GID from range 1000 to 59999 ...
    info: Adding new group `admin' (1002) ...
    info: Adding new user `admin' (1002) with group `admin (1002)' ...
    info: Creating home directory `/home/admin' ...
    info: Copying files from `/etc/skel' ...
    New password:
    Retype new password:
    passwd: password updated successfully
    Changing the user information for admin
    Enter the new value, or press ENTER for the default
    	Full Name []: ADMIN User
    	Room Number []:
    	Work Phone []:
    	Home Phone []:
    	Other []:
    Is the information correct? [Y/n]
    info: Adding new user `admin' to supplemental / extra groups `users' ...
    info: Adding user `admin' to group `users' ...

- set up environment for administrator

.. code-block:: shell

    su - admin

.. code-block:: shell

    cat >> ~/.bashrc <<EOF
    export XDG_DATA_HOME=\${XDG_DATA_HOME-~/.local/share}
    export XDG_CONFIG_HOME=\${XDG_CONFIG_HOME-~/.config}
    export PROJECT_HOME=/opt/epics
    export PATH="\$(echo \${PROJECT_HOME}/pvxs/bin/*):$PATH"
    cd ~
    EOF

    exit

.. code-block:: console

    logout

- copy admin certificate from pvacms

.. code-block:: shell

    mkdir -p ~admin/.config/pva/1.3
    cp -pr ~pvacms/.config/pva/1.3/admin.p12 ~admin/.config/pva/1.3/client.p12
    chown admin ~admin/.config/pva/1.3/client.p12
    chmod 400 ~admin/.config/pva/1.3/client.p12

.. _spva_qs_std_server:

|4| Add a Secure PVAccess Server - SoftIOC
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- add user and when prompted use "SOFTIOC Server" as Full Name

.. code-block:: shell

    adduser softioc

.. code-block:: console

    info: Adding user `softioc' ...
    info: Selecting UID/GID from range 1000 to 59999 ...
    info: Adding new group `softioc' (1003) ...
    info: Adding new user `softioc' (1003) with group `softioc (1003)' ...
    info: Creating home directory `/home/softioc' ...
    info: Copying files from `/etc/skel' ...
    New password:
    Retype new password:
    passwd: password updated successfully
    Changing the user information for softioc
    Enter the new value, or press ENTER for the default
    	Full Name []: SOFTIOC Server
    	Room Number []:
    	Work Phone []:
    	Home Phone []:
    	Other []:
    Is the information correct? [Y/n]
    info: Adding new user `softioc' to supplemental / extra groups `users' ...
    info: Adding user `softioc' to group `users' ...

- set up environment for softioc server

.. code-block:: shell

    su - softioc

.. code-block:: shell

    cat >> ~/.bashrc <<EOF
    export XDG_DATA_HOME=\${XDG_DATA_HOME-~/.local/share}
    export XDG_CONFIG_HOME=\${XDG_CONFIG_HOME-~/.config}
    export PROJECT_HOME=/opt/epics
    export PATH="\$(echo \${PROJECT_HOME}/pvxs/bin/*):$PATH"
    cd ~
    EOF

    exit

.. code-block:: console

    logout

.. _spva_qs_std_client:

|5| Add a Secure PVAccess Client
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- add user and when prompted use "SPVA client" as Full Name

.. code-block:: shell

    adduser client

.. code-block:: console

    info: Adding user `client' ...
    info: Selecting UID/GID from range 1000 to 59999 ...
    info: Adding new group `client' (1004) ...
    info: Adding new user `client' (1004) with group `client (1004)' ...
    info: Creating home directory `/home/client' ...
    info: Copying files from `/etc/skel' ...
    New password:
    Retype new password:
    passwd: password updated successfully
    Changing the user information for client
    Enter the new value, or press ENTER for the default
    	Full Name []: SPVA client
    	Room Number []:
    	Work Phone []:
    	Home Phone []:
    	Other []:
    Is the information correct? [Y/n]
    info: Adding new user `client' to supplemental / extra groups `users' ...
    info: Adding user `client' to group `users' ...

- set up environment for client

.. code-block:: shell

    su - client

.. code-block:: shell

    cat >> ~/.bashrc <<EOF
    export XDG_DATA_HOME=\${XDG_DATA_HOME-~/.local/share}
    export XDG_CONFIG_HOME=\${XDG_CONFIG_HOME-~/.config}
    export PROJECT_HOME=/opt/epics
    export PATH="\$(echo \${PROJECT_HOME}/pvxs/bin/*):$PATH"
    cd ~
    EOF

    exit

.. code-block:: console

    logout


|step| Run PVACMS
---------------

|1| Login as pvacms in a new shell
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\²
- in a different terminal log in as the pvacms user in the same container:

.. code-block:: shell

    docker exec -it --user pvacms spva_std /bin/bash

|2| Run PVACMS
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- run pvacms:

  - create the pvacms server certificate

    - creates pvacms server certificate
    - at location specified by ``EPICS_PVACMS_TLS_KEYCHAIN`` or ``${XDG_CONFIG_HOME}/pva/1.3/pvacms.p12`` by default

  - start pvacms with verbose logging off

.. code-block:: shell

    pvacms

.. code-block:: console

    Keychain file created   : /home/pvacms/.config/pva/1.3/pvacms.p12
    PVACMS [46093d7c] Service Running

.. note::

    ``46093d7c`` is the issuer ID which is comprised of the first 8 characters
    of the hex Subject Key Identifier of the certificate authority certificate.  You will see this
    preceding all certificate identifiers from this PVACMS

Leave this PVACMS service running while running SoftIOC and SPVA client below.

.. _spva_qs_std_create_cert:

|step| Run SoftIOC
-------------------------------

|1| Login as softioc in a new shell
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\³

.. code-block:: shell

    docker exec -it --user softioc spva_std /bin/bash


|2| Create Server Certificate
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- create a softioc server certificate

  - creates softioc server certificate
  - at location specified by ``EPICS_PVAS_TLS_KEYCHAIN`` or ``${XDG_CONFIG_HOME}/pva/1.3/server.p12`` by default

.. code-block:: shell

    authnstd -u server \
      -n "IOC1" \
      -o "KLI:LI01:10" \
      --ou "FACET"

.. code-block:: console

    Keychain file created   : /home/softioc/.config/pva/1.3/server.p12
    Certificate identifier  : 46093d7c:13415272142438558829

.. note::

    Write down the certificate ID ``46093d7c:13415272142438558829`` (<issuer_id>:<serial_number>).
    You will need this ID to carry out operations on this certificate including APPROVING it.

|3| Verify that certificate is created pending approval
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- get the current status of a certificate

.. code-block:: shell

    pvxcert 46093d7c:13415272142438558829

.. code-block:: console

    Certificate Status:
    ============================================
    Certificate ID: 46093d7c:13415272142438558829
    Status        : PENDING_APPROVAL
    Status Issued : Sat Mar 08 12:31:11 2025 UTC
    Status Expires: Sat Mar 08 13:01:11 2025 UTC
    --------------------------------------------

|4| Login as admin in a new shell
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\⁴

.. code-block:: shell

    docker exec -it --user admin spva_std /bin/bash

|5| Approve certificate
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

    pvxcert --approve 46093d7c:13415272142438558829

.. code-block:: console

    Approve ==> CERT:STATUS:46093d7c:13415272142438558829 ==> Completed Successfully

|6| Check the certificate status has changed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

    pvxcert 46093d7c:13415272142438558829

.. code-block:: console

    Certificate Status:
    ============================================
    Certificate ID: 46093d7c:13415272142438558829
    Status        : VALID
    Status Issued : Sat Mar 08 12:31:50 2025 UTC
    Status Expires: Sat Mar 08 13:01:50 2025 UTC
    --------------------------------------------


|7| Run Secure PVAccess Service
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\³
- back in the server shell start the service

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
    2025-03-08T12:32:06.263544555 WARN pvxs.tcp.init Server unable to bind TCP port 5075, falling back to [::]:37961
    2025-03-08T12:32:06.263601805 WARN pvxs.tcp.init Server unable to bind TLS port 5076, falling back to [::]:35093
    Starting iocInit
    ############################################################################
    ## EPICS R7.0.8.2-DEV
    ## Rev. R7.0.8.1-123-g48607a42586b1a316cd6
    ## Rev. Date Git: 2024-11-29 17:08:28 +0000
    ############################################################################
    iocRun: All initialization complete
    epics>

|step| SPVA Client
----------------------

|1| Login as client in a new shell
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\⁵

.. code-block:: shell

    docker exec -it --user client spva_std /bin/bash

|2| Create Certificate
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- create a client certificate

  - creates a client certificate
  - at location specified by ``EPICS_PVA_TLS_KEYCHAIN`` or ``${XDG_CONFIG_HOME}/pva/1.3/client.p12`` by default

.. code-block:: shell

    authnstd -u client \
      -n "greg" \
      -o "SLAC.STANFORD.EDU" \
      --ou "Controls"

.. code-block:: console

    Keychain file created   : /home/client/.config/pva/1.3/client.p12
    Certificate identifier  : 46093d7c:5283204721404445451

.. note::

    Write down the certificate ID ``46093d7c:5283204721404445451`` (<issuer_id>:<serial_number>).
    You will need this ID to carry out operations on this certificate including APPROVING it.

|3| Approve certificate
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\⁴
- in the admin shell again, approve the certificate

.. code-block:: shell

    pvxcert --approve 46093d7c:5283204721404445451

.. code-block:: console

    Approve ==> CERT:STATUS:46093d7c:5283204721404445451 ==> Completed Successfully


|4| Run an SPVA client
^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\⁵
- back to the client shell again to get a value

.. code-block:: shell

    pvxget -F tree test:structExample

.. code-block:: console

    test:structExample
        struct {
            struct {
                struct {
                    int32_t queueSize = 0
                    bool atomic = true
                } _options
            } record
            ...
            struct "epics:nt/NTScalar:1.0" {
                double value = 0
                struct "alarm_t" {
                    int32_t severity = 2
                    int32_t status = 1
                    string message = "LOLO"
                } alarm
                struct "time_t" {
                    int64_t secondsPastEpoch = 1741433438
                    int32_t nanoseconds = 665740043
                    int32_t userTag = 0
                } timeStamp
                struct {
                    double limitLow = 0
                    double limitHigh = 10
                    string description = "Counter"
                    string units = "Counts"
                    int32_t precision = 0
                    struct "enum_t" {
                        int32_t index = 0
                        string[] choices = {7}["Default", "String", "Binary", "Decimal", "Hex", "Exponential", "Engineering"]
                    } form
                } display
                struct {
                    double limitLow = 0
                    double limitHigh = 10
                    double minStep = 0
                } control
                struct {
                    bool active = false
                    double lowAlarmLimit = 2
                    double lowWarningLimit = 4
                    double highWarningLimit = 6
                    double highAlarmLimit = 8
                    int32_t lowAlarmSeverity = 0
                    int32_t lowWarningSeverity = 0
                    int32_t highWarningSeverity = 0
                    int32_t highAlarmSeverity = 0
                    double hysteresis = 0
                } valueAlarm
            } calc
        }

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
    # TLS x509:46093d7c:13415272142438558829:EPICS Root Certificate Authority/softioc@172.17.0.2:35093
    test:enumExample from 172.17.0.2:35093
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

  - ``TLS x509:46093d7c:13415272142438558829:EPICS Root Certificate Authority/softioc @ 172.17.0.2`` indicates that:

    - The connection is ``TLS``,
    - The Server end of the channel has been authenticated by the Root Certificate Authority ``EPICS Root Certificate Authority``
    - The Server end of the channel's name has been authenticated as ``softioc`` and is connecting from host ``172.17.0.2``


|step| Permissions
------------------------

|1| Security Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^

- field ``test:spec`` is defined in ``testioc.db`` and protected by the ``SPECIAL`` security group

.. code-block:: shell

    ...

    record(ao, "$(user):spec") {
       field(ASG, "SPECIAL")
    }


- the ``SPECIAL`` security group protects ``test:spec`` in ``testioc.acf``

  - it makes it writeable if, and only if

    - user is "michael" and
    - method is ``x509`` - client has been authenticated using an *X.509 certificate* and
    - the certificate authority that signed the certificate was *EPICS Root Certificate Authority*

.. code-block:: shell

    AUTHORITY(AUTH_EPICS_ROOT, "EPICS Root Certificate Authority")

    UAG(OPERATORS) {
        "michael"
    }

    ASG(SPECIAL) {
        RULE(1,WRITE,TRAPWRITE) {
            UAG(OPERATORS)
    		AUTHORITY(AUTH_EPICS_ROOT)
    		METHOD("x509")
        }
    }

|2| Security Enforcement
^^^^^^^^^^^^^^^^^^^^^^^^^^

- show that we can GET the value with or without TLS

.. code-block:: shell

    pvxget test:spec -r value

.. code-block:: console

    test:spec
        value double = 0

.. code-block:: shell

    env EPICS_PVA_TLS_KEYCHAIN= pvxget test:spec -r value

.. code-block:: console

    test:spec
        value double = 0

- show that we cannot set (``PUT``) the value with, or without TLS if we are not identified as "michael"

.. code-block:: shell

    pvxput test:spec 10

.. code-block:: console

    Error N4pvxs6client11RemoteErrorE : Put not permitted

.. code-block:: shell

    env EPICS_PVA_TLS_KEYCHAIN= pvxput test:spec 10

.. code-block:: console

    Error N4pvxs6client11RemoteErrorE : Put not permitted

|3| Client Authorization
^^^^^^^^^^^^^^^^^^^^^^^^^^

- So we need to create a new certificate that will identify us as "michael"

.. code-block:: shell

    export EPICS_PVA_TLS_KEYCHAIN=~/.config/pva/1.3/michael.p12
    authnstd -n michael

.. code-block:: console

    Keychain file created   : /home/client/.config/pva/1.3/michael.p12
    Certificate identifier  : b271f07a:4803259031245539247

- |terminal|\⁴
- and ask our administrator to approve it

.. code-block:: shell

    pvxcert --approve b271f07a:4803259031245539247

.. code-block:: console

    Approve ==> CERT:STATUS:b271f07a:4803259031245539247 ==> Completed Successfully

- |terminal|\⁵
- show that we can set the value if

  - we are identified as "michael"
  - using an ``X.509`` certificate
  - created by the *EPICS Root Certificate Authority*

.. code-block:: shell

    pvxput test:spec 10
    pvxget test:spec -r value

 .. code-block:: console

     test:spec
         value double = 10
