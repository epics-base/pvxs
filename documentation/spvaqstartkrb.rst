.. _quick_start_krb:

⚡ Kerberos Authenticator
==================================================

This section contains a Quick Start Guide (⚡) for the Secure PVAccess *Kerberos Authenticator*.

    The Kerberos Authenticator is an Authenticator that uses a kerberos ticket to create an X.509
    certificate.

    It takes the ``PRINCIPAL`` from the ticket and splits it up on '@' to extract the
    ``common name``, and ``organization`` for the certificate's
    subject while leaving the ``organizational unit`` blank.

    The information
    is sent to the PVACMS which validates that the request is authentic and the credentials
    correct by contacting the KDC.  If all checks-out then certificates are generated in the ``VALID`` state.

Our starting point for this Quick Start Guide is the end of the :ref:`_quick_start_std` so if you haven't gone through it yet
do that now then come back here.  You need to have users's configured (``pvacms``, ``admin``, ``softioc``, and ``client``).
We will set up a containerised KDC and configure it so that the users can get tickets.  We will create
a pvacms Kerberos service and provide PVACMS a keytab for passwordless authentication so that it can verify CCRs presented
by clients requesting new certificates.

See :ref:`secure_pvaccess` for general documentation on Secure PVAccess.

Other Quick Start Guides:

- :ref:`quick_start`
- :ref:`quick_start_std`
- :ref:`quick_start_ldap`

🎓 What you will learn:
-------------------------------------

- :ref:`Creating a containerised KDC <spva_qs_krb_kdc>`,
- :ref:`Building PVXS with Kerberos Authenticator support <spva_qs_krb_build>`,
- :ref:`Exporting pvacms keytab from KDC and configuring pvacms to use it <spva_qs_krb_pvacms>`,
- :ref:`Creating certificates using the Kerberos Authenticator<spva_qs_krb_server>` and
- :ref:`Connecting a Kerberos Client to an SPVA Server<spva_qs_krb_client>`

⏩ Pre-Built
------------------------------

If you want a pre-setup environment, try the following.  You will need three terminal sessions.

① 🖥¹ Load image
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

start new container with pre-built Secure PVAccess with Kerberos Authenticator and 4 Users

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

② 🖥² Log in as Service
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

log in as softioc service account

.. code-block:: shell

    docker exec -it --user softioc spva_krb /bin/bash

get a kerberos ticket.  Enter "secret" as the password when prompted

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

create a server certificate using the Kerberos Authenticator

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
    Subject        : CN=softioc, O=EPICS.ORG
    Issuer         : CN=EPICS Root CA, C=US, O=ca.epics.org, OU=EPICS Certificate Authority
    Valid from     : Sat Mar 08 15:23:21 2025 UTC
    Cert Expires   : Sun Mar 09 15:23:09 2025 UTC
    --------------------------------------------

    Certificate Status:
    ============================================
    Certificate ID: 47530d89:3826361579604613181
    Status        : VALID
    Status Issued : Sat Mar 08 15:47:14 2025 UTC
    Status Expires: Sat Mar 08 16:17:14 2025 UTC
    --------------------------------------------

③ 🖥³ Log in as a Client
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

log in as a Secure PVAccess client

.. code-block:: shell

    docker exec -it --user client spva_krb /bin/bash

get a kerberos ticket.  Enter "secret" as the password when prompted

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

create a client certificate using the Kerberos Authenticator

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
    Subject        : CN=client, O=EPICS.ORG
    Issuer         : CN=EPICS Root CA, C=US, O=ca.epics.org, OU=EPICS Certificate Authority
    Valid from     : Sat Mar 08 15:31:44 2025 UTC
    Cert Expires   : Sun Mar 09 15:27:50 2025 UTC
    --------------------------------------------

    Certificate Status:
    ============================================
    Certificate ID: 47530d89:15177030356392297708
    Status        : VALID
    Status Issued : Sat Mar 08 15:40:20 2025 UTC
    Status Expires: Sat Mar 08 16:10:20 2025 UTC
    --------------------------------------------


④ 🖥² Start SoftIOC
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

start SoftIOC

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

⑤ 🖥³ Get PV value
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

get a PV ``test:enumExample`` value from the SoftIOC

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
    # TLS x509:EPICS Root CA/softioc@172.17.0.2:34381
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

verify that connection is TLS

- `TLS x509:EPICS Root CA/softioc @ 172.17.0.2` indicates that:

  - The connection is `TLS`,
  - The Server end of the channel has been authenticated by the Root CA `EPICS Root CA`
  - The Server end of the channel's name has been authenticated as `softioc` and is connecting from host ``172.17.0.2``

