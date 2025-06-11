.. _quick_start:

|guide| Quick Start PVXS
========================


    Secure PVAccess is a version of the PVAccess protocol secured with TLS. It delivers robust
    protection for EPICS network agents through zero‑trust, mutually authenticated connections
    and end‑to‑end encryption. This upgrade reinforces EPICS’s authorization system by ensuring
    authenticated endpoints and establishing trusted authorities. Additionally, it
    incorporates a comprehensive certificate management service, *PVACMS*, that issues, and provides
    status of, X.509 certificates.


This section contains a Quick Start |guide| for Secure PVAccess.  It shows how to configure and
build *epics-base* and then *pvxs* with the Secure PVAccess
protocol enabled.  We provide containerised build instructions
that allow you to familiarize yourself with the protocol and tools before
deploying into your network.
See :ref:`secure_pvaccess` for general documentation.

Other Quick Start Guides:

- :ref:`quick_start_std`
- :ref:`quick_start_krb`
- :ref:`quick_start_ldap`

|learn| You will learn
****************************

- :ref:`Building and Deploying epics-base and the PVXS libraries and executables <spva_qs_build_and_deploy>`,
- :ref:`Running PVACMS to manage certificates <spva_qs_pvacms>`,
- :ref:`Hands on experience with Certificate Management<spva_qs_admin>`

|pre-packaged|\Prepackaged
****************************

If you want a prepackaged environment, try the following.  You will need two terminal sessions.

|1| Run PVACMS
-----------------------

- |terminal|\¹
- start a vm in a container named *ubuntu_pvxs* from a Prepackaged Secure PVAccess image

.. code-block:: shell

    docker run -it --name ubuntu_pvxs georgeleveln/pvxs:latest

- within the container, start *pvacms*

.. code-block:: shell

    export XDG_DATA_HOME=${XDG_DATA_HOME-~/.local/share}
    export XDG_CONFIG_HOME=${XDG_CONFIG_HOME-~/.config}
    export PVXS_HOST_ARCH=$(${PROJECT_HOME}/epics-base/startup/EpicsHostArch)
    export PATH="${PROJECT_HOME}/pvxs/bin/${PVXS_HOST_ARCH}:$PATH"
    pvacms -v

.. code-block:: console

    Certificate DB created  : /root/.local/share/pva/1.3/certs.db
    2025-03-08T09:45:46.357411047 INFO pvxs.certs.cms 06e4748c:1314642908097862106 *=> VALID
    Keychain file created   : /root/.config/pva/1.3/cert_auth.p12
    Created Default ACF file: /root/.config/pva/1.3/pvacms.acf
    2025-03-08T09:45:46.416659464 INFO pvxs.certs.cms 06e4748c:9522902379233552024 *=> VALID
    Keychain file created   : /root/.config/pva/1.3/admin.p12
    2025-03-08T09:45:46.483891839 INFO pvxs.certs.cms 06e4748c:12098279511235536670 *=> VALID
    Keychain file created   : /root/.config/pva/1.3/pvacms.p12
    Effective config
    EPICS_CERT_AUTH_COUNTRY=US
    EPICS_CERT_AUTH_NAME=EPICS Root Certificate Authority
    EPICS_CERT_AUTH_ORGANIZATION=certs.epics.org
    EPICS_CERT_AUTH_ORGANIZATIONAL_UNIT=EPICS Certificate Authority
    EPICS_CERT_AUTH_TLS_KEYCHAIN=/home/pvacms/.config/pva/1.3/cert_auth.p12
    EPICS_PVACMS_ACF=/home/pvacms/.config/pva/1.3/pvacms.acf
    EPICS_PVACMS_CERTS_REQUIRE_SUBSCRIPTION=YES
    EPICS_PVACMS_CERT_STATUS_VALIDITY_MINS=30m
    EPICS_PVACMS_CERT_VALIDITY=6M
    EPICS_PVACMS_DB=/home/pvacms/.local/share/pva/1.3/certs.db
    EPICS_PVACMS_DISALLOW_CUSTOM_DURATION=NO
    EPICS_PVACMS_REQUIRE_APPROVAL=YES
    EPICS_PVACMS_TLS_STOP_IF_NO_CERT=YES
    EPICS_PVAS_AUTH_COUNTRY=US
    EPICS_PVAS_AUTH_ORGANIZATION=certs.epics.org
    EPICS_PVAS_AUTH_ORGANIZATIONAL_UNIT=EPICS Certificate Authority
    EPICS_PVAS_AUTO_BEACON_ADDR_LIST=YES
    EPICS_PVAS_BROADCAST_PORT=5076
    EPICS_PVAS_CERT_PV_PREFIX=CERT
    EPICS_PVAS_SERVER_PORT=5075
    EPICS_PVAS_TLS_KEYCHAIN=/home/pvacms/.config/pva/1.3/pvacms.p12
    EPICS_PVAS_TLS_OPTIONS=client_cert=optional on_expiration=fallback-to-tcp no_revocation_check on_no_cms=fallback-to-tcp
    EPICS_PVAS_TLS_PORT=5076
    EPICS_PVAS_TLS_STOP_IF_NO_CERT=YES

    +=======================================+=======================================
    | EPICS Secure PVAccess Certificate Management Service
    +---------------------------------------+---------------------------------------
    | Certificate Database                  : /home/pvacms/.local/share/pva/1.3/certs.db
    | Certificate Authority                 : CN = EPICS Root Certificate Authority, C = US, O = certs.epics.org, OU = EPICS Certificate Authority
    | Certificate Authority Keychain File   : /home/pvacms/.config/pva/1.3/cert_auth.p12
    | PVACMS Keychain File                  : /home/pvacms/.config/pva/1.3/pvacms.p12
    | PVACMS Access Control File            : /home/pvacms/.config/pva/1.3/pvacms.acf
    +---------------------------------------+---------------------------------------
    | PVACMS [2535f0b8] Service Running     |
    +=======================================+=======================================

|2| Run Tools
----------------------

- |terminal|\²
- in a new terminal open a new shell to the same container

.. code-block:: shell

    docker exec -it ubuntu_pvxs /bin/bash

- set up the environment

.. code-block:: shell

    export XDG_DATA_HOME=${XDG_DATA_HOME-~/.local/share}
    export XDG_CONFIG_HOME=${XDG_CONFIG_HOME-~/.config}
    export PVXS_HOST_ARCH=$(${PROJECT_HOME}/epics-base/startup/EpicsHostArch)
    export PATH="${PROJECT_HOME}/pvxs/bin/${PVXS_HOST_ARCH}:$PATH"
    export EPICS_PVA_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.3/admin.p12

- run some *pvxcert* commands

.. code-block:: shell

    pvxcert 06e4748c:1314642908097862106

.. code-block:: console

    Certificate Status:
    ============================================
    Certificate ID: 06e4748c:1314642908097862106
    Status        : VALID
    Status Issued : Sat Mar 08 09:47:40 2025 UTC
    Status Expires: Sat Mar 08 10:17:40 2025 UTC
    --------------------------------------------

.. code-block:: shell

    pvxcert -f /root/.config/pva/1.3/admin.p12

.. code-block:: console

    Certificate Details:
    ============================================
    Certificate ID : 06e4748c:9522902379233552024
    Entity Subject : CN=admin, C=US
    Issuer Subject : CN=EPICS Root, C=US, O=certs.epics.org, OU=EPICS Certificate Authority
    Valid From     : Sat Mar 08 09:45:46 2025 UTC
    Expires On     : Mon Mar 09 09:45:46 2026 UTC
    --------------------------------------------

    Certificate Status:
    ============================================
    Certificate ID: 06e4748c:9522902379233552024
    Status        : VALID
    Status Issued : Sat Mar 08 09:47:56 2025 UTC
    Status Expires: Sat Mar 08 10:17:56 2025 UTC
    --------------------------------------------

.. code-block:: shell

    pvxcert --revoke 06e4748c:9522902379233552024

.. code-block:: console

    Revoke ==> CERT:STATUS:06e4748c:9522902379233552024 ==> Completed Successfully

.. code-block:: shell

    pvxcert --revoke 06e4748c:1314642908097862106

.. code-block:: console

    Revoke ==> CERT:STATUS:06e4748c:1314642908097862106
    2025-03-08T09:49:08.021246627 ERR pvxs.certs.tool REVOKED operation not authorized on 06e4748c:1314642908097862106

|step-by-step| Step-by-Step
****************************

|step| Docker Image
--------------------------------------------

|1| Image
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Locate the image you want to use from the list below

+--------------+----------------+--------------------------------------------+
| Distribution | container name | image                                      |
+==============+================+============================================+
| Ubuntu       | ubuntu_pvxs    | ubuntu_latest                              |
+--------------+----------------+--------------------------------------------+
| RHEL         | rhel_pvxs      | registry.access.redhat.com/ubi8/ubi:latest |
+--------------+----------------+--------------------------------------------+
| CentOS       | centos_pvxs    | centos_latest                              |
+--------------+----------------+--------------------------------------------+
| Rocky        | rocky_pvxs     | rocky_latest                               |
+--------------+----------------+--------------------------------------------+
| Alma         | alma_pvxs      | alma_latest                                |
+--------------+----------------+--------------------------------------------+
| Fedora       | fedora_pvxs    | fedora_latest                              |
+--------------+----------------+--------------------------------------------+
| Alpine       | alpine_pvxs    | alpine_latest                              |
+--------------+----------------+--------------------------------------------+


|2| Create
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\¹
- start a vm in a container named *ubuntu_pvxs* from a ubuntu image

.. code-block:: shell

    docker run -it --name ubuntu_pvxs ubuntu:latest /bin/bash

where:

- ``--name ubuntu_pvxs`` : sets the name of the container
- ``ubuntu:latest`` : the image we're using for the remainder of the examples
- ``/bin/bash`` : the command to run when entering the VM

.. _spva_qs_build_and_deploy:

|step| Build PVXS
-------------------------------------------------

|1| Environment
^^^^^^^^^^^^^^^^^^^^^^^^^^

- make working directory for building project files

.. code-block:: shell

    export PROJECT_HOME=/opt/epics
    mkdir -p ${PROJECT_HOME}


|2| Requirements
^^^^^^^^^^^^^^^^^^^^^^^^

Select from the following installation instructions based on the image you selected:

For Debian/Ubuntu
~~~~~~~~~~~~~~~~~~~~

.. code-block:: shell

    apt-get update
    apt-get install -y \
           build-essential \
           git \
           openssl \
           libssl-dev \
           libevent-dev \
           libsqlite3-dev \
           libcurl4-openssl-dev \
           pkg-config

For RHEL/CentOS/Rocky/Alma Linux/Fedora
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: shell

    dnf install -y \
           gcc-c++ \
           git \
           make \
           openssl-devel \
           libevent-devel \
           sqlite-devel \
           libcurl-devel \
           pkg-config

For Alpine Linux
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: shell

    apk add --no-cache \
           build-base \
           git \
           openssl-dev \
           libevent-dev \
           sqlite-dev \
           curl-dev \
           pkgconfig

For RTEMS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- install RTEMS toolchain from https://docs.rtems.org/branches/master/user/start/

- ensure the following are built into your BSP:
    - openssl
    - libevent
    - sqlite
    - libcurl

.. note::

  RTEMS support requires additional configuration. See RTEMS-specific documentation.


For MacOS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- install Homebrew if not already installed

.. code-block:: shell

    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

- update Homebrew and install dependencies

.. code-block:: shell

    brew update
    brew install \
           openssl@3 \
           libevent \
           sqlite3 \
           curl \
           pkg-config

.. note::

  If you don't have homebrew and don't want to install it, here's how you would install the prerequisites.

  - ensure *Xcode* Command Line Tools are installed

  .. code-block:: shell

    xcode-select --install

  - install *OpenSSL*

  .. code-block:: shell

    curl -O https://www.openssl.org/source/openssl-3.1.2.tar.gz
    tar -xzf openssl-3.1.2.tar.gz
    cd openssl-3.1.2
    ./Configure darwin64-x86_64-cc
    make
    sudo make install

  - install *libevent*

  .. code-block:: shell

    curl -O https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz
    tar -xzf libevent-2.1.12-stable.tar.gz
    cd libevent-2.1.12-stable
    ./configure
    make
    sudo make install

  - install *SQLite*

  .. code-block:: shell

    curl -O https://sqlite.org/2023/sqlite-autoconf-3430200.tar.gz
    tar -xzf sqlite-autoconf-3430200.tar.gz
    cd sqlite-autoconf-3430200
    ./configure
    make
    sudo make install

  - install *Curl*

  - check if its already there

    .. code-block:: shell

        curl --version

  - if not then install it

    .. code-block:: shell

        curl -O https://curl.se/download/curl-8.1.2.tar.gz
        tar -xzf curl-8.1.2.tar.gz
        cd curl-8.1.2
        ./configure
        make
        sudo make install

  - install *pkg-config*

  .. code-block:: shell

    curl -O https://pkgconfig.freedesktop.org/releases/pkg-config-0.29.2.tar.gz
    tar -xzf pkg-config-0.29.2.tar.gz
    cd pkg-config-0.29.2
    ./configure --with-internal-glib
    make
        sudo make install


|3| epics-base
^^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

    cd ${PROJECT_HOME}
    git clone --branch 7.0-secure-pvaccess https://github.com/george-mcintyre/epics-base.git
    cd epics-base

    make -j10 all
    cd ${PROJECT_HOME}

|4| Configure
^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

    cd ${PROJECT_HOME}
    cat >> RELEASE.local <<EOF
    EPICS_BASE = \$(TOP)/../epics-base
    EOF

|5| Build
^^^^^^^^^^^^^^

.. code-block:: shell

    cd ${PROJECT_HOME}
    cat >> CONFIG_SITE.local <<EOF
    PVXS_ENABLE_PVACMS = YES
    EOF

    git clone --recursive  --branch tls https://github.com/george-mcintyre/pvxs.git
    cd pvxs

    make -j10 all
    cd ${PROJECT_HOME}


.. _spva_qs_pvacms:


|step| PVACMS
-------------------------------------------------------

|1| Configure
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Environment

  - set up XDG environment if not already set

.. code-block:: shell

    export XDG_DATA_HOME=${XDG_DATA_HOME-~/.local/share}
    export XDG_CONFIG_HOME=${XDG_CONFIG_HOME-~/.config}

- PATH

  - set PATH to include Secure PVAccess executables

.. code-block:: shell

    export PVXS_HOST_ARCH=$(${PROJECT_HOME}/epics-base/startup/EpicsHostArch)
    export PATH="${PROJECT_HOME}/pvxs/bin/${PVXS_HOST_ARCH}:$PATH"


- *optionally*

  - Configure Certificate database file location*

.. code-block:: shell

    export EPICS_PVACMS_DB=${XDG_DATA_HOME}/pva/1.3/certs.db


- *optionally*

  - Configure root certificate authority keychain file location
  - Place your certificate authority's certificate and key in this file if you have one
otherwise the certificate authority certificate will be created here

.. code-block:: shell

    export EPICS_CERT_AUTH_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.3/cert_auth.p12


- *optionally*

  - Specify the subject name of your Root Certificate Authority in case you don't provide a Root Certificate Authority certificate and it needs to be created

.. code-block:: shell

    export EPICS_CERT_AUTH_NAME="EPICS Root Certificate Authority"           # CN
    export EPICS_CERT_AUTH_ORGANIZATION="certs.epics.org"                    # O
    export EPICS_CERT_AUTH_ORGANIZATIONAL_UNIT="EPICS Certificate Authority" # OU
    export EPICS_CERT_AUTH_COUNTRY="US"                                     # C


- *optionally*

  - Configure PVACMS Keychain file location
  - The PVACMS keychain file will be created at this location if it does not exist

.. code-block:: shell

    export EPICS_PVACMS_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.3/pvacms.p12


- *optionally*

  - Configure Admin User Keychain file location
  - An Admin User keychain file will be created at this location if it does not exist

.. code-block:: shell

    export EPICS_ADMIN_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.3/admin.p12


- *optionally*

  - Configure PVACMS ADMIN user Access Control File (ACF) location
  - An ACF file that controls access to PVACMS resources (certificates, etc.) is created at this location if it does not exist
  - By default the file created ensures that administrator permissions are granted to any user that presents a certificate that is signed by the configured Root Certificate Authority and has CN="admin", O="", OU="", C="US"
  - You can modify this file to add other admin users to the UAG section, or conditions to an existing or new RULES section

.. code-block:: shell

    export EPICS_PVACMS_ACF=${XDG_CONFIG_HOME}/pva/1.3/pvacms.acf

|2| Run
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

    pvacms -v

.. code-block:: console

    Certificate DB created  : /root/.local/share/pva/1.3/certs.db
    2025-03-04T14:53:32.401223876 INFO pvxs.certs.cms 2535f0b8:7554235394877908901 *=> VALID
    Keychain file created   : /root/.config/pva/1.3/cert_auth.p12
    Created Default ACF file: /root/.config/pva/1.3/pvacms.acf
    2025-03-04T14:53:32.538922876 INFO pvxs.certs.cms 2535f0b8:7810503273530005364 *=> VALID
    Keychain file created   : /root/.config/pva/1.3/admin.p12
    2025-03-04T14:53:32.589539542 INFO pvxs.certs.cms 2535f0b8:15782598755272381308 *=> VALID
    Keychain file created   : /root/.config/pva/1.3/pvacms.p12
    Effective config
    EPICS_CERT_AUTH_COUNTRY=US
    EPICS_CERT_AUTH_NAME=EPICS Root Certificate Authority
    EPICS_CERT_AUTH_ORGANIZATION=certs.epics.org
    EPICS_CERT_AUTH_ORGANIZATIONAL_UNIT=EPICS Certificate Authority
    EPICS_CERT_AUTH_TLS_KEYCHAIN=/home/pvacms/.config/pva/1.3/cert_auth.p12
    EPICS_PVACMS_ACF=/home/pvacms/.config/pva/1.3/pvacms.acf
    EPICS_PVACMS_CERTS_REQUIRE_SUBSCRIPTION=DEFAULT
    EPICS_PVACMS_CERT_STATUS_VALIDITY_MINS=30m
    EPICS_PVACMS_CERT_VALIDITY=6M
    EPICS_PVACMS_DB=/home/pvacms/.local/share/pva/1.3/certs.db
    EPICS_PVACMS_DISALLOW_CUSTOM_DURATION=NO
    EPICS_PVACMS_REQUIRE_APPROVAL=YES
    EPICS_PVACMS_TLS_STOP_IF_NO_CERT=YES
    EPICS_PVAS_AUTH_COUNTRY=US
    EPICS_PVAS_AUTH_ORGANIZATION=certs.epics.org
    EPICS_PVAS_AUTH_ORGANIZATIONAL_UNIT=EPICS Certificate Authority
    EPICS_PVAS_AUTO_BEACON_ADDR_LIST=YES
    EPICS_PVAS_BROADCAST_PORT=5076
    EPICS_PVAS_CERT_PV_PREFIX=CERT
    EPICS_PVAS_SERVER_PORT=5075
    EPICS_PVAS_TLS_KEYCHAIN=/home/pvacms/.config/pva/1.3/pvacms.p12
    EPICS_PVAS_TLS_OPTIONS=client_cert=optional on_expiration=fallback-to-tcp no_revocation_check on_no_cms=fallback-to-tcp
    EPICS_PVAS_TLS_PORT=5076
    EPICS_PVAS_TLS_STOP_IF_NO_CERT=YES

    +=======================================+=======================================
    | EPICS Secure PVAccess Certificate Management Service
    +---------------------------------------+---------------------------------------
    | Certificate Database                  : /home/pvacms/.local/share/pva/1.3/certs.db
    | Certificate Authority                 : CN = EPICS Root Certificate Authority, C = US, O = certs.epics.org, OU = EPICS Certificate Authority
    | Certificate Authority Keychain File   : /home/pvacms/.config/pva/1.3/cert_auth.p12
    | PVACMS Keychain File                  : /home/pvacms/.config/pva/1.3/pvacms.p12
    | PVACMS Access Control File            : /home/pvacms/.config/pva/1.3/pvacms.acf
    +---------------------------------------+---------------------------------------
    | PVACMS [2535f0b8] Service Running     |
    +=======================================+=======================================

.. note::

  Make a note of the certificates that are created

  - `2535f0b8:7554235394877908901`  : Root Certificate Authority Certificate
  - `2535f0b8:7810503273530005364`  : Admin User Certificate
  - `2535f0b8:15782598755272381308` : PVACMS Server Certificate

.. _spva_qs_admin:

|step| Test
------------------------------------------------------

|1|  Configure
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\²
- in a different terminal open a shell to the same container:

.. code-block:: shell

    docker exec -it ubuntu_pvxs /bin/bash

----------------------

- set up XDG environment if not already set, and set PATH

.. code-block:: shell

    export PROJECT_HOME=/opt/epics
    export XDG_DATA_HOME=${XDG_DATA_HOME-~/.local/share}
    export XDG_CONFIG_HOME=${XDG_CONFIG_HOME-~/.config}
    export PVXS_HOST_ARCH=$(${PROJECT_HOME}/epics-base/startup/EpicsHostArch)
    export PATH="${PROJECT_HOME}/pvxs/bin/${PVXS_HOST_ARCH}:$PATH"

----------------------

- configure the location of the Admin User's keychain file.

We will be carrying out some protected operations so we will need to have access
to the Admin User's keychain file

.. code-block:: shell

    export EPICS_PVA_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.3/admin.p12


|2|\Get Status
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- get the status of Root Certificate Authority Certificate

.. code-block:: shell

    pvxcert 2535f0b8:7554235394877908901

.. code-block:: console

    Certificate Status:
    ============================================
    Certificate ID: 2535f0b8:7554235394877908901
    Status        : VALID
    Status Issued : Tue Mar 04 15:27:10 2025 UTC
    Status Expires: Tue Mar 04 15:57:10 2025 UTC
    --------------------------------------------

- check status of the Admin Certificate by file name

.. code-block:: shell

    pvxcert -f /root/.config/pva/1.3/admin.p12

.. code-block:: console

    Certificate Details:
    ============================================
    Certificate ID : 2535f0b8:7810503273530005364
    Entity Subject : CN=admin, C=US
    Issuer Subject : CN=EPICS Root Certificate Authority, C=US, O=certs.epics.org, OU=EPICS Certificate Authority
    Valid From     : Tue Mar 04 14:53:32 2025 UTC
    Expires On     : Thu Mar 05 14:53:32 2026 UTC
    --------------------------------------------

    Certificate Status:
    ============================================
    Certificate ID: 2535f0b8:7810503273530005364
    Status        : VALID
    Status Issued : Tue Mar 04 15:29:54 2025 UTC
    Status Expires: Tue Mar 04 15:59:54 2025 UTC
    --------------------------------------------


|3| Revoke
^^^^^^^^^^^^^^^^^^^^^^^^^^

- revoke Admin User's certificate.

Once this completes, the Admin user will lose administrator
status

.. code-block:: shell

    pvxcert --revoke 2535f0b8:7810503273530005364

.. code-block:: console

    Revoke ==> CERT:STATUS:2535f0b8:7810503273530005364 ==> Completed Successfully

----------------------

- try to revoke Root Certificate Authority Certificate

Fail because Admin User's Certificate has been revoked

.. code-block:: shell

    pvxcert --revoke 2535f0b8:7554235394877908901

.. code-block:: console

    Revoke ==> CERT:STATUS:2535f0b8:7554235394877908901
    2025-03-04T15:38:09.101065420 ERR pvxs.certs.tool REVOKED operation not authorized on 2535f0b8:7554235394877908901

----------------------

regenerate admin certificate

- in the other other terminal window,  Stop PVACMS (ctrl-C)

.. code-block:: shell

    ^C

.. code-block:: console

    PVACMS [2535f0b8] Service Exiting

- Create a new Admin User Certificate

.. code-block:: shell

    pvacms --admin-keychain-new admin

.. code-block:: console

    2025-03-04T15:40:38.519777878 WARN pvxs.certs.file
        Cert file backed up: /root/.config/pva/1.3/admin.p12 ==> /root/.config/pva/1.3/admin.2503041540.p12
    Keychain file created   : /root/.config/pva/1.3/admin.p12
    Admin user "admin" has been added to list of administrators of this PVACMS
    Restart the PVACMS for it to take effect

- Restart PVACMS

.. code-block:: shell

    pvacms

.. code-block:: console

    PVACMS [2535f0b8] Service Running
