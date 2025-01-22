.. _quick_start:

Secure PVA Quick Start
======================

This section contains quick start guides for common Secure PVAccess
tasks. See :ref:`secure_pvaccess` for general documentation on Secure PVAccess.

In this section you'll find quick starts for :ref:`spva_qs_build_and_deploy`,
:ref:`spva_qs_pvacms`, :ref:`spva_qs_server` and :ref:`spva_qs_client`


.. _spva_qs_build_and_deploy:

If you're going to test this in a VM
------------------------------------

    .. code-block:: sh

        # Create docker container and open a bash shell into it
        # Do the building and approving from this shell
        docker run -it --name ubuntu_pvxs ubuntu:latest /bin/bash

        # In this shell modify the shell startup script so that it will set the appropriate variables
        cat >> ~/.bashrc <<EOF

        export XDG_DATA_HOME=${XDG_DATA_HOME-~/.local/share}
        export XDG_CONFIG_HOME=${XDG_CONFIG_HOME-~/.config}
        export PROJECT_HOME=~/src
        EOF
        source ~/.bashrc

        # Make three other shells (in different terminals) for running PVACMS, a server, and a client
        docker exec -it ubuntu_pvxs /bin/bash


Build & Deploy
--------------


1. Initialise Environment
^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        # Set up data and configuration home if not already set
        export XDG_DATA_HOME=${XDG_DATA_HOME-~/.local/share}
        export XDG_CONFIG_HOME=${XDG_CONFIG_HOME-~/.config}

        # Make working directory for building project files
        export XDG_DATA_HOME=${XDG_DATA_HOME-~/.local/share}
        export XDG_CONFIG_HOME=${XDG_CONFIG_HOME-~/.config}
        export PROJECT_HOME=~/src
        mkdir -p ${PROJECT_HOME}

2. Install Requirements
^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #############
        # For Debian/Ubuntu

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

        #############
        # For RHEL/CentOS/Rocky/Alma Linux/Fedora

        dnf install -y \
            gcc-c++ \
            git \
            make \
            openssl-devel \
            libevent-devel \
            sqlite-devel \
            libcurl-devel \
            pkg-config

        #############
        # For macOS
        # Install Homebrew if not already installed
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

        # Update Homebrew and install dependencies
        brew update
        brew install \
            openssl@3 \
            libevent \
            sqlite3 \
            curl \
            pkg-config

        #############
        # For Alpine Linux

        apk add --no-cache \
            build-base \
            git \
            openssl-dev \
            libevent-dev \
            sqlite-dev \
            curl-dev \
            pkgconfig

        #############
        # For RTEMS
        # First install RTEMS toolchain from https://docs.rtems.org/branches/master/user/start/
        # Then ensure these are built into your BSP:
        #   - openssl
        #   - libevent
        #   - sqlite
        #   - libcurl
        # Note: RTEMS support requires additional configuration. See RTEMS-specific documentation.


Note for MacOS users
~~~~~~~~~~~~~~~~~~~~

If you don't have homebrew and don't want to install it, here's how you would install the prerequisites.

    .. code-block:: sh

        # Ensure Xcode Command Line Tools are installed
        xcode-select --install

        # Install OpenSSL
        curl -O https://www.openssl.org/source/openssl-3.1.2.tar.gz
        tar -xzf openssl-3.1.2.tar.gz
        cd openssl-3.1.2
        ./Configure darwin64-x86_64-cc
        make
        sudo make install

        # Install libevent
        curl -O https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz
        tar -xzf libevent-2.1.12-stable.tar.gz
        cd libevent-2.1.12-stable
        ./configure
        make
        sudo make install

        # Install SQLite
        curl -O https://sqlite.org/2023/sqlite-autoconf-3430200.tar.gz
        tar -xzf sqlite-autoconf-3430200.tar.gz
        cd sqlite-autoconf-3430200
        ./configure
        make
        sudo make install

        # Install cURL
        # check if its already there
        curl --version
        # If not then install like this:
        curl -O https://curl.se/download/curl-8.1.2.tar.gz
        tar -xzf curl-8.1.2.tar.gz
        cd curl-8.1.2
        ./configure
        make
        sudo make install

        # Install pkg-config
        curl -O https://pkgconfig.freedesktop.org/releases/pkg-config-0.29.2.tar.gz
        tar -xzf pkg-config-0.29.2.tar.gz
        cd pkg-config-0.29.2
        ./configure --with-internal-glib
        make
        sudo make install


3. Build epics-base
^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        cd ${PROJECT_HOME}
        git clone --branch 7.0-method_and_authority https://github.com/george-mcintyre/epics-base.git
        cd epics-base

        make -j10 all
        cd ${PROJECT_HOME}

4. Configure PVXS Build
^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        cd ${PROJECT_HOME}
        cat >> RELEASE.local <<EOF
        EPICS_BASE = \$(TOP)/../epics-base
        EOF

        # Optional: To enable appropriate site authentication mechanisms.
        # Note: `authnstd` is always available.

        # cat >> CONFIG_SITE.local <<EOF
        # PVXS_ENABLE_KRB_AUTH = YES
        # PVXS_ENABLE_JWT_AUTH = YES
        # PVXS_ENABLE_LDAP_AUTH = YES
        #EOF

5. Build PVXS
^^^^^^^^^^^^^

    .. code-block:: sh

        cd ${PROJECT_HOME}
        git clone --recursive  --branch tls https://github.com/george-mcintyre/pvxs.git
        cd pvxs

        # Build PVXS

        make -j10 all
        cd ${PROJECT_HOME}



.. _spva_qs_pvacms:

PVACMS
---------------

1. Database configuration
^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### [optional] Set path and name of the CA database file (default: ./certs.db)
        # Environment: EPICS_PVACMS_DB
        # Default    : ${XDG_DATA_HOME}/pva/1.3/certs.db
        # export EPICS_PVACMS_DB=${XDG_DATA_HOME}/pva/1.3/certs.db


2. Certificate Authority
^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### SETUP CA KEYCHAIN FILE
        # Place your CA's certificate and key in this file if you have one
        # otherwise the CA certificate will be created by PVACMS
        # Environment: EPICS_CA_TLS_KEYCHAIN
        # Default    : ${XDG_CONFIG_HOME}/pva/1.3/ca.p12
        # export EPICS_CA_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.3/ca.p12

In case you have not provided your own CA certificate, PVACMS can produce one for you if you configure
what you want it to contain.

    .. code-block:: sh

        # Specify the name of your CA
        # Environment: EPICS_CA_NAME, EPICS_CA_ORGANIZATION, EPICS_CA_ORGANIZATIONAL_UNIT
        # Default    : CN=EPICS Root CA, O=ca.epics.org, OU=EPICS Certificate Authority,
        # export EPICS_CA_NAME="EPICS Root CA"
        # export EPICS_CA_ORGANIZATION="ca.epics.org"
        # export EPICS_CA_ORGANIZATIONAL_UNIT="EPICS Certificate Authority"


3. Server Certificate
^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### SETUP PVACMS KEYCHAIN FILE
        # Environment: EPICS_PVACMS_TLS_KEYCHAIN
        # Default    : ${XDG_CONFIG_HOME}/pva/1.3/pvacms.p12
        # export EPICS_PVACMS_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.3/pvacms.p12


4. Admin User
^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        # Configure ADMIN user client certificate (will be created for you)
        # Environment: EPICS_ADMIN_TLS_KEYCHAIN
        # Default    : ${XDG_CONFIG_HOME}/pva/1.3/admin.p12
        # export EPICS_ADMIN_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.3/admin.p12

        # Configure PVACMS ADMIN user access control file
        # Environment: EPICS_PVACMS_ACF
        # Default    : ${XDG_CONFIG_HOME}/pva/1.3/pvacms.acf
        # export EPICS_PVACMS_ACF=${XDG_CONFIG_HOME}/pva/1.3/pvacms.acf


5. Run PVACMS
^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### RUN PVACMS
        #
        # 1. Create root CA
        #   - creates root CA if does not exist,
        #   - at location specified by EPICS_CA_TLS_KEYCHAIN or ${XDG_CONFIG_HOME}/pva/1.3/ca.p12,
        #   - with CN specified by EPICS_CA_NAME
        #   - with  O specified by EPICS_CA_ORGANIZATION
        #   - with OU specified by EPICS_CA_ORGANIZATIONAL_UNIT
        #
        # 2. Create the PVACMS server certificate
        #   - creates server certificate if does not exist,
        #   - at location specified by EPICS_PVACMS_TLS_KEYCHAIN or ${XDG_CONFIG_HOME}/pva/1.3/pvacms.p12,
        #
        # 3. Create PVACMS certificate database
        #   - creates database if does not exist
        #   - at location pointed to by EPICS_PVACMS_DB or ${XDG_DATA_HOME}/pva/1.3/certs.db
        #
        # 4. Create the default ACF file that controls permissions for the PVACMS service
        #   - creates default ACF (or yaml) file
        #   - at location pointed to by EPICS_PVACMS_ACF or ${XDG_CONFIG_HOME}/pva/1.3/pvacms.acf
        #
        # 5. Create the default admin client certificate that can be used to access PVACMS admin functions like REVOKE and APPROVE
        #   - creates default admin client certificate
        #   - at location specified by EPICS_ADMIN_TLS_KEYCHAIN or ${XDG_CONFIG_HOME}/pva/1.3/admin.p12,
        #
        # 6. Start PVACMS service with verbose logging

        ${PROJECT_HOME}/pvxs/bin/*/pvacms

        ...

        Certificate DB created  : /root/.local/share/pva/1.3/certs.db
        Keychain file created   : /root/.config/pva/1.3/ca.p12
        Created Default ACF file: /root/.config/pva/1.3/pvacms.acf
        Keychain file created   : /root/.config/pva/1.3/admin.p12
        Keychain file created   : /root/.config/pva/1.3/pvacms.p12
        PVACMS [6caf749c] Service Running

Note the ``6caf749c`` is the issuer ID which is comprised of the first 8 characters
of the hex Subject Key Identifier of the CA certificate.

Leave this PVACMS service running for while running server and client below.

.. _spva_qs_server:

SPVA Server
---------------

1. Keychain Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### Set keychain path (keychain will be created here if it doesn't already exist)
        # An EPICS server agent Key and Certificate combined
        # Environment: EPICS_PVAS_TLS_KEYCHAIN
        # Default    : ${XDG_CONFIG_HOME}/pva/1.3/server.p12
        export EPICS_PVAS_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.3/server.p12

2. Create Certificate
^^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### 1. Create a new server private key and certificate at location specified by EPICS_PVAS_TLS_KEYCHAIN

        ${PROJECT_HOME}/pvxs/bin/*/authnstd -u server \
          -N "IOC1" \
          -O "KLI:LI01:10" \
          -o "FACET"

        ...

        Keychain file created   : /root/.config/pva/1.3/server.p12
        Certificate identifier  : 6caf749c:853259638908858244

        ...

Note the certificate ID ``6caf749c:853259638908858244``.
You will need ID to carry out operations on this certificate including APPROVING it.

3. Verify that certificate is created pending approval
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### 1. Get the current status of a certificate

        ${PROJECT_HOME}/pvxs/bin/*/pvxcert 6caf749c:853259638908858244


4. Approve certificate
^^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### 1. Use a user that has access to the admin certificate and point EPICS_PVA_TLS_KEYCHAIN to it
        # Environment: EPICS_PVA_TLS_KEYCHAIN
        # Default    : ${XDG_CONFIG_HOME}/pva/1.3/client.p12
        export EPICS_PVA_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.3/admin.p12

        #### 2. Approve the certificate
        ${PROJECT_HOME}/pvxs/bin/*/pvxcert --approve 6caf749c:853259638908858244


5. Check the certificate status has changed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### 1. Get the current status of a certificate

        ${PROJECT_HOME}/pvxs/bin/*/pvxcert 6caf749c:853259638908858244


6. Run an SPVA Service
^^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        ${PROJECT_HOME}/pvxs/bin/*/softIocPVX \
            -m user=test,N=tst,P=tst \
            -d ${PROJECT_HOME}/pvxs/test/testioc.db \
            -d ${PROJECT_HOME}/pvxs/test/testiocg.db \
            -d ${PROJECT_HOME}/pvxs/test/image.db \
            -G ${PROJECT_HOME}/pvxs/test/image.json \
            -a ${PROJECT_HOME}/pvxs/test/testioc.acf


.. _spva_qs_client:

SPVA Client
---------------

1. Keychain Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### Set keychain paths (keychain file will be created here if it doesn't already exist)
        # An EPICS client agent certificate if required
        # Environment: EPICS_PVA_TLS_KEYCHAIN
        # Default    : ${XDG_CONFIG_HOME}/pva/1.3/client.p12
        export EPICS_PVA_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.3/client.p12

2. Create Certificate
^^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### 1. Create client key and certificate at location specified by EPICS_PVA_TLS_KEYCHAIN

        ${PROJECT_HOME}/pvxs/bin/*/authnstd -u client \
          -N "greg" \
          -O "SLAC.STANFORD.EDU" \
          -o "Controls"


3. Approve certificate
^^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### 1. Use a user that has access to the admin certificate and point EPICS_PVA_TLS_KEYCHAIN to it
        # Environment: EPICS_PVA_TLS_KEYCHAIN
        # Default    : ${XDG_CONFIG_HOME}/pva/1.3/admin.p12
        export EPICS_PVA_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.3/admin.p12

        #### 2. Approve the certificate
        ${PROJECT_HOME}/pvxs/bin/*/pvxcert --approve 6caf749c:389088582448532596


4. Run an SPVA Client
^^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        export EPICS_PVA_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.3/client.p12

        ${PROJECT_HOME}/pvxs/bin/*/pvxget -F tree test:structExample
