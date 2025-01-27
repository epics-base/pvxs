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


1. Create a container from the image
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        # docker run -it --name <container_name> <image> /bin/bash
        docker run -it --name ubuntu_pvxs ubuntu:latest /bin/bash


Build & Deploy
--------------


1. Initialise Environment
^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        # Make working directory for building project files
        export PROJECT_HOME=/opt/epics
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


.. _spva_qs_add_users:


Add Quick Start Users
---------------------


1. Add pvacms user
^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh


        # Add user and when prompted use "PVACMS Server" as Full Name
        adduser pvacms


    .. code-block:: sh


        # Set up environment for pvacms server
        su - pvacms


    .. code-block:: sh

        cat >> ~/.bashrc <<EOF

        export XDG_DATA_HOME=\${XDG_DATA_HOME-~/.local/share}
        export XDG_CONFIG_HOME=\${XDG_CONFIG_HOME-~/.config}
        export PROJECT_HOME=/opt/epics

        #### [optional] Set path and name of the CA database file (default: ./certs.db)
        # Environment: EPICS_PVACMS_DB
        # Default    : \${XDG_DATA_HOME}/pva/1.3/certs.db
        # export EPICS_PVACMS_DB=\${XDG_DATA_HOME}/pva/1.3/certs.db

        #### SETUP CA KEYCHAIN FILE
        # Place your CA's certificate and key in this file if you have one
        # otherwise the CA certificate will be created by PVACMS
        # Environment: EPICS_CA_TLS_KEYCHAIN
        # Default    : \${XDG_CONFIG_HOME}/pva/1.3/ca.p12
        # export EPICS_CA_TLS_KEYCHAIN=\${XDG_CONFIG_HOME}/pva/1.3/ca.p12

        # Specify the name of your CA
        # Environment: EPICS_CA_NAME, EPICS_CA_ORGANIZATION, EPICS_CA_ORGANIZATIONAL_UNIT
        # Default    : CN=EPICS Root CA, O=ca.epics.org, OU=EPICS Certificate Authority,
        # export EPICS_CA_NAME="EPICS Root CA"
        # export EPICS_CA_ORGANIZATION="ca.epics.org"
        # export EPICS_CA_ORGANIZATIONAL_UNIT="EPICS Certificate Authority"

        #### SETUP PVACMS KEYCHAIN FILE
        # Environment: EPICS_PVACMS_TLS_KEYCHAIN
        # Default    : \${XDG_CONFIG_HOME}/pva/1.3/pvacms.p12
        # export EPICS_PVACMS_TLS_KEYCHAIN=\${XDG_CONFIG_HOME}/pva/1.3/pvacms.p12

        # Configure ADMIN user client certificate (will be created for you)
        # This file will be copied to the admin user
        # Environment: EPICS_ADMIN_TLS_KEYCHAIN
        # Default    : \${XDG_CONFIG_HOME}/pva/1.3/admin.p12
        # export EPICS_ADMIN_TLS_KEYCHAIN=\${XDG_CONFIG_HOME}/pva/1.3/admin.p12

        # Configure PVACMS ADMIN user access control file
        # Environment: EPICS_PVACMS_ACF
        # Default    : \${XDG_CONFIG_HOME}/pva/1.3/pvacms.acf
        # export EPICS_PVACMS_ACF=\${XDG_CONFIG_HOME}/pva/1.3/pvacms.acf

        # set path
        export PATH="\$(echo \${PROJECT_HOME}/pvxs/bin/*):$PATH"

        cd ~
        EOF

        exit


2. Add admin user
^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        # Add user and when prompted use "ADMIN User" as Full Name
        adduser admin


    .. code-block:: sh

        # Set up environment for pvacms server
        su - admin


    .. code-block:: sh

        cat >> ~/.bashrc <<EOF

        export XDG_DATA_HOME=\${XDG_DATA_HOME-~/.local/share}
        export XDG_CONFIG_HOME=\${XDG_CONFIG_HOME-~/.config}
        export PROJECT_HOME=/opt/epics

        #### SETUP ADMIN KEYCHAIN FILE (will be copied from PVACMS)
        # Environment: EPICS_PVA_TLS_KEYCHAIN
        # Default    : \${XDG_CONFIG_HOME}/pva/1.3/client.p12
        # export EPICS_PVA_TLS_KEYCHAIN=\${XDG_CONFIG_HOME}/pva/1.3/client.p12

        # set path
        export PATH="\$(echo \${PROJECT_HOME}/pvxs/bin/*):$PATH"

        cd ~
        EOF

        exit

3. Add Soft IOC user
^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        # Add user and when prompted use "SOFTIOC Server" as Full Name
        adduser softioc


    .. code-block:: sh

        # Set up environment for pvacms server
        su - softioc


    .. code-block:: sh

        cat >> ~/.bashrc <<EOF

        export XDG_DATA_HOME=\${XDG_DATA_HOME-~/.local/share}
        export XDG_CONFIG_HOME=\${XDG_CONFIG_HOME-~/.config}
        export PROJECT_HOME=/opt/epics

        #### SETUP SOFTIOC KEYCHAIN FILE
        # Environment: EPICS_PVAS_TLS_KEYCHAIN
        # Default    : \${XDG_CONFIG_HOME}/pva/1.3/server.p12
        export EPICS_PVAS_TLS_KEYCHAIN=\${XDG_CONFIG_HOME}/pva/1.3/server.p12

        # set path
        export PATH="\$(echo \${PROJECT_HOME}/pvxs/bin/*):$PATH"

        cd ~
        EOF

        exit

4. Add SPVA Client user
^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        # Add user and when prompted use "SPVA Client" as Full Name
        adduser client


    .. code-block:: sh

        # Set up environment for pvacms server
        su - client

    .. code-block:: sh

        cat >> ~/.bashrc <<EOF

        export XDG_DATA_HOME=\${XDG_DATA_HOME-~/.local/share}
        export XDG_CONFIG_HOME=\${XDG_CONFIG_HOME-~/.config}
        export PROJECT_HOME=/opt/epics

        #### SETUP SPVA Client KEYCHAIN FILE
        # Environment: EPICS_PVA_TLS_KEYCHAIN
        # Default    : \${XDG_CONFIG_HOME}/pva/1.3/client.p12
        export EPICS_PVA_TLS_KEYCHAIN=\${XDG_CONFIG_HOME}/pva/1.3/client.p12

        # set path
        export PATH="\$(echo \${PROJECT_HOME}/pvxs/bin/*):$PATH"

        cd ~
        EOF

        exit


.. _spva_qs_pvacms:

PVACMS
---------------

1. Login as pvacms in a new shell
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        # If you're using docker
        docker exec -it --user pvacms ubuntu_pvxs /bin/bash


2. Run PVACMS
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

        pvacms

        ...

        Certificate DB created  : /home/pvacms/.local/share/pva/1.3/certs.db
        Keychain file created   : /home/pvacms/.config/pva/1.3/ca.p12
        Created Default ACF file: /home/pvacms/.config/pva/1.3/pvacms.acf
        Keychain file created   : /home/pvacms/.config/pva/1.3/admin.p12
        Keychain file created   : /home/pvacms/.config/pva/1.3/pvacms.p12
        PVACMS [6caf749c] Service Running

Note the ``6caf749c`` is the issuer ID which is comprised of the first 8 characters
of the hex Subject Key Identifier of the CA certificate.

Leave this PVACMS service running while running SoftIOC and SPVA client below.

3. Copy Admin Certificate to Admin user
^^^^^^^^^^^^^^^

In the root shell (not PVACMS shell)

    .. code-block:: sh

        mkdir -p ~admin/.config/pva/1.3
        cp -pr ~pvacms/.config/pva/1.3/admin.p12 ~admin/.config/pva/1.3/client.p12
        chown admin ~admin/.config/pva/1.3/client.p12
        chmod 400 ~admin/.config/pva/1.3/client.p12


.. _spva_qs_server:

Secure PV Access SoftIOC Server
-------------------------------

1. Login as softioc in a new shell
^^^^^^^^^^^^^^^

    .. code-block:: sh

        # If you're using docker
        docker exec -it --user softioc ubuntu_pvxs /bin/bash


2. Create Certificate
^^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### 1. Create a new server private key and certificate at location specified by EPICS_PVAS_TLS_KEYCHAIN

        authnstd -u server \
          -N "IOC1" \
          -O "KLI:LI01:10" \
          -o "FACET"

        ...

        Keychain file created   : /home/softioc/.config/pva/1.3/server.p12
        Certificate identifier  : 6caf749c:853259638908858244

        ...

Note the certificate ID ``6caf749c:853259638908858244`` (<issuer_id>:<serial_number>).
You will need this ID to carry out operations on this certificate including APPROVING it.

3. Verify that certificate is created pending approval
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### 1. Get the current status of a certificate

        pvxcert <issuer_id>:<serial_number>


4. Approve certificate
^^^^^^^^^^^^^^^^^^^^^^^^^^


    .. code-block:: sh

        #### 1. Login as admin in a new shell
        docker exec -it --user admin ubuntu_pvxs /bin/bash

        #### 2. Approve the certificate
        pvxcert --approve <issuer_id>:<serial_number>


5. Check the certificate status has changed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### 1. Back in softIOC shell, get the current status of a certificate

        pvxcert <issuer_id>:<serial_number>


6. Run an SPVA Service
^^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        softIocPVX \
            -m user=test,N=tst,P=tst \
            -d ${PROJECT_HOME}/pvxs/test/testioc.db \
            -d ${PROJECT_HOME}/pvxs/test/testiocg.db \
            -d ${PROJECT_HOME}/pvxs/test/image.db \
            -G ${PROJECT_HOME}/pvxs/test/image.json \
            -a ${PROJECT_HOME}/pvxs/test/testioc.acf


.. _spva_qs_client:

SPVA Client
---------------

1. Login as client in a new shell
^^^^^^^^^^^^^^^

    .. code-block:: sh

        # If you're using docker
        docker exec -it --user client ubuntu_pvxs /bin/bash



2. Create Certificate
^^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### 1. Create client key and certificate at location specified by EPICS_PVA_TLS_KEYCHAIN

        authnstd -u client \
          -N "greg" \
          -O "SLAC.STANFORD.EDU" \
          -o "Controls"


4. Approve certificate
^^^^^^^^^^^^^^^^^^^^^^^^^^


    .. code-block:: sh

        #### 1. Switch back to admin shell

        #### 2. Approve the certificate
        pvxcert --approve <issuer_id>:<serial_number>


4. Run an SPVA Client
^^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### 1. Back in client shell, get a value from the SoftIOC

        pvxget -F tree test:structExample

        #### 2. Show that the configuration is using TLS
        pvxinfo -v test:enumExample

        #### 3. Show a connection without TLS
        env -u EPICS_PVA_TLS_KEYCHAIN pvxinfo -v test:enumExample
