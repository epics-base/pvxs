.. _quick_start:

Secure PVA Quick Start
================

Build & Deploy
----------------

See :ref:`secure_pvaccess` for detailed documentation

1. Initialise Environment
^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        # Set up data and configuration home if not already set
        # export XDG_DATA_HOME=${XDG_DATA_HOME-~/.local/share}
        # export XDG_CONFIG_HOME=${XDG_CONFIG_HOME-~/.config}
        # mkdir -p ${XDG_DATA_HOME}/pva/1.3 ${XDG_CONFIG_HOME}/pva/1.3

        # Make working directory for building project files
        export PROJECT_HOME=~/src
        mkdir -p ${PROJECT_HOME}

2. Install Requirements
^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

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
            pkg-config \
            zsh

        # For RHEL/CentOS/Rocky/Alma Linux/Fedora

        dnf install -y \
            gcc-c++ \
            git \
            make \
            openssl-devel \
            libevent-devel \
            sqlite-devel \
            libcurl-devel \
            pkg-config \
            zsh

        # For macOS

        brew update
        brew install \
            openssl@3 \
            libevent \
            sqlite3 \
            curl \
            pkg-config \
            zsh

        # For Alpine Linux

        apk add --no-cache \
            build-base \
            git \
            openssl-dev \
            libevent-dev \
            sqlite-dev \
            curl-dev \
            pkgconfig \
            zsh

        # For RTEMS
        # First install RTEMS toolchain from https://docs.rtems.org/branches/master/user/start/
        # Then ensure these are built into your BSP:
        #   - openssl
        #   - libevent
        #   - sqlite
        #   - libcurl
        # Note: RTEMS support requires additional configuration. See RTEMS-specific documentation.

3. Build epics-base
^^^^^^^^^^^^^^^-^

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
^^^^^^^^^^^^

    .. code-block:: sh

        cd ${PROJECT_HOME}
        git clone --recursive  --branch tls https://github.com/george-mcintyre/pvxs.git
        cd pvxs

        # Build PVXS

        make -j10 all
        cd ${PROJECT_HOME}


PVACMS Quick Start
---------------

1. Database configuration
^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### [optional] Set path and name of the CA database file (default: ./certs.db)
        # Environment: EPICS_PVACMS_DB
        # Default    : ${XDG_DATA_HOME}/pva/1.3/certs.db
        # export EPICS_PVACMS_DB=${XDG_DATA_HOME}/pva/1.3/certs.db


2. Certificate Authority
^^^^^^^^^^^^^^^

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
        export EPICS_CA_NAME="EPICS Test Root CA"
        # export EPICS_CA_ORGANIZATION="ca.epics.org"
        # export EPICS_CA_ORGANIZATIONAL_UNIT="EPICS Certificate Authority"


3. Server Certificate
^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### SETUP PVACMS KEYCHAIN FILE
        # Environment: EPICS_PVACMS_TLS_KEYCHAIN
        # Default    : ${XDG_CONFIG_HOME}/pva/1.3/pvacms.p12
        # export EPICS_PVACMS_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.3/pvacms.p12


4. Admin User
^^^^^^^^^^^^^^^

    .. code-block:: sh

        # Configure ADMIN user client certificate (will be created for you)
        # Environment: EPICS_ADMIN_TLS_KEYCHAIN
        # Default    : ${XDG_CONFIG_HOME}/pva/1.3/admin.p12
        # export EPICS_ADMIN_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.3/admin.p12

        # Configure PVACMS ADMIN user access control file
        # Environment: EPICS_PVACMS_ACF
        # Default    : ${XDG_CONFIG_HOME}/pva/1.3/pvacms.acf
        # export EPICS_PVACMS_ACF=${XDG_CONFIG_HOME}/pva/1.3/pvacms.acf

    .. code-block:: sh

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

        ${PROJECT_HOME}/pvxs/bin/*/pvacms -v

        ...

        Effective config
        EPICS_PVAS_AUTO_BEACON_ADDR_LIST=YES
        EPICS_PVAS_BROADCAST_PORT=5076
        EPICS_PVAS_SERVER_PORT=5075
        EPICS_PVAS_TLS_KEYCHAIN=/root/.config/pva/1.3/pvacms.p12
        EPICS_PVAS_TLS_OPTIONS=client_cert=optional on_expiration=fallback-to-tcp no_revocation_check on_no_cms=fallback-to-tcp
        EPICS_PVAS_TLS_PORT=5076
        EPICS_PVAS_TLS_STOP_IF_NO_CERT=YES
        PVACMS [6caf749c] Service Running

Note the `6caf749c` is the issuer ID which is comprised of the first 8 characters
of the hex Subject Key Identifier of the CA certificate.

SPVA-SERVER Quick Start
---------------

1. Keychain Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### Set keychain path (keychain will be created here if it doesn't already exist)
        # An EPICS server agent Key and Certificate combined
        # Environment: EPICS_PVAS_TLS_KEYCHAIN
        # Default    : ${XDG_CONFIG_HOME}/pva/1.3/server.p12
        # export EPICS_PVAS_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.3/server.p12

2. Create Certificate
^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### 1. Create a new server private key and certificate at location specified by EPICS_PVAS_TLS_KEYCHAIN

        ${PROJECT_HOME}/pvxs/bin/*/authnstd -v -u server \
          -N "IOC1" \
          -O "KLI:LI01:10" \
          -o "FACET"

        ...

        Certificate created: 6caf749c:853259638908858244

        ...

Note the certificate ID `6caf749c:853259638908858244`.
You will need ID to carry out operations on this certificate including APPROVING it.

3. PENDING_APPROVAL check
^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### 1. Get the current status of a certificate

        ${PROJECT_HOME}/pvxs/bin/*/pvxcert 6caf749c:853259638908858244

        Get Status ==> CERT:STATUS:6caf749c:853259638908858244
            status.value.index int32_t = 1
            status.value.choices string[] = {6}["UNKNOWN", "PENDING_APPROVAL", "PENDING", "VALID", "EXPIRED", "REVOKED"]
            status.timeStamp.secondsPastEpoch int64_t = 1732078162
            serial uint64_t = 853259638908858244
            state string = "PENDING_APPROVAL"
            ocsp_status.value.choices string[] = {3}["OCSP_CERTSTATUS_GOOD", "OCSP_CERTSTATUS_REVOKED", "OCSP_CERTSTATUS_UNKNOWN"]
            ocsp_status.timeStamp.secondsPastEpoch int64_t = 1732078162
            ocsp_state string = "OCSP_CERTSTATUS_UNKNOWN"
            ocsp_status_date string = "Wed Nov 20 04:49:22 2024 UTC"
            ocsp_certified_until string = "Wed Nov 20 05:19:22 2024 UTC"
            ocsp_revocation_date string = "Thu Jan 01 00:00:00 1970 UTC"
            ocsp_response uint8_t[] = {1607}[48, 130, 6, 67, 10, 1, 0, 160, 130, 6, 60, 48, 130, 6, 56, 6, 9, 43, 6, 1, ...]

4. APPROVE certificate
^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### 1. Use a user that has access to the admin certificate and point EPICS_PVA_TLS_KEYCHAIN to it
        # Environment: EPICS_PVA_TLS_KEYCHAIN
        # Default    : ${XDG_CONFIG_HOME}/pva/1.3/admin.p12
        # export EPICS_PVA_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.3/admin.p12

        #### 2. Approve the certificate
        ${PROJECT_HOME}/pvxs/bin/*/pvxcert --approve 6caf749c:853259638908858244


5. VALID check
^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### 1. Get the current status of a certificate

        ${PROJECT_HOME}/pvxs/bin/*/pvxcert 6caf749c:853259638908858244

        Get Status ==> CERT:STATUS:6caf749c:853259638908858244
            status.value.index int32_t = 3
            status.value.choices string[] = {6}["UNKNOWN", "PENDING_APPROVAL", "PENDING", "VALID", "EXPIRED", "REVOKED"]
            status.timeStamp.secondsPastEpoch int64_t = 1732078162
            serial uint64_t = 853259638908858244
            state string = "VALID"
            ocsp_status.value.choices string[] = {3}["OCSP_CERTSTATUS_GOOD", "OCSP_CERTSTATUS_REVOKED", "OCSP_CERTSTATUS_UNKNOWN"]
            ocsp_status.timeStamp.secondsPastEpoch int64_t = 1732078162
            ocsp_state string = "OCSP_CERTSTATUS_GOOD"
            ocsp_status_date string = "Wed Nov 20 04:49:22 2024 UTC"
            ocsp_certified_until string = "Wed Nov 20 05:19:22 2024 UTC"
            ocsp_revocation_date string = "Thu Jan 01 00:00:00 1970 UTC"
            ocsp_response uint8_t[] = {1607}[48, 130, 6, 67, 10, 1, 0, 160, 130, 6, 60, 48, 130, 6, 56, 6, 9, 43, 6, 1, ...]

6. Run an SPVA Service
^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        ${PROJECT_HOME}/pvxs/bin/*/softIocPVX \
            -m user=test,N=tst,P=tst \
            -d ${PROJECT_HOME}/pvxs/test/testioc.db \
            -d ${PROJECT_HOME}/pvxs/test/testiocg.db \
            -d ${PROJECT_HOME}/pvxs/test/image.db \
            -G ${PROJECT_HOME}/pvxs/test/image.json \
            -a ${PROJECT_HOME}/pvxs/test/testioc.acf


SPVA-CLIENT Quick Start
---------------

1. Keychain Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### Set keychain paths (keychain file will be created here if it doesn't already exist)
        # An EPICS client agent certificate if required
        # Environment: EPICS_PVA_TLS_KEYCHAIN
        # Default    : ${XDG_CONFIG_HOME}/pva/1.3/client.p12
        # export EPICS_PVA_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.3/client.p12

2. Create Certificate
^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### 1. Create client key and certificate at location specified by EPICS_PVA_TLS_KEYCHAIN

        ${PROJECT_HOME}/pvxs/bin/*/authnstd -v -u client \
          -N "greg" \
          -O "SLAC.STANFORD.EDU" \
          -o "Controls"

        ...

        Certificate created: 6caf749c:389088582448532596

        ...


3. APPROVE certificate
^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        #### 1. Use a user that has access to the admin certificate and point EPICS_PVA_TLS_KEYCHAIN to it
        # Environment: EPICS_PVA_TLS_KEYCHAIN
        # Default    : ${XDG_CONFIG_HOME}/pva/1.3/admin.p12
        # export EPICS_PVA_TLS_KEYCHAIN=${XDG_CONFIG_HOME}/pva/1.3/admin.p12

        #### 2. Approve the certificate
        ${PROJECT_HOME}/pvxs/bin/*/pvxcert --approve 6caf749c:389088582448532596


4. Run an SPVA Client
^^^^^^^^^^^^^^^^^^^^

    .. code-block:: sh

        ${PROJECT_HOME}/pvxs/bin/*/pvxget test:structExample
