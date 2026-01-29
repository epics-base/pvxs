.. _quick_start_jwt:

|guide| Quick Start JWT - OUT OF SCOPE!
==================================================

    OUT OF SCOPE!  This feature is not Included in the scope of this project

This section contains a Quick Start |guide| for the Secure PVAccess *Java Web Token (JWT) Authenticator*.

    The JWT Authenticator is an Authenticator that uses a JSON Web Token (JWT) to create an X.509 certificate.

    It verifies the token’s signature and claims (such as the issuer and expiration time) to ensure the token’s authenticity.

    The token’s subject (``sub``) is used as the certificate’s Common Name, and the token’s issuer (``iss``)
    (or associated domain) is used for the Organization field (the Organizational Unit is left blank by default).

    The token is sent to the PVACMS, which validates the token (checking the signature and payload
    against the trusted issuer). If the token is valid, PVACMS generates a signed certificate in the
    ``VALID`` state using the token’s identity information.

Our starting point for this Quick Start Guide is the end of the :ref:`quick_start_std` so if you haven't gone through it yet
do that now then come back here.  You need to have users's configured (``pvacms``, ``admin``, ``client``, and ``client``).
We will set up a containerized JWT environment to simulate an identity provider and issue tokens for our users.
We will also configure PVACMS to trust the JWT issuer's validation URI. Then we’ll use a JWT to obtain certificates for a
server and a client, and demonstrate a Secure PVAccess connection using those certificates.

See :ref:`secure_pvaccess` for general documentation on Secure PVAccess.

Other Quick Start Guides:

- :ref:`quick_start`
- :ref:`quick_start_std`
- :ref:`quick_start_krb`
- :ref:`quick_start_ldap`
- :ref:`quick_start_gw`

|learn| You will learn:
******************************

- :ref:`Creating a Sample JWT Issuer & Validator in a Container <spva_qs_jwt_kdc>`,
- :ref:`Building PVXS with Java Web Token (JWT) Authenticator support <spva_qs_jwt_build>`,
- :ref:`Configuring PVACMS for Java Web Tokens (JWT) <spva_qs_jwt_pvacms>`,
- :ref:`Creating certificates using the Java Web Token (JWT) Authenticator<spva_qs_jwt_server>` and
- :ref:`Connecting a Java Web Token (JWT) Client to an SPVA Server<spva_qs_jwt_client>`

|pre-packaged|\Prepackaged
******************************

If you want a prepackaged environment, try the following.  You will need three terminal sessions.

|1| Load image
------------------------------

- |terminal|\¹
- Start the container with a prepackaged Secure PVAccess environment that includes JWT support

.. code-block:: shell

    docker run -it --name spva_jwt georgeleveln/spva_jwt:latest

.. code-block:: console

    2025-03-08 14:40:43,319 CRIT Supervisor is running as root.  Privileges were not dropped because no user is specified in the config file.  If you intend to run as root, you can set user=root in the config file to avoid this message.
    2025-03-08 14:40:43,319 INFO Included extra file "/etc/supervisor/conf.d/jwt-issuer.conf" during parsing
    2025-03-08 14:40:43,319 INFO Included extra file "/etc/supervisor/conf.d/pvacms.conf" during parsing
    2025-03-08 14:40:43,322 INFO supervisord started with pid 1
    2025-03-08 14:40:44,334 INFO spawned: 'jwt-issuer' with pid 7
    2025-03-08 14:40:44,346 INFO spawned: 'pvacms' with pid 9
    2025-03-08 14:40:45,589 INFO success: jwt5-issuer entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
    2025-03-08 14:40:45,589 INFO success: pvacms entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)

|2| Service
------------------------------

- |terminal|\²
- log in as service account

.. code-block:: shell

    docker exec -it --user softioc spva_jwt /bin/bash

- get a token.  Use "secret" as the password

.. code-block:: shell

    TOKEN=$(curl -s "http://localhost:8080/default/token?sub=softioc&password=secret")
    echo ${TOKEN} > token_file

.. code-block:: console

    curl -sG --data-urlencode "token=$TOKEN" "http://localhost:8080/default/verify"

.. code-block:: console

    {"claims":{"aud":"default","exp":1755150736,"iat":1755147136,"iss":"http://localhost:8080/default","jti":"c40d1fc2-40f2-4bf9-a84a-fff5fadea38a","nbf":1755147136,"sub":"softioc"},"header":{"alg":"RS256","kid":"demo-key-1","typ":"JWT"},"valid":true}

- create a server certificate using the Java Web Token (JWT) Authenticator

.. code-block:: shell

    authnjwt -u server --token-file token_file

.. code-block:: console

    Keychain file created   : /home/softioc/.config/pva/1.4/server.p12
    Certificate identifier  : 47530d89:3826361579604613180

.. code-block:: shell

    pvxcert -f ~/.config/pva/1.4/server.p12

.. code-block:: console

    Certificate Details:
    ============================================
    Certificate ID : 47530d89:3826361579604613180
    Entity Subject : CN=softioc, O=localhost
    Issuer Subject : CN=EPICS Root Certificate Authority, C=US, O=certs.epics.org, OU=EPICS Certificate Authority
    Valid From     : Sat Mar 08 15:23:21 2025 UTC
    Expires On     : Sun Mar 09 15:23:09 2025 UTC
    --------------------------------------------

    Certificate Status:
    ============================================
    Certificate ID: 47530d89:3826361579604613180
    Status        : VALID
    Status Issued : Sat Mar 08 15:47:14 2025 UTC
    Status Expires: Sat Mar 08 16:17:14 2025 UTC
    --------------------------------------------

|3| Client
------------------------------

- |terminal|\³
- log in as a Secure PVAccess client

.. code-block:: shell

    docker exec -it --user client spva_jwt /bin/bash

- get a token.  Use "secret" as the password

.. code-block:: shell

    TOKEN=$(curl -s "http://localhost:8080/default/token?sub=client&password=secret")
    echo ${TOKEN} > token_file

.. code-block:: console

    curl -sG --data-urlencode "token=$TOKEN" "http://localhost:8080/default/verify"

.. code-block:: console

    {"claims":{"aud":"default","exp":1755150140,"iat":1755146540,"iss":"http://localhost:8080/default","jti":"c7cad85c-ae49-49cc-abf7-c3be923ce06b","nbf":1755146540,"sub":"client"},"header":{"alg":"RS256","kid":"demo-key-1","typ":"JWT"},"valid":true}


.. code-block:: console

    { "valid": true, "claims": { "sub": "client", ... } }

- create a client certificate using the Java Web Token (JWT) Authenticator

.. code-block:: shell

    authnjwt --token-file token_file

.. code-block:: console

    Keychain file created   : /home/client/.config/pva/1.4/client.p12
    Certificate identifier  : 47530d89:15177030356392297708

.. code-block:: shell

    pvxcert -f ~/.config/pva/1.4/client.p12

.. code-block:: console

    Certificate Details:
    ============================================
    Certificate ID : 47530d89:15177030356392297708
    Entity Subject : CN=client, O=localhost
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
        -a ${PROJECT_HOME}/pvxs/test/testioc.tls.acf

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
    EPICS_PVA_TLS_KEYCHAIN=/home/client/.config/pva/1.4/client.p12
    EPICS_PVA_TLS_OPTIONS=on_expiration=fallback-to-tcp
    EPICS_PVA_TLS_PORT=5076
    XDG_CONFIG_HOME=/home/client/.config/pva/1.4
    XDG_DATA_HOME=/home/client/.local/share/pva/1.4
    # TLS x509:47530d89:3826361579604613181:EPICS Root Certificate Authority/client@172.17.0.2:34381
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

- ``TLS x509:47530d89:3826361579604613181:EPICS Root Certificate Authority/client @ 172.17.0.2`` indicates that:

  - The connection is ``TLS``,
  - The Server end of the channel has been authenticated by the Root Certificate Authority ``EPICS Root Certificate Authority``
  - The Server end of the channel's name has been authenticated as ``client`` and is connecting from host ``172.17.0.2``

|step-by-step| Step-By-Step
********************************

+------------------------------------+------------------------------+------------------------------------------------+-----------------------------------------------------------------------+
| Env. *pvacms*                      | Params. *pvacms*             | Keys and Values                                | Description                                                           |
+====================================+==============================+================================================+=======================================================================+
|  EPICS_AUTH_JWT_REQUEST_FORMAT     |  ``--jwt-request-format``    | string format for verification request payload |  A string that is used verbatim as the payload for the verification   |
|                                    |                              |                                                |  request while substituting the string ``#token#`` for the token      |
|                                    |                              |                                                |  value, and ``#kid#`` for the key id. This is used when the           |
|                                    |                              | e.g. ``{ "token": "#token#" }``                |  verification server requires a formatted payload for the             |
|                                    |                              |                                                |  verification request. If the string is simply ``#token#`` (default)  |
|                                    |                              | e.g. ``#token#``                               |  then the verification endpoint is called with the raw token as       |
|                                    |                              |                                                |  the payload.                                                         |
+------------------------------------+------------------------------+------------------------------------------------+-----------------------------------------------------------------------+
|  EPICS_AUTH_JWT_REQUEST_METHOD     |  ``--jwt-request-method``    | ``POST`` (default)                             |  This determines whether the endpoint will be called with             |
|                                    |                              | ``GET```                                       |  ``HTTP GET`` or ``POST`` .                                           |
|                                    |                              |                                                |  If called with ``POST``, then the payload is exactly what is defined |
|                                    |                              | e.g. of call made for GET:                     |  by the ``EPICS_AUTH_JWT_RESPONSE_FORMAT`` variable.                  |
|                                    |                              |                                                |  If called with GET, then the token is passed in the                  |
|                                    |                              | **GET** /api/validate-token HTTP/1.1           |  **Authorization** header of the ``HTTP GET`` request                 |
|                                    |                              |                                                |                                                                       |
|                                    |                              | **Authorization**: Bearer eyJhbGcXVCJ9...      |                                                                       |
+------------------------------------+------------------------------+------------------------------------------------+-----------------------------------------------------------------------+
|  EPICS_AUTH_JWT_RESPONSE_FORMAT    |  ``--jwt-response-format``   | string format for verification response value  |  A pattern string that we can use to decode the response from a       |
|                                    |                              |                                                |  verification endpoint if the response is formatted text. All white   |
|                                    |                              |                                                |  space is removed in the given string and in the response. Then all   |
|                                    |                              | e.g. ``{ "payload": { * },``                   |  the text prior to ``#response#`` is matched and removed from the     |
|                                    |                              |      ``  "valid": #response# }``               |  response and all the text after the response is likewise removed,    |
|                                    |                              |                                                |  what remains is the response value.                                  |
|                                    |                              | e.g. ``#response#``                            |  An asterisk in the string matches any sequence of characters in the  |
|                                    |                              |                                                |  response. It is converted to lowercase and interpreted as valid      |
|                                    |                              |                                                |  if it equals ``valid``, ``ok``, ``true``, ``t``, ``yes``, ``y``, or  |
|                                    |                              |                                                |  ``1``.  If the string is ``#response#`` (default) then the response  |
|                                    |                              |                                                |  is raw and is converted to lowercase and compared without removing   |
|                                    |                              |                                                |  any formatting                                                       |
+------------------------------------+------------------------------+------------------------------------------------+-----------------------------------------------------------------------+
|  EPICS_AUTH_JWT_TRUSTED_URI        | ``--jwt-trusted-uri``        | uri of JWT validation endpoint                 |  Trusted URI of the validation endpoint including the ``http://``,    |
|                                    |                              |                                                |  ``https://``, and port number.  There is no default, it must be      |
|                                    |                              | e.g. ``http://issuer/api/validate-token``      |  the text prior to ``#response#`` is matched and removed from the     |
|                                    |                              |                                                |  specified.  This is used to compare to the ``iss`` field in the      |
|                                    |                              |                                                |  decoded token payload if it is provided.  If it is not the same,     |
|                                    |                              |                                                |  then the validation fails.  If the ``iss`` field is missing, then    |
|                                    |                              |                                                |  the value of this variable is taken as the validation URI.           |
+------------------------------------+------------------------------+------------------------------------------------+-----------------------------------------------------------------------+
|  EPICS_AUTH_JWT_USE_RESPONSE_CODE  | ``--jwt-use-response-code``  | case insensitive:                              |  If set this tells PVACMS that when it receives a ``200``             |
|                                    |                              | ``YES``, ``TRUE``,  or ``1``                   |  HTTP-response code from the HTTP request then the token is valid,    |
|                                    |                              |                                                |  and invalid for any other response code.                             |
+------------------------------------+------------------------------+------------------------------------------------+-----------------------------------------------------------------------+


+----------------------+-----------------------------+------------------------------------------------+-----------------------------------------------------------------------+
| Env. *authnjwt*      | Params. *authjwt*           | Keys and Values                                | Description                                                           |
+======================+=============================+================================================+=======================================================================+
| EPICS_AUTH_JWT_FILE  | ``--token-file <file>``     | location of JWT file                           | file containing JWT token text                                        |
|                      |                             | e.g. ``~/.config/pva/1.4/jwt.txt``             |                                                                       |
+----------------------+-----------------------------+------------------------------------------------+-----------------------------------------------------------------------+



|step| Docker Image
------------------------------------------

|1| Use a Prepackaged spva_std image
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\¹
- open a terminal and load pre-built image
- don't forget to add /bin/bash at the end to suppress running the pvacms

.. code-block:: shell

    docker run -it --name spva_jwt georgeleveln/spva_std:latest /bin/bash

.. _spva_qs_jwt_kdc:

|step| JWT Issuer & Validator
------------------------------------------

This section shows how to install and configure a Java Web Token (JWT) Issuer & Validator.  This
is included to enable you to test the Java Web Token (JWT) Authenticator before deploying it
into your network.  It will enable you to configure EPICS agents that
have valid JWTs that can be exchanged for X.509 certificates
using the Java Web Token (JWT) Authenticator.


|1| Install prerequisites
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Add Python to run our JWT Issuer and Validator

  - python3
  - python3-pip - for package management in python
      - flask
      - pyjwt package for parsing JTWs
      - cryptography package for cryptographic keys

.. code-block:: shell

    apt-get update && \
    apt-get install -y \
      python3 python3-pip \
      python3-flask python3-jwt python3-cryptography \
      curl && \
    rm -rf /var/lib/apt/lists/*

.. code-block:: console

    Hit:1 http://ports.ubuntu.com/ubuntu-ports noble InRelease
    Get:2 http://ports.ubuntu.com/ubuntu-ports noble-updates InRelease [126 kB]
    Get:3 http://ports.ubuntu.com/ubuntu-ports noble-backports InRelease [126 kB]
    Get:4 http://ports.ubuntu.com/ubuntu-ports noble-security InRelease [126 kB]
    Get:5 http://ports.ubuntu.com/ubuntu-ports noble-updates/multiverse arm64 Packages [39.2 kB]
    Get:6 http://ports.ubuntu.com/ubuntu-ports noble-updates/universe arm64 Packages [1422 kB]
    Get:7 http://ports.ubuntu.com/ubuntu-ports noble-updates/main arm64 Packages [1705 kB]
    Get:8 http://ports.ubuntu.com/ubuntu-ports noble-updates/restricted arm64 Packages [2704 kB]
    Get:9 http://ports.ubuntu.com/ubuntu-ports noble-backports/main arm64 Packages [48.8 kB]
    Get:10 http://ports.ubuntu.com/ubuntu-ports noble-backports/universe arm64 Packages [37.2 kB] ...

.. _spva_qs_jwt_build:

|2| Rebuild pvxs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- enable Java Web Token (JWT) Authenticator by updating ``CONFIG_SITE.local``
- do a clean rebuild of pvxs

.. code-block:: shell

    export PROJECT_HOME=/opt/epics
    cd ${PROJECT_HOME}

    cat >> CONFIG_SITE.local <<EOF
    EVENT2_HAS_OPENSSL = YES
    PVXS_ENABLE_PVACMS = YES
    PVXS_ENABLE_JWT_AUTH = YES
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


|3| Configure JWT Issuer and Validator
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- configure the JWT Issuer and Validator

  - create application

.. code-block:: shell

    cat > /opt/epics/app.py <<EOF
    import base64
    import os
    import uuid
    from datetime import datetime, timedelta, timezone
    from pathlib import Path

    from flask import Flask, request, jsonify, Response
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    app = Flask(__name__)

    # --- Config (env overridable) ---
    PORT = int(os.getenv("PORT", "8080"))
    DEFAULT_ISS = os.getenv("ISSUER", "http://localhost:8080/default")
    DEFAULT_AUD = os.getenv("DEFAULT_AUDIENCE", "default")
    DEFAULT_EXP_SECS = int(os.getenv("DEFAULT_EXP_SECS", "3600"))
    ALGO = os.getenv("ALGO", "RS256")  # RS256 (default) or HS256
    KEY_DIR = Path(os.getenv("KEY_DIR", "/data/keys"))
    KID = os.getenv("KID", "demo-key-1")
    HS_SECRET = os.getenv("HS_SECRET", "dev-secret-change-me")  # only used if ALGO=HS256

    # --- Keys (ephemeral by default; files used only if writable and present) ---
    _priv_key = None
    _pub_key = None

    def _b64u(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def _ensure_keys():
        """Generate or load RSA keys for RS256. HS256 uses HS_SECRET."""
        global _priv_key, _pub_key
        if ALGO.upper() == "HS256":
            return  # nothing to do

        KEY_DIR.mkdir(parents=True, exist_ok=True)
        priv_path = KEY_DIR / "id_rsa.pem"
        pub_path = KEY_DIR / "id_rsa.pub"

        if priv_path.exists() and pub_path.exists():
            _priv_key = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
            _pub_key = serialization.load_pem_public_key(pub_path.read_bytes())
            return

        # Generate ephemeral RSA keypair
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = key.public_key()

        _priv_key = key
        _pub_key = pub

        # Best-effort write (ok if it fails; we remain in-memory)
        try:
            priv_bytes = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            pub_bytes = pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            priv_path.write_bytes(priv_bytes)
            pub_path.write_bytes(pub_bytes)
        except Exception:
            pass

    def _current_priv_key():
        return HS_SECRET if ALGO.upper() == "HS256" else _priv_key

    def _current_pub_key():
        return HS_SECRET if ALGO.upper() == "HS256" else _pub_key

    def _rsa_jwk():
        if ALGO.upper() == "HS256" or _pub_key is None:
            return []
        nums = _pub_key.public_numbers()
        n = _b64u(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big"))
        e = _b64u(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big"))
        return [{
            "kty": "RSA",
            "kid": KID,
            "alg": "RS256",
            "use": "sig",
            "n": n,
            "e": e,
        }]

    # Initialize keys at import
    _ensure_keys()

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    # Issue: GET /default/token?sub=client&password=secret[&aud=...&iss=...&exp_secs=...]
    @app.get("/default/token")
    def issue_token():
        sub = request.args.get("sub")
        pwd = request.args.get("password")
        if not sub:
            return jsonify(error="missing 'sub'"), 400
        if pwd != "secret":
            return "Forbidden", 403

        aud = request.args.get("aud", DEFAULT_AUD)
        iss = request.args.get("iss", DEFAULT_ISS)
        exp_secs = int(request.args.get("exp_secs", DEFAULT_EXP_SECS))

        now = datetime.now(timezone.utc)
        claims = {
            "sub": sub,
            "iss": iss,
            "aud": aud,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=exp_secs)).timestamp()),
            "jti": str(uuid.uuid4()),
        }

        headers = {"kid": KID, "typ": "JWT"}
        token = jwt.encode(
            claims,
            _current_priv_key(),
            algorithm=ALGO,
            headers=headers,
        )
        # Return RAW token (text/plain), not JSON
        return Response(token, mimetype="text/plain")

    # Verify: GET /default/verify?token=... [&expected_iss=...][&expected_aud=...]
    @app.get("/default/verify")
    def verify_token():
        token = request.args.get("token")
        if not token:
            return jsonify(valid=False, error="missing 'token'"), 400

        expected_iss = request.args.get("expected_iss", DEFAULT_ISS)
        expected_aud = request.args.get("expected_aud")  # optional

        options = {
            "require": ["exp", "iat", "nbf", "iss", "sub"],
            "verify_aud": bool(expected_aud),
        }

        try:
            decoded = jwt.decode(
                token,
                _current_pub_key(),
                algorithms=[ALGO],
                issuer=expected_iss,
                audience=expected_aud if expected_aud else None,
                options=options,
            )
            header = jwt.get_unverified_header(token)
            return jsonify(valid=True, header=header, claims=decoded)
        except Exception as e:
            return jsonify(valid=False, error=str(e))

    # JWKS
    @app.get("/.well-known/jwks.json")
    @app.get("/default/jwks")
    def jwks():
        return jsonify({"keys": _rsa_jwk()})

    if __name__ == "__main__":
        app.run(host="0.0.0.0", port=PORT)
    EOF

.. _spva_qs_jwt_pvacms:

|4| Configure PVACMS for Java Web Token (JWT) Authenticator
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- set up environment for pvacms
  - request contains just token, no JSON
  - use HTTP GET with parameter = ``token`` set to token value.
  - the response will be any valid JSON with a tag ``valid`` whose value will indicate whether the token is valid
  - specify the url to use to verify tokens http://localhost:8080/default/verify.
  - for verification token is URL encoded as parameter ``token``

.. code-block:: shell

    cat >> /home/pvacms/.spva_jwt_bashrc <<EOF
    export EPICS_AUTH_JWT_REQUEST_FORMAT='#token#'
    export EPICS_AUTH_JWT_REQUEST_METHOD='GET'
    export EPICS_AUTH_JWT_RESPONSE_FORMAT='{ *, "valid": "#response#" }'
    export EPICS_AUTH_JWT_TRUSTED_URI='http://localhost:8080/default/verify'
    #export EPICS_AUTH_JWT_USE_RESPONSE_CODE=NO
    EOF

- set up pvacms to run this new config

.. code-block:: shell

    echo "source ~/.spva_jwt_bashrc" >> /home/pvacms/.bashrc

|5| Configure Supervisor to run the JWT authenticator
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- configure jwt_issuer supervisord

.. code-block:: shell

    cat > /etc/supervisor/conf.d/jwt_issuer.conf <<EOF
    [program:jwt-issuer]
    command=python3 /opt/epics/app.py
    autostart=true
    autorestart=true
    stdout_logfile=/var/log/supervisor/jwt-issuer.out.log
    stderr_logfile=/var/log/supervisor/jwt-issuer.err.log
    EOF


|6| Start Services
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- update pvacms supervisor config to include Java Web Token (JWT) Authenticator configuration

.. code-block:: shell

    cat >> /etc/supervisor/conf.d/pvacms.conf <<EOF
    environment=EPICS_AUTH_JWT_RESPONSE_FORMAT='{ *, "valid": "#response#" }',EPICS_AUTH_JWT_TRUSTED_URI="http://localhost:8080/default/verify"
    EOF

- start jwt_issuer, and pvacms with Java Web Token (JWT) Authenticator support

.. code-block:: shell

    /usr/bin/supervisord -c /etc/supervisor/supervisord.conf

.. code-block:: console

   2025-08-14 05:38:25,124 INFO Included extra file "/etc/supervisor/conf.d/jwt_issuer.conf" during parsing
   2025-08-14 05:38:25,124 INFO Included extra file "/etc/supervisor/conf.d/pvacms.conf" during parsing
   2025-08-14 05:38:25,124 INFO Set uid to user 0 succeeded
   2025-08-14 05:38:25,125 INFO supervisord started with pid 2774
   2025-08-14 05:38:26,136 INFO spawned: 'jwt-issuer' with pid 2775
   2025-08-14 05:38:26,138 INFO spawned: 'pvacms' with pid 2776
   2025-08-14 05:38:27,493 INFO success: jwt-issuer entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
   2025-08-14 05:38:27,493 INFO success: pvacms entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)

.. _spva_qs_jwt_server:

|step| Run SoftIOC
------------------------------------------

|1| Login as softioc in a new shell
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\²

.. code-block:: shell

    docker exec -it --user softioc spva_jwt /bin/bash

|3| Get JWT (token)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- get a token.  Use "secret" as the password

.. code-block:: shell

    TOKEN=$(curl -s "http://localhost:8080/default/token?sub=softioc&password=secret")
    echo ${TOKEN} > token_file

.. code-block:: console

    curl -sG --data-urlencode "token=$TOKEN" "http://localhost:8080/default/verify"

.. code-block:: console

    {"claims":{"aud":"default","exp":1755150736,"iat":1755147136,"iss":"http://localhost:8080/default","jti":"c40d1fc2-40f2-4bf9-a84a-fff5fadea38a","nbf":1755147136,"sub":"softioc"},"header":{"alg":"RS256","kid":"demo-key-1","typ":"JWT"},"valid":true}


|3| Get Certificate
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- create a client server certificate

  - creates client server certificate
  - at location specified by ``EPICS_PVAS_TLS_KEYCHAIN`` or ``${XDG_CONFIG_HOME}/pva/1.4/server.p12`` by default

.. code-block:: shell

    authnjwt -u server --token-file token_file

.. code-block:: console

    Keychain file created   : /home/client/.config/pva/1.4/server.p12
    Certificate identifier  : b271f07a:12421554925305118824

|4| Check the certificate status is VALID
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- check that the generated certificate is ``VALID``
- note that the *name* is ``softioc`` - picked up from ``sub`` in the JWT
- note that the *organization* is ``localhost`` - picked up from the issuer domain
- note that the *expiration date* is the same as the ``exp`` of the JWT
- note that the *start date* is set to the ``nbf`` of the JWT

.. code-block:: shell

    pvxcert -f ~/.config/pva/1.4/server.p12

.. code-block:: console

    Certificate Details:
    ============================================
    Certificate ID : 47530d89:3826361579604613180
    Entity Subject : CN=softioc, O=localhost
    Issuer Subject : CN=EPICS Root Certificate Authority, C=US, O=certs.epics.org, OU=EPICS Certificate Authority
    Valid From     : Sat Mar 08 15:23:21 2025 UTC
    Expires On     : Sun Mar 09 15:23:09 2025 UTC
    --------------------------------------------

    Certificate Status:
    ============================================
    Certificate ID: 47530d89:3826361579604613180
    Status        : VALID
    Status Issued : Sat Mar 08 15:47:14 2025 UTC
    Status Expires: Sat Mar 08 16:17:14 2025 UTC
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
        -a ${PROJECT_HOME}/pvxs/test/testioc.tls.acf

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

.. _spva_qs_jwt_client:

|step| SPVA Client
------------------------------------------

|1| Login as client in a new shell
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- |terminal|\³

.. code-block:: shell

    docker exec -it --user client spva_jwt /bin/bash


|2| Get JWT (token)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- get a token.  Use "secret" as the password

.. code-block:: shell

    TOKEN=$(curl -s "http://localhost:8080/default/token?sub=client&password=secret")
    echo ${TOKEN} > token_file

.. code-block:: console

    curl -sG --data-urlencode "token=$TOKEN" "http://localhost:8080/default/verify"

.. code-block:: console

    {"claims":{"aud":"default","exp":1755150140,"iat":1755146540,"iss":"http://localhost:8080/default","jti":"c7cad85c-ae49-49cc-abf7-c3be923ce06b","nbf":1755146540,"sub":"client"},"header":{"alg":"RS256","kid":"demo-key-1","typ":"JWT"},"valid":true}


.. code-block:: console

    { "valid": true, "claims": { "sub": "client", ... } }


|3| Get Certificate
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- create a client certificate

  - creates a client certificate
  - at location specified by ``EPICS_PVA_TLS_KEYCHAIN`` or ``${XDG_CONFIG_HOME}/pva/1.4/client.p12`` by default

.. code-block:: shell

    authnjwt --token-file token_file

.. code-block:: console

    Keychain file created   : /home/client/.config/pva/1.4/client.p12
    Certificate identifier  : b271f07a:1204731550645534180

|4| Check the certificate status is VALID
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- check that the generated certificate is ``VALID``
- note that the *name* is ``client`` - picked up from ``sub`` in the JWT
- note that the *organization* is ``localhost`` - picked up from the issuer domain
- note that the *expiration date* is the same as the ``exp`` of the JWT
- note that the *start date* is set to the ``nbf`` of the JWT

.. code-block:: shell

    pvxcert -f ~/.config/pva/1.4/client.p12

.. code-block:: console

    Certificate Details:
    ============================================
    Certificate ID : b271f07a:1204731550645534180
    Entity Subject : CN=client, O=localhost
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
    EPICS_PVA_TLS_KEYCHAIN=/home/client/.config/pva/1.4/client.p12
    EPICS_PVA_TLS_OPTIONS=on_expiration=fallback-to-tcp
    EPICS_PVA_TLS_PORT=5076
    XDG_CONFIG_HOME=/home/client/.config/pva/1.4
    XDG_DATA_HOME=/home/client/.local/share/pva/1.4
    # TLS x509:b271f07a:12421554925305118824:EPICS Root Certificate Authority/client@172.17.0.2:37027
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

  - ``TLS x509:b271f07a:12421554925305118824:EPICS Root Certificate Authority/client @ 172.17.0.2`` indicates that:

    - The connection is ``TLS``,
    - The Server end of the channel has been authenticated by the Root Certificate Authority ``EPICS Root Certificate Authority``
    - The Server end of the channel's name has been authenticated as ``client`` and is connecting from host ``172.17.0.2``


