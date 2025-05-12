.. _glossary:

|security| SPVA Glossary
==========================

.. _glossary_auth_vs_authz:

- Auth or ``AuthN`` (Authentication) vs ``AuthZ`` (Authorization).

  In cybersecurity, these abbreviations are commonly used to differentiate between two distinct aspects of the security process.

  - ``Authentication`` refers to the process of verifying the validity of the credentials and claims presented within a security token, ensuring that the entity is who or what it claims to be.
  - ``Authorization``, on the other hand, is the process of determining and granting the appropriate access permissions to resources based on the authenticated entity's credentials and associated privileges.

.. _glossary_certificate_subject:

- Certificate’s Subject.

  This is a way of referring to all the fields in the X.509 certificate that identify the entity.  These are:-

  - ``CN``: common name e.g. ``slac.stanford.edu``;
  - ``O``: organization e.g. ``Stanford National Laboratory``;
  - ``OU``: organizational unit e.g. ``SLAC Certificate Authority``;
  - ``C``: country e.g. ``US``.

  In Secure PVAccess:

  - the ``CN`` common name stores

    - the device name e.g. ``KLYS:LI16:21``,
    - or username e.g. ``greg``,
    - or process name  e.g. ``archiver``.

    For Certificate Authorities the ``CN`` field will be

    - the name of the Certificate Authority, e.g. ``SLAC Certificate Authority`` or ``ORNL Certificate Authority``.
      This field value is used in an ``ASG`` ``AUTHORITY`` rule to identify the certificate issuer.

  - the ``O`` organization field stores

    - the hostname e.g. ``centos01``,
    - the IP Address e.g. ``192.168.3.2``,
    - the realm e.g. ``SLAC.STANFORD.EDU``,
    - or another domain identifier.

  - the ``OU`` organizational unit field stores

    - is optional but can be used to store the organizational unit e.g. ``PEP II``, or ``LCLS``.

  - the ``C`` country field stores

    - the country e.g. ``US``

.. _glossary_client_certificate:

- Client Certificate, Server Certificate, X.509.

  In cryptography, a client certificate is a type of digital certificate that is used by client systems
  to make authenticated requests to a remote server which itself has a server certificate.
  They contain claims that are signed by a Certificate Authority that is trusted by the peer certificate user.
  All Secure PVAccess certificates are ``X.509`` certificates.

.. _glossary_custom_extension:

- Custom Extension, for X.509 Certificates.

  The ``X.509`` certificate format allows for the inclusion of custom extensions, (``RFC 5208``),
  which are data blobs encoded within certificates and signed alongside other certificate claims.
  In Secure PVAccess, we use a custom extension ``status_monitoring_extension``.
  If present, the extension mandates that a certificate shall only be considered valid only if
  its status is successfully verified retrieved from the PV provided within the extension and that the certificate status received is ``VALID``.

.. _glossary_diskless_server:
.. _glossary_diskless_node:
.. _glossary_network_computer:
.. _glossary_ioc_client:

- Diskless Server, Diskless Node, Network Computer, IOC.

  A network device without disk drives, which employs network booting to load its operating system from a server, and network mounted drives for storage.

.. _glossary_epics_agents:

- EPICS Agents.

  Refers to any EPICS client, server, gateway, or tool.

.. _glossary_epics_security:

- EPICS Security.

  The EPICS technology that provides user Authorization.  It is configured using an :ref:`access_control_file_ACF`.

.. _glossary_jwt:

- JWT - JSON Web Token.

  (``RFC 7519``) - A compact URL-safe means of representing claims to be transferred between two parties.
  The token is signed to certify its authenticity.
  It will generally contain a claim as to the identity of the bearer (sub) as well as validity date ranges (nbf, exp).


.. _glossary_kerberos:
.. _glossary_kerberos_ticket:

- Kerberos, Kerberos Ticket.

  - A protocol for authenticating service requests between trusted hosts across an untrusted network, such as the internet.
  - Kerberos support is built into all major computer operating systems, including Microsoft Windows, Apple macOS, FreeBSD and Linux.
  - A Kerberos ticket is a certificate issued by an authentication server (Key Distribution Center - ``KDC``) and encrypted using that server’s key.
  - Two ticket types:

    - A Ticket Granting Ticket (``TGT``) allows clients to subsequently request Service Tickets
    - Service Tickets are passed to servers as the client’s credentials.

  - An important distinction with Kerberos is that it uses a symmetric key system where the same key used
    to encode data is used to decode it therefore that key is never shared and so only the KDC
    can verify a Kerberos ticket that it has issued – clients or servers can’t independently verify that a ticket is valid.

.. _glossary_ocsp:

- OCSP - Online Certificate Status Protocol.

  A modern alternative to the Certificate Revocation List (CRL) that is used to check whether a digital certificate is valid or has been revoked.
  While ``OCSP`` requests and responses are typically served over HTTP,
  we use ``PVACMS`` to create and send, OCSP certificate status responses over the Secure PVAccess Protocol.

.. _glossary_pkcs12:

- PKCS#12 - Public Key Cryptography Standard.

  In cryptography, ``PKCS#12`` defines an archive file format for storing many cryptography objects as a single file.
  It is commonly used to bundle a private key with its ``X.509`` certificate and/or to bundle all the members of a chain of trust.
  It is defined in ``RFC 7292``.
  We use PKCS#12 files to store:

  - the Root Certificate Authority's Certificate that is the trust anchor for all TLS operations in an EPICS agent
  - the EPICS agent's public / private key pair,
  - the EPICS agent's certificate created using the public key.
  - the Certificate Authority keychain

  The PKCS#12 files are referenced by environment variables described in the :ref:`secure_pvaccess_configuration`.

.. _glossary_skid:

- SKID - Subject Key Identifier.

  - The SKID uniquely identifies a certificate's key pair by computing a hash of its public key.
    In simple terms, it links a certificate to the underlying key pair.
  - In our implementation, the SKID serves as a unique identifier for an entity—whether that be a process,
    machine, IOC, service, or any participant in the Secure PVAccess network.
    It effectively states, "This is my key pair," ensuring consistency when certificates are renewed.
  - Practically, the SKID is generated by hashing the public key. Since the public key is
    uniquely paired with its corresponding private key, the hash reliably identifies the key pair.
  - An EPICS agent stores the private key in the same key file as the certificate. When renewing a certificate,
    the agent reuses the same private key, which is copied to the new key file,
    resulting in an identical SKID.
  - According to our policy, a new certificate with the same SKID cannot be issued
    unless the previous certificate has either ``EXPIRED`` or been ``REVOKED``.
  - For display purposes, we show only the first 8 characters of the SKID’s hexadecimal hash, providing a concise identifier.

