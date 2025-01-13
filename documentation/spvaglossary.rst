.. _glossary:

SPVA Glossary
=============

.. _glossary_auth_vs_authz:

- Auth or AuthN (Authentication) vs AuthZ (Authorization).
    In cybersecurity, these abbreviations are commonly used to differentiate between two distinct aspects of the security process.

    - ``Authentication`` refers to the process of verifying the validity of the credentials and claims presented within a security token, ensuring that the entity is who or what it claims to be.
    - ``Authorization``, on the other hand, is the process of determining and granting the appropriate access permissions to resources based on the authenticated entity's credentials and associated privileges.

.. _glossary_certificate_authority:

- CA – Certificate Authority.
    An entity that signs, and issues digital certificates.  Each site where EPICS is installed will use the proposed PVACMS as their CA.

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
        - the name of the CA, e.g. ``SLAC Certificate Authority`` or ``ORNL CA``.
          This field value is used in an ASG AUTHORITY rule to identify the certificate issuer.

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
    In cryptography, a client certificate is a type of digital certificate that is used by client systems to make authenticated requests to a remote server which itself has a server certificate.
    They contain claims that are signed by a CA that is trusted by the peer certificate user.
    All Secure PVAccess certificates are X.509 certificates.

.. _glossary_custom_extension:

- Custom Extension, for X.509 Certificates.
    The `X.509` certificate format allows for the inclusion of custom extensions, (RFC 5208),
    which are data blobs encoded within certificates and signed alongside other certificate claims.
    In Secure PVAccess, we use a custom extension ``status_monitoring_extension``.
    If present, the extension mandates that a certificate shall only be considered valid only if
    its status is successfully verified retrieved from the PV provided within the extension and that the certificate status received is ``VALID``.

.. _glossary_diskless_server:
.. _glossary_diskless_node:
.. _glossary_network_computer:
.. _glossary_hybrid_client:

- Diskless Server, Diskless Node, Network Computer, Hybrid Client.
    A network device without disk drives, which employs network booting to load its operating system from a server, and network mounted drives for storage.

.. _glossary_epics_agents:

- EPICS Agents.
    Refers to any EPICS client, server, gateway, or tool.

.. _glossary_epics_security:

- EPICS Security.
    The EPICS technology that provides user Authorization.  It is configured using an :ref:`access_control_file_ACF`.

.. _glossary_jwt:

- JWT - JSON Web Token.
    (RFC 7519) - A compact URL-safe means of representing claims to be transferred between two parties.
    The token is signed to certify its authenticity.
    It will generally contain a claim as to the identity of the bearer (sub) as well as validity date ranges (nbf, exp).


.. _glossary_kerberos:
.. _glossary_kerberos_ticket:

- Kerberos, Kerberos Ticket.
    A protocol for authenticating service requests between trusted hosts across an untrusted network, such as the internet.
    Kerberos support is built into all major computer operating systems, including Microsoft Windows, Apple macOS, FreeBSD and Linux.
    A Kerberos ticket is a certificate issued by an authentication server (Key Distribution Center - KDC) and encrypted using that server’s key.
    Two ticket types: A Ticket Granting Ticket (TGT) allows clients to subsequently request Service Tickets which are then passed to servers as the client’s credentials.
    An important distinction with Kerberos is that it uses a symmetric key system where the same key used to encode data is used to decode it therefore that key is never shared and so only the KDC can verify a Kerberos ticket that it has issued – clients or servers can’t independently verify that a ticket is valid.
    An EPICS agent needing to get a certificate will need to contact PVACMS using GSSAPI to be authenticated.

.. _glossary_ocsp:

- OCSP - Online Certificate Status Protocol.
    A modern alternative to the Certificate Revocation List (CRL) that is used to check whether a digital certificate is valid or has been revoked.
    While OCSP requests and responses are typically served over HTTP, we use PVACS to request, and receive, OCSP responses over the Secure PVAccess Protocol.

.. _glossary_pkcs12:

- PKCS#12 - Public Key Cryptography Standard.
    In cryptography, PKCS#12 defines an archive file format for storing many cryptography objects as a single file.
    It is commonly used to bundle a private key with its X.509 certificate and/or to bundle all the members of a chain of trust.
    It is defined in ``RFC 7292``.
    We use PKCS#12 files to store the EPICS agent's public / private key pair, and for each EPICS agent certificate created using the public key.
    The PKCS#12 files are referenced by environment variables described in the :ref:`secure_pvaccess_configuration`.

.. _glossary_pvacms_stapling:

- PVACS Stapling.
    This is the equivalent of OCSP stapling but implemented using PVACS.

.. _glossary_skid:

- SKID - Subject Key Identifier.

    - The SKID identifies the subject of the certificate.
      In simple terms the subject key identifier of a certificate is nothing more than a mechanism for certifying
      that the bearer of the certificate has the private corresponding to the certificate's public key.
    - so, the SKID is a way of identifying the private key so that if it is used to generate a new certificate
      the bearer is identified as the same.  Its saying “This is my X” where X can be
      a process, machine, IOC, service, or anything that can participate in a Secure
      EPICS network.
    - In practice it simply makes a hash of the public key,
      as the public key has a one-to-one relationship to the private key.
    - An EPICS agent keeps the private key in a separate key file to
      the certificate so that it can be used to generate a new certificate when
      the old one expires and will retain the same SKID on the network.  You can’t
      generate a new certificate with the same SKID while a prior one has not ``EXPIRED`` or been ``REVOKED``.
    - when we show the SKID of a certificate issuer we use only the first 8 characters of the hexadecimal hash.

