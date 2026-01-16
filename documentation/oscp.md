# OSCP payloads in brief

cf. [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960)

## Response structure

* OCSPResponse
  * responseStatus (enum)
  * responseBytes (ResponseBytes)
    * responseType (OID)
    * response (interpretation based on type OID)

responseType will be one of:

* `id-pkix-ocsp-basic` (`response` is BasicOCSPResponse)
* `id-pkix-ocsp` (unused?)
* Others?

* BasicOCSPResponse
  * tbsResponseData (This is the signed payload!!!)
    * version
    * responderID
      * byName | byKey
    * producedAt (time of attestations)
    * responses (array of SingleResponse)
      * repeated
        * certID
        * certStatus (enum with data: good, revoked(w/ time), unknown)
        * thisUpdate (time, beginning of validity period)
        * nextUpdate (time, end of validity period)
        * singleExtensions
    * responseExtensions
  * signatureAlgorithm
  * signature
  * certs (optional, in addition to TLS negotiated chain, and keyring file)

## Interpretation and Verification

Security decisions must only be made on the signed portion of a response
after it has been validated.

eg. the `responseStatus` is not signed, and so should not be trusted!

Validation is assumed to be delegated to a TLS library (eg. openssl via `OCSP_basic_verify()`).

Invalid responses may be logged, but should otherwise be ignored.

`producedAt` from successive updates should be monotonic.
Duplicate/older updates should be ignored.

Each SingleResponse from a BasicOCSPResponse should be inspected.

If `CertStatus == good`, and if the system time is within the interval `thisUpdate` and `nextUpdate`,
then the target certificate is attested until `nextUpdate`, or until a later valid response is received (based on `producedAt`).

If `CertStatus == revoked`, then the certificate is to be considered revoked after `revocationTime`.

If `CertStatus == unknown`, then ignore?  Notify of logout?

## PVA extended interpretation

A SPVA node, having encountered an x509v3 certificate (self or peer) will maintain a "validity" status, validity time interval, and a flag to indicate whether at the end of the validity time interval status reverts to "unknown", or expire/revoke.

When the certificate does not include the OCSP-over-PVA extension,
the status is "good",
and the time interval is copied from the cert. `notBefore` and `notAfter`.

### OCSP over PVA

Design decision: all revocations are immediate, ignore `revocationTime` and post-dated revocation.

At any moment, if the status is "good", and the system time is within the validity interval,
then the cert. may be trusted.

For a cert. with the OCSP-over-PVA extension,
initially the "validity status" of this certificate is considered "unknown" for all times.

The node will subscribe to the indicated status PV.
Updates to the status PV will contain an `OCSPResponse`.

An initial "good" reply will establish/update the validity interval `[thisUpdate, nextUpdate)`.

Successive "good" updates should advance `nextUpdate`, but may leave `thisUpdate` unchanged.

`thisUpdate` should be no earlier than the `notBefore` time of the attested certificate,
and `nextUpdate` should not be after the `notAfter` time.

eg. when "validity" is tracking an interactive session, `timeUpdate` could be the login time.
