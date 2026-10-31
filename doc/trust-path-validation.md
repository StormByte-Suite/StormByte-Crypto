# Bundled trust admission and native path policy

`<StormByte/crypto/x509/trust_path.hxx>` is transport-independent **path
validation**, not full peer authentication. A PEM bundle loading successfully
does not authenticate anyone.

## Trust contract

`LoadBundledTLSRoots()` returns an independently owned Safe vector parsed from
the embedded, SHA-256-verified, versioned Mozilla-derived server-root snapshot.
The immutable revision and digest are exposed as library-owned strings.
Modifying that copy cannot change `ValidateBundledTLSPath` admission.
There are no runtime trust downloads. Provenance, selection rules, license and
every excluded root/cutoff are in `thirdparty/trust/`.

`ValidateBundledTLSPath(leaf, intermediates, at, identity)` requires strict
DNS/binary-IP SAN identity with no CN fallback, a non-CA leaf, and the existing
TLS signing-purpose check (present KU must permit digitalSignature; present EKU
must explicitly permit serverAuth). Empty inputs,
unsupported identity kinds and more than 16 intermediate candidates fail.

### Linux

Only the embedded admitted roots are candidates. Linux does **not** open distro
or system CA stores/files, inspect trust environment variables, call a platform
trust library, or perform network I/O. It matches the last supplied issuer's
signature/name to a bundled anchor and applies `TLSPeerVerifier` to the complete
ordered path, including leaf purpose, identity, validity and CA restrictions.

This is the existing **constrained subset**, not an RFC 5280 path builder:

- intermediates must be in exact leaf-to-root order, excluding the root;
- exact DER issuer names; conservative pathLen counting, including self-issued CAs;
- issuer/root v3 CA, KU, EKU, key suitability and certificate validity enforced;
- RSA 2048–8192 or named P-256/P-384/P-521 keys; SHA-2 RSA PKCS#1 v1.5/ECDSA
  certificate signatures (not RSA-PSS certificate signatures);
- unsupported name/policy/proxy/TLS Feature restrictions and unprocessed
  critical extensions **fail**, never silently disappear.

See [the detailed verifier contract](tls-peer-verification.md). Some public
chains will be rejected deliberately until their constraints are implemented.
No existing parser or legacy `VerifyChain` semantics were changed.

### Windows

CryptoAPI builds an offline chain in an engine with `hExclusiveRoot` set to a
private **memory store of bundled roots**, not a union with system roots.
Server-auth EKU and `CERT_CHAIN_POLICY_SSL` must pass without ignored errors.
CryptoAPI's current-OS strong-signature policy is requested explicitly.
The actual terminal root must exactly match an admitted, time-valid CA.

Separately, the normal Windows trust engine evaluates native root admission,
distrust and TLS policy. It must succeed with the **same terminal root**.
An OS-only root cannot pass the exclusive evaluation; a bundle-only or
OS-distrusted root cannot pass the normal evaluation. AIA retrieval and automatic
auth-root update are disabled, and URL retrieval is cache-only.

### macOS

Security.framework evaluates `SecPolicyCreateSSL` in a private SecTrust object,
with explicit bundled anchors and `SecTrustSetAnchorCertificatesOnly(true)`.
The actual root must exactly match an admitted, time-valid CA.

A separate SecTrust evaluation with normal native trust settings must accept
the **same terminal root**, preserving native root distrust/policy instead of
overriding it with explicit-anchor trust. Both objects have network fetching
disabled. No keychain is modified.

Native platforms may build paths from supplied certificates and native cached
issuers; Linux never does. This operation supplies no requested policy OIDs,
CT evidence, handshake transcript or stapled revocation evidence. Native policies
are platform/version dependent and can be stricter than the Linux subset.
Strict SAN matching is independently enforced before native TLS policy, so
neither native backend needs CN-based hostname matching.

### Custom CA is an explicit, separate mode

`ValidateCustomCATLSPath` accepts exactly one caller-selected anchor, without
bundled admission or normal OS-root admission. It retains Linux's constraints,
or scoped native SSL policy with an exclusive explicit anchor. It neither
installs the CA nor widens production bundled trust. Root certificate validity
is enforced even where native abstract-anchor policy might otherwise ignore it.
Custom path success still asserts **no revocation or authentication**.

## Mandatory payment revocation: NOT COMPLETE

`VerifyPaymentPeer` first performs bundled path validation. Invalid paths return
`PaymentPeerError::TrustPathRejected`. Even a valid path returns
**`PaymentPeerError::RevocationUnavailable`**. This unit has no success branch
and accepts no caller-forgeable “revocation checked” flag.

Actual signed CRL/OCSP evidence validation, issuer/responder authorization,
freshness, certificate binding and hard-fail handling of **absent, unknown,
stale, invalid or revoked** evidence are mandatory subsequent work. Native
path success, cached native hints, a successful OpenSSL probe, and this bundle
are not substitutes. Payment peer authentication and the TLS engine must not
be claimed complete or enabled based on these path-only results. Proof of key
possession/CertificateVerify also remains outside this operation.

## Offline tests and observed compatibility

The original 43 CTest registrations are unchanged. Two Linux registrations
exercise the new API, with one replay under hostile/nonexistent CA environment
settings. Tests cover snapshot integrity/provenance/exclusions, independent
copies, custom separation, invalid requests, unsupported Linux constraints,
purpose/time failures and real public-chain path validation.
Top-level CTest discovery is enabled when `ENABLE_TEST` is on, so both
`ctest --test-dir build` and `ctest --test-dir build/test` run the suite.

With `ENABLE_TEST=ON`, macOS/Windows also compile `X509NativeTrustTests`.
Its separately compiled private test helper uses exclusive memory roots on
Windows and explicit object-scoped SecTrust anchors on macOS to simulate native
trust, **never OS-store/keychain mutation**. The test-only symbol and fixture
system-root injection do not exist in the production library. Tests exercise
the two-sided admission intersection, purpose/path-length/signature/time
failures, and the public RSA chain with isolated roots. Those native tests are
prepared for the existing CI matrix; they have not been run on Linux.

Public reference certificates were captured on **2026-10-31** with bounded
OpenSSL probes of `api-m.paypal.com` and `api-m.sandbox.paypal.com`, without API
calls, credentials or private keys. Both endpoints supplied the same RSA-2048
leaf and intermediate in this observation:

- leaf DER SHA-256:
  `c7db732d9ea7f9da01fd50a0ab8d75ca828e80db3d1bec162f6e9e3209fb1ac0`;
- intermediate DER SHA-256:
  `c8025f9fc65fdfc95b3ca8cc7867b9a587b5277973957917463fc813d0b625a9`;
- issuer: DigiCert Global G2 TLS RSA SHA256 2020 CA1;
- bundled anchor selected by signature verification: DigiCert Global Root G2,
  omitted by the servers;
- certificate signatures: RSA PKCS#1 v1.5/SHA-256;
- TLS 1.3 probe: AES-128-GCM/SHA-256 and RSA-PSS-RSAE/SHA-256 signing.
  Default OpenSSL also negotiated X25519MLKEM768; separate probes constrained
  to X25519 succeeded. The preflight X25519 observation is therefore compatible;
- an ECDSA-only signature-policy probe failed the handshake.

The captured chains **pass the actual Linux bundled path verifier** at
2026-10-31 for both expected hostnames; payment verification still fails
`RevocationUnavailable`. This is reference-chain compatibility, **not a claim
that StormByte TLS or PayPal integration works**. TLS RSA-PSS signature vocabulary,
signing and transcript verification require a separate future unit. The bundle
contains the wider curated server-root set, not only today's PayPal issuer.
