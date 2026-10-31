# Offline TLS peer-certificate verification

`<StormByte/crypto/x509/tls_peer.hxx>` adds one stateless composition:

```cpp
X509::SubjectAltName expected(
	X509::SubjectAltNameType::DNS, Safe::Binary("peer.example.com"));
auto verified = X509::TLSPeerVerifier::Verify(
	leaf, orderedIntermediates, explicitlyTrustedAnchor,
	callerTime, X509::TLSRole::Server, &expected);
```

The exact entrypoint is:

```cpp
static ExpectedTLSPeer Verify(const Certificate& leaf,
	std::span<const Certificate> intermediates, const Certificate& anchor,
	TimePoint at, TLSRole role, const SubjectAltName* identity = nullptr);
```

`ExpectedTLSPeer` is `Expected<void, TLSPeerFailure>`. Inputs are borrowed only
during the call. `SubjectAltName` owns its bytes with `Safe::Binary`; result
storage is Safe-owned, and the error's state is trivial with out-of-line value
operations. Allocation failures propagate rather than becoming trust success.
The implementation shares the certificate parser's private, immutable ranges
and existing DER/signature/KU/EKU/SAN helpers, without adding a competing parser
or changing `Certificate::VerifyChain`, parsing, purpose or license semantics.

## Roles and identities

- **Server:** an expected identity is mandatory. DNS is caller-selected ASCII
  hostname text (IDNs already in A-label form); IP is exactly 4 or 16
  network-order bytes, **not** a textual IP literal.
- **Client:** identity may be omitted. This verifies a client signing certificate
  under the supplied CA but **does not identify a user, authorize an account, or
  assert any application identity**. TLS client certificates often use identities
  other than DNS/IP. Application authorization is outside this API.
- When supplied for either role, identity uses existing strict SAN matching:
  full case-insensitive DNS with one trailing dot normalized, a complete leftmost
  wildcard over one label, exact IP bytes, no CN fallback, no IDNA conversion,
  no DNS/IP cross-kind fallback or mapped-address equivalence.
- Every present SAN is validated on the leaf, intermediates and anchor, even
  for identityless clients. Critical SAN is limited to DNS/IP names; other
  general-name kinds cannot be treated as fully processed critical extensions.
- Missing EKU is unrestricted. Every present EKU on **every certificate** must
  explicitly grant serverAuth or clientAuth for the role; anyEKU alone fails,
  while anyEKU together with that explicit role is accepted. The complete EKU
  DER/OIDs are checked; other well-formed OIDs do not grant a role.
- The leaf must not be a CA. Present leaf KU must allow digitalSignature, for a
  **TLS 1.3 signing role**, not key encipherment or agreement alone.
- Issuers require keyCertSign when KU is present, **not** digitalSignature.
  Every present KU is strictly validated, including named-bit DER, the nine-bit
  range and the requirement that encipherOnly/decipherOnly imply keyAgreement.
  keyCertSign also requires cA basicConstraints; a non-CA leaf cannot assert it.

These rules follow RFC 8446 §4.4.2.2 and RFC 5280 §4.2.1.3/§4.2.1.12.
They do not implement TLS CertificateVerify, RSA-PSS negotiation or a handshake.

## Ordered chain and anchor policy

The input is exactly `leaf -> intermediates[0] -> ... -> anchor`. Intermediates
exclude the leaf and anchor. Every non-anchor issuer name must match the next
subject's **exact DER**, and its signature must verify with that issuer's key.
No reordering, alternative-path search, AIA fetching, system trust, certificate
store, cross-sign resolution, name canonicalization or missing-issuer recovery
is performed. Extraneous/duplicate certificates can invalidate a path.

The anchor is trusted **because the caller selects it**, not because it is
self-signed, last in a peer-supplied bundle, or trusted by the OS. Its own
signature, signature algorithm and issuer name are not verified or used to
establish trust. A corrupted anchor self-signature therefore does not invalidate
the externally selected key.

RFC 5280 §6.1.1 defines abstract trust-anchor information, not necessarily a
normal certificate in the validated path. This API deliberately imposes a
stricter **local certificate-anchor policy**: the anchor must be a valid v3 CA,
have critical cA basicConstraints, permit keyCertSign when KU is present, have
compatible EKU, satisfy its pathLen and extension restrictions, and contain a
supported validated key. The same issuer rules apply to intermediates.

Every certificate, including the anchor, uses the explicit `TimePoint`
(`std::chrono::sys_seconds`); notBefore and notAfter are **inclusive**.
No wall clock is consulted. Each issuer's pathLen counts the supplied
intermediate CAs below it. Self-issued intermediates are counted too, rather
than using the RFC's rollover exemption: this conservative subset can reject
otherwise valid rollover paths, but does not silently exempt unprocessed paths.

## Supported algorithms and extensions

Keys must validate and be RSA **2048..8192 bits** or named-curve ECDSA
**P-256/P-384/P-521**. Non-anchor certificate signatures must be RSA PKCS#1 v1.5
or ECDSA with **SHA-256/384/512**, with supported AlgorithmIdentifier parameters.
SHA-1, RSA-PSS, EdDSA, explicit EC parameters, other curves and weak RSA keys are
not accepted by this subset. These certificate-signature algorithms do not
claim compatibility with the separate designated TLS profile or TLS wire
signature schemes.

| Extension | Processing |
| --- | --- |
| basicConstraints | Parser checks structure/cA/pathLen; composition rejects DER DEFAULT FALSE encoding and requires critical cA on issuers. |
| keyUsage | Strict DER and role/issuer usage; agreement-only bits require keyAgreement. |
| extendedKeyUsage | Complete DER/OID validation and explicit chainwide role check. |
| subjectAltName | Whole existing SAN validation; critical forms limited to DNS/IP. |
| nameConstraints (2.5.29.30) | **UnsupportedConstraint whenever present**, even noncritical or malformed: subtree restrictions are not evaluated. |
| policyMappings (2.5.29.33), policyConstraints (2.5.29.36), inhibitAnyPolicy (2.5.29.54) | **UnsupportedConstraint whenever present**, even noncritical: policy mapping/counters and explicit-policy restrictions are not implemented. |
| TLS Feature (1.3.6.1.5.5.7.1.24) | **UnsupportedConstraint whenever present**; no handshake/stapled OCSP is available to discharge RFC 7633 obligations such as Must-Staple. |
| proxyCertInfo (1.3.6.1.5.5.7.1.14) | **UnsupportedConstraint whenever present**; RFC 3820 proxy path/authorization restrictions are not implemented. |
| certificatePolicies (2.5.29.32) | Critical: **unsupported**. Noncritical: ignored without a requested-policy evaluation or policy-acceptance assertion. Policy assertions alone are not treated as universal path restrictions. |
| SKI, AKI | Noncritical: ignored hints, not path selection. Critical: **unsupported**, even though the legacy parser recognizes their OIDs. |
| Other critical extensions | **UnsupportedCriticalExtension**, including recognized but unprocessed issuerAltName, AIA and CRL extensions. |
| Other noncritical extensions | Ignored per the constrained contract (including unknown benign extensions, AIA, CRL distribution points and issuerAltName); no semantic validation or fetching is claimed. |

This is **not a full RFC 5280 validator or public HTTPS-ready trust system**.
The supported extension subset is intentionally fail-closed for restrictions
that it cannot discharge, without blanket rejection of standard noncritical
hints or unrequested policy assertions. DER framing and duplicate-extension
rejection continue to come from the existing certificate parser.

## Error map and precedence

`TLSPeerFailure::Code()` returns `TLSPeerError`.
`CertificateIndex()` is **0 for leaf, 1..N for intermediates, N+1 for anchor**.
A link/signature failure reports the signed child, not the candidate issuer.
Request failures use index 0. Detail getters are meaningful only in their
corresponding category.

| Category | Meaning |
| --- | --- |
| UnsupportedRole / MissingServerIdentity / UnsupportedIdentity | Invalid request role or absent/unsupported identity kind. |
| InvalidCertificate / InvalidTime | Empty or moved-from certificate / outside caller-time validity. |
| LeafIsCA / NotCA / PathLengthExceeded | Invalid leaf classification / issuer CA classification / pathLen restriction. |
| IssuerKeyUsageNotAllowed | Present issuer KU lacks keyCertSign (distinct from a leaf's digitalSignature purpose error). |
| SignatureOrIssuerMismatch | Signature or exact-DER issuer/subject link fails; includes rogue anchor, missing issuer and unordered paths. |
| UnsupportedAlgorithm | Signature algorithm/parameters or public-key type, parameters, size or validation outside the subset. |
| UnsupportedCriticalExtension / UnsupportedConstraint / MalformedExtension | Unprocessed critical semantics / unsupported present restriction / inconsistent or malformed processed extension. |
| Purpose | `PurposeDetail()` preserves `MalformedExtendedKeyUsage`, `MalformedKeyUsage`, `ExtendedKeyUsageNotAllowed` or `KeyUsageNotAllowed` from role/issuer usage validation. |
| Identity | `IdentityDetail()` preserves `InvalidExpectedName`, `InvalidExpectedAddress`, `MissingSubjectAltName`, `MalformedSubjectAltName` or `NoMatch`; malformed issuer SAN retains that issuer index. |

Precedence: request validation; then each certificate from leaf to anchor:
empty, time, leaf CA classification, present SAN validation, extension audit,
EKU/KU checks (leaf uses existing purpose precedence), issuer CA/KU/pathLen,
KU agreement consistency, key/signature-algorithm subset, preceding-child
signature. Expected identity matching is last. Success never hides a failed
chain, usage, constraint or identity check.

## Residual obligations and regression coverage

**There is no CRL/OCSP checking. A revoked certificate can pass.** Noncritical
CRL/AIA URLs are hints, not evidence of revocation checking or online readiness.
Ordinary certificates without Must-Staple are not rejected merely because no
revocation data is supplied. Must-Staple/TLS Feature certificates instead fail
unsupported; this is not an assertion that they were revoked.

Callers still need TLS key-possession proof, protocol/algorithm negotiation,
appropriate trust provisioning, revocation policy, application authorization,
and any additional policy/public-PKI requirements. There is no socket, Network,
HTTP, TLS session, trust-store integration, hostname discovery or Internet-ready
authentication guarantee in this API.

`X509TLSPeerTests` adds independent custom-CA fixtures for valid direct and
ordered multi-intermediate server/client chains, DNS/IPv4/IPv6, RSA/ECDSA/SHA-2,
explicit exact validity boundaries, rogue/missing anchor, signatures,
CA/pathLen/KU/EKU on leaf/issuers/anchor, critical/unprocessed/malformed
extensions, no-CN-fallback identity errors, ordered-chain limitations and Safe
value/result lifecycle. Original tests remain unchanged.

Regenerate public fixtures on POSIX from the repository root with
`node test/x509/generate_tls_peer_fixtures.mjs`. OpenSSL is only a generation
tool; disposable keys stay in memory/subprocess pipes and are never stored.
The generator removes its project-local public scratch files on exit. Tests
need neither Node nor OpenSSL and never generate keys or perform network I/O.

```sh
cmake --build build -j"$(nproc)"
ctest --test-dir build/test -R '^X509TLSPeerTests$' --output-on-failure
ctest --test-dir build/test --output-on-failure
```
