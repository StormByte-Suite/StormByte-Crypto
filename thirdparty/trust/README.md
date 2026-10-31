# Curated public TLS server roots

Certificate/trust **data**, not an additional runtime code dependency. The data
in `certdata.txt`, the extracted `roots.pem`, and the embedded certificate
material in `lib/private/StormByte/crypto/x509/bundled_roots.hxx` are redistributed
under Mozilla Public License 2.0 (`../../COPYING.MPL2`). They are not covered by
StormByte-Crypto's original-source commercial/LGPL grant.

Publisher: Mozilla NSS, https://github.com/mozilla/nss.

- Source revision: `0a2b0c75fa036930d98331b721c0780693a3e17a`
- Upstream change date: **2026-10-20**
- Retrieval date: **2026-10-31**
- Exact source URL:
  https://raw.githubusercontent.com/mozilla/nss/0a2b0c75fa036930d98331b721c0780693a3e17a/lib/ckfw/builtins/certdata.txt
- Source SHA-256:
  `3ec2b4d240dc12c747eaf450061db84af757c483bbda302f9e29ceb5d70be510`
- Extracted PEM SHA-256:
  `605910d60aa2dedf70cca0d048c17b60f6edb3931f8471dde17822b4df49b5a3`
- Admitted server roots: **117 of 169 certificate objects**.

## Selection and exclusions

Extraction joins each certificate to its unique NSS trust object using its DER
SHA-1 fingerprint, then verifies the issuer and serial attributes also match.
SHA-1 is only the upstream record identifier, not the provenance integrity
algorithm: the pinned source and generated PEM are verified with SHA-256.

Admission requires all of:

1. `CKA_TRUST_SERVER_AUTH == CKT_NSS_TRUSTED_DELEGATOR`;
2. `CKA_NSS_MOZILLA_CA_POLICY == CK_TRUE`;
3. an **explicit** `CKA_NSS_SERVER_DISTRUST_AFTER == CK_FALSE`.

`MUST_VERIFY_TRUST`, `NOT_TRUSTED`, missing cutoff metadata and every dated
server-distrust restriction are excluded. `manifest.json` retains every
certificate's fingerprint, server trust flag, cutoff presence/value, and
admission decision. No certificate is admitted merely because it appears in
certdata, and email/code-signing trust is not server trust.

NSS dated server distrust is an issuance-date restriction. Rather than flatten
away that obligation, this deliberately conservative profile excludes the
**entire root**, even its pre-cutoff leaf issuances. In this revision Izenpe.com
is the one otherwise server-trusted root excluded for a dated restriction
(`260415235959Z`). Entrust dated restrictions and G4's absent cutoff are retained
in the manifest and excluded as well.

This is **not all of Mozilla/Firefox/NSS policy**: external distrust lists,
CT, EV, browser-specific requirements, future changes, and revocation databases
are not imported. Certificate-encoded constraints remain subject to the
platform path validator, and unsupported restrictions fail on Linux. Root
certificate validity is independently enforced at the requested validation time
on all platforms, inclusively at both endpoints.

## Reproduction and updates

From the repository root, `python3 thirdparty/trust/generate_snapshot.py` verifies
the pinned source and deterministically reproduces the PEM, complete manifest
and embedded header. It is offline, uses only Python's standard library, and
is not invoked at runtime or required to build the library. Unknown metadata,
ambiguous records and unexpected hashes fail extraction.

Updates require deliberate source/policy/license review, regenerated artifacts,
tests and a **new published StormByte-Crypto version**. No automatic network
updates, environment override, system CA fallback or mutable production root
registry exists. Consumers must install a future release to receive trust changes.
