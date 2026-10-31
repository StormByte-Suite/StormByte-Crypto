# StormByte-Crypto

![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)
![C++26](https://img.shields.io/badge/C%2B%2B-26-00599C?logo=c%2B%2B&logoColor=white)
![CMake](https://img.shields.io/badge/CMake-3.28+-064F8C?logo=cmake&logoColor=white)
![License: LGPL v3 or commercial](https://img.shields.io/badge/License-LGPL_v3_or_commercial-blue.svg)
[![CI](https://github.com/StormByte-Suite/StormByte-Crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/StormByte-Suite/StormByte-Crypto/actions/workflows/ci.yml)
[![Sponsor](https://img.shields.io/badge/Sponsor-StormBytePP-ea4aaa?logo=githubsponsors)](https://github.com/sponsors/StormBytePP)

This repository is **StormByte Crypto**: hash, compress, encrypt, sign and key agreement for the StormByte C++ suite.

It depends on [StormByte Base](https://github.com/StormByte-Suite/StormByte/releases/tag/2.2.2) 2.2.2, [StormByte Buffer](https://github.com/StormByte-Suite/StormByte-Buffer) 2.0.5, [StormByte-Logger](https://github.com/StormByte-Suite/StormByte-Logger) 2.0.5 and [StormByte System](https://github.com/StormByte-Suite/StormByte-System) 2.1.2. Public headers live under `StormByte/crypto/`. Crypto++ and OpenSSL are private implementation dependencies: installed headers expose neither library's types. Bundled builds link both statically; consumers do not install either dependency.

The suite is split on purpose. Base, Buffer, Config, Database, Logger, Multimedia, Network and System are **other repositories**. This one does not implement them.

## What this module does

- **Hasher** — SHA-256, SHA-512, SHA3-256, SHA3-512, BLAKE2b, BLAKE2s. One-shot hex digest or a `Buffer::Consumer` that yields the digest when the source closes.
- **HMAC** — One-shot HMAC-SHA-256 and HMAC-SHA-384 with binary full-length tags, wiped `Secure::Password` keys, typed errors and constant-time tag verification.
- **TLS** — TLS 1.3 client/server sessions backed by pinned, statically linked OpenSSL 3.5.9. Sessions exchange ciphertext and plaintext through bounded caller-owned buffers; Crypto does no socket, DNS, HTTP or filesystem I/O.
- **Random** — Cryptographically secure bytes as `Safe::SecureBinary` and unbiased printable ASCII text as `Safe::String`, using the existing per-thread generator.
- **Compressor** — Zlib, Gzip, BZip2. Same block / stream contract as the rest of the module.
- **Symmetric crypter** — AES CBC, AES-GCM, ChaCha20-Poly1305, Camellia, Serpent, Twofish. Keys from `Secure::Password` via PBKDF2-HMAC-SHA256 (600 000 iterations). Authenticated modes fail closed on a bad tag or a wrong password.
- **Asymmetric crypter** — RSA OAEP-SHA and ECC ECIES. `Strategy::Native` is one PK transform per blob. `Strategy::Hybrid` wraps a random AES-256-GCM session key. Decrypt auto-detects the envelope.
- **Signer** — DSA, RSA PKCS#1 v1.5 + SHA-256, ECDSA, Ed25519. Block and streaming sign / verify.
- **Secret** — ECDH on secp256r1 / secp384r1 / secp521r1, and X25519. The shared secret is a `Secure::Password`, not a `std::string`.
- **KeyPair** — Generate, persist PEM or DER, optional PKCS#8 (PBES2 + PBKDF2 + AES-256-CBC, OpenSSL-compatible). Public key travels as `StormByte::Safe::String` (Base64 SPKI); private key stays in a `Secure::Password`. Handles are `StormByte::Safe::Clonable` with `Safe::Shared` (`KeyPair::Generic::PointerType`).
- **X509** — Strict DER/PEM certificate parsing and chain verification up to a trusted anchor: ecdsa-with-SHA256/384/512 and sha256/384/512WithRSAEncryption signatures, validity periods, basicConstraints (CA flag and path length), keyUsage and rejection of unknown critical extensions, plus strict subjectAltName DNS/IP extraction and expected-identity name checks.
- **Secure::Password / Secure::Vault** — wiped secret buffer and named store under `StormByte::Crypto::Secure`. Last owner zeros the bytes. Vault is movable, not copyable. `Password::Size()` is `StormByte::ByteSize`. A missing `Vault::Get` is `StormByte.Crypto.Secure.Vault: …`.
- **Buffer-first I/O** — `std::span<const std::byte>` → `Buffer::WriteOnly` for blocks; `Buffer::Consumer` in / out for pipelines (Network, Multimedia). Octet payloads are `StormByte::Safe::Binary`. Abstract counts use `StormByte::Size`; octet lengths use `StormByte::ByteSize`. Borrowed text inputs generally use `std::string_view`; key agreement borrows a `const Safe::String&`.

## The rest of the suite

| Module | Role | API |
| --- | --- | --- |
| [Base](https://github.com/StormByte-Suite/StormByte) | Exceptions, Expected, serialization, UUID, concepts, `Safe::String` / `Safe::WString` / `Safe::Binary` / `Size` / `ByteSize` | [/StormByte](http://suite.stormbyte.org/StormByte) |
| [Buffer](https://github.com/StormByte-Suite/StormByte-Buffer) | FIFO, SharedFIFO, Ring, Producer/Consumer and multi-stage pipelines | [/StormByte-Buffer](http://suite.stormbyte.org/StormByte-Buffer) |
| [Config](https://github.com/StormByte-Suite/StormByte-Config) | Human-readable text and versioned binary documents (groups, lists, raw bytes) | [/StormByte-Config](http://suite.stormbyte.org/StormByte-Config) |
| **Crypto** | This repository | [/StormByte-Crypto](http://suite.stormbyte.org/StormByte-Crypto) |
| [Database](https://github.com/StormByte-Suite/StormByte-Database) | One API over SQLite, PostgreSQL and MariaDB | [/StormByte-Database](http://suite.stormbyte.org/StormByte-Database) |
| [Logger](https://github.com/StormByte-Suite/StormByte-Logger) | Stream logger with levels, headers, hierarchical components and `Scope` | [/StormByte-Logger](http://suite.stormbyte.org/StormByte-Logger) |
| [Multimedia](https://github.com/StormByte-Suite/StormByte-Multimedia) | Decode, encode and containers without raw FFmpeg types; codecs enabled only if present | [/StormByte-Multimedia](http://suite.stormbyte.org/StormByte-Multimedia) |
| [Network](https://github.com/StormByte-Suite/StormByte-Network) | Framed packets, Client/Server, IPv4/IPv6 TCP and Buffer pipelines (compress/encrypt) | [/StormByte-Network](http://suite.stormbyte.org/StormByte-Network) |
| [System](https://github.com/StormByte-Suite/StormByte-System) | Processes, pipes and environment variables across Linux, Windows and macOS | [/StormByte-System](http://suite.stormbyte.org/StormByte-System) |

## Table of Contents

- [What this module does](#what-this-module-does)
- [The rest of the suite](#the-rest-of-the-suite)
- [Installation](#installation)
- [Usage](#usage)
	- [Private implementation](#private-implementation)
  - [Factories](#factories)
  - [Random bytes and text](#random-bytes-and-text)
  - [Password and Vault](#password-and-vault)
  - [Hash and compress](#hash-and-compress)
  - [HMAC](#hmac)
  - [Raw-key AEAD](#raw-key-aead)
  - [TLS sessions](#tls-sessions)
  - [Symmetric encrypt](#symmetric-encrypt)
  - [Asymmetric encrypt](#asymmetric-encrypt)
  - [KeyPair on disk](#keypair-on-disk)
  - [Sign and verify](#sign-and-verify)
  - [Key agreement](#key-agreement)
  - [Certificate chains](#certificate-chains)
- [Security notes](#security-notes)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

## Installation

Needs a C++26 compiler, CMake 3.28 or newer, [StormByte-BuildMaster](https://github.com/StormByte-Suite/StormByte-BuildMaster) >= 2.1.3, [StormByte Base](https://github.com/StormByte-Suite/StormByte/releases/tag/2.2.2) 2.2.2, [StormByte Buffer](https://github.com/StormByte-Suite/StormByte-Buffer) 2.0.5, [StormByte-Logger](https://github.com/StormByte-Suite/StormByte-Logger) 2.0.5 and [StormByte System](https://github.com/StormByte-Suite/StormByte-System) 2.1.2. Configure downloads those release archives. There is no StormByte source submodule. Crypto++, OpenSSL 3.5.9 (pinned with its CMake port) and libbzip2 are build dependencies. OpenSSL is compiled statically into Crypto and is not part of the public API. Windows builds this module with MSVC: Crypto++ does not build with clang-cl.

```sh
git clone --recursive https://github.com/StormByte-Suite/StormByte-Crypto.git
cd StormByte-Crypto
cmake -S . -B build
cmake --build build
```

Shared vs static follows CMake `BUILD_SHARED_LIBS` (declared in `lib/`, default ON). A plain configure builds the shared library. `-DBUILD_SHARED_LIBS=OFF` builds a static archive; on Windows the headers then do not use `dllimport`. The downloaded archives are the same mode. Prefer a **static** Crypto++ link when you redistribute; that is independent of whether StormByte-Crypto itself is shared or static.

A shared build keeps this library as its own `.so` / `.dll`. Under the LGPL that is usually the simpler way to ship: the user can replace that file. A static archive is folded into your binary. The LGPL still applies to this code; you must give the recipient a way to relink your product with a different build of this library. If that does not fit how you distribute the final product, a commercial license is available from the copyright holder (see [License](#license)).

Link `StormByte-Crypto` (and Buffer / System / Base). Base supplies the Safe text and binary types; there is no separate String dependency. Include path: the public install prefix, headers as `#include <StormByte/crypto/….hxx>`.

## Usage

Headers are `#include <StormByte/crypto/….hxx>`. Namespace root is `StormByte::Crypto`. Wiped secrets live in `StormByte::Crypto::Secure`.

Nothing in the public tree includes Crypto++. Private headers are not installed.

Public handles are `Clonable` + `MakePointer` / `Shared`. KeyPair, Signer, Crypter and Secret take `KeyPair::Generic::PointerType`, not `std::shared_ptr`. Exceptions use `Path{"Crypto"}`; child offices add their own segment. `what()` is `StormByte.Crypto` or `StormByte.Crypto.<Child>: message`. Secure uses `StormByte.Crypto.Secure` / `StormByte.Crypto.Secure.Vault`.

Every public Crypto class, including algorithm bases, leaves and exceptions, explicitly declares `MaybeSafe` for that exact type: use ABI-compatible toolchains and keep Crypto, Base and Buffer loaded while their objects or lifetime callbacks exist. Consumer-derived types are not registered by these declarations. Clone and move callbacks are created inside Crypto. This is conditional DLL safety, not compatibility between arbitrary C++ ABIs. Each Safe component still enforces its own value requirements; registration alone does not make a move-only or non-default-constructible type admissible to every collection.

Private keys and key-agreement results use `StormByte::Safe::Optional<Secure::Password>`, not `std::optional`. Dereferencing a const Safe optional returns a password snapshot; retain the snapshot while borrowing its bytes. A default-constructed `Password` is empty and can be stored in `Safe::Vector`, `Safe::Optional` and `Safe::Queue`. Persistence accepts native-character `KeyPair::PathView`; force-inlined `std::filesystem::path` adapters read the caller's path locally, then Crypto constructs its own path from the view. Rebuild binary consumers after these ABI changes.

Key agreement returns an empty Safe optional for invalid keys or failed derivation. `Share` and `DeriveSharedSecret` are not `noexcept`: creating even an empty Safe result may fail to allocate and propagate a StormByte exception.

The usage snippets below are independent function-body examples: keep the includes at file scope and place the remaining statements inside a function. Retain each `Safe::Binary` returned by `FIFO::Data()` while using its `span()`; the span borrows that binary's storage. `Safe::Binary::size()` returns `ByteSize`, so use `span()` for APIs expecting a standard byte span, and explicitly convert lengths to `std::size_t` when constructing a `std::string_view`.

### Private implementation

The private `Engine` and helper code uses Safe ownership too, not just the installed API. Crypter operations, compressor stream operations, signer/verification boxes and Crypto++ filters use `Safe::Unique`; hasher operations and deserialized keys use `Safe::Shared`. Temporary text uses `Safe::String`, binary work buffers use `Safe::Binary` / `Safe::Vector`, and secure content retains a wiped `Safe::Vector<unsigned char>`. Safe storage alone does not wipe secrets: the private secure-content and wipe helpers perform that work explicitly.

Streaming workers use `Safe::Thread`. Hasher, crypter and signer callbacks use `Safe::Function<void()>` with Crypto-owned invocation, clone and release callbacks, rather than an owning `std::function`. Callback contexts allocate through `Safe::Heap`; cloning creates a separate context and release destroys it in Crypto before freeing the Base allocation. Move-only engine state is retained through Safe shared owners where the callback must be copyable. Crypto and Base must remain loaded until those workers and callback copies finish. Crypto++ remains a private backend; this port does not make its native types public Safe values or remove its own internal allocations.

Crypto's streaming loops use `Safe::this_thread::yield()` when waiting for input. Buffer supplies the channel synchronization: its sink, ring and pumper implementations use `Safe::Mutex`, `Safe::UniqueLock` and `Safe::ConditionVariable` (with Safe atomic state where needed). These are dependency implementation details, not additional Mutex members in Crypto's engine or an exported Crypto locking API.

### Factories

```cpp
#include <StormByte/crypto/compressor/generic.hxx>
#include <StormByte/crypto/crypter/asymmetric/generic.hxx>
#include <StormByte/crypto/crypter/symmetric/generic.hxx>
#include <StormByte/crypto/hasher/generic.hxx>
#include <StormByte/crypto/keypair/ecdh.hxx>
#include <StormByte/crypto/keypair/ecdsa.hxx>
#include <StormByte/crypto/keypair/rsa.hxx>
#include <StormByte/crypto/secret/generic.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/crypto/signer/generic.hxx>

using namespace StormByte::Crypto;

Secure::Password password("factory-placeholder");
auto ecdsaKp = KeyPair::ECDSA::Generate(256);
auto ecdhKp = KeyPair::ECDH::Generate(256);
auto hasher = Hasher::Create(Hasher::Type::SHA256);
auto zip    = Compressor::Create(Compressor::Type::Zlib, 6);
auto aes    = Crypter::Create(Crypter::Type::AES_GCM, password);
auto rsaKp  = KeyPair::RSA::Generate(2048);
auto rsa    = Crypter::Create(Crypter::Type::RSA, rsaKp);
auto signer = Signer::Create(Signer::Type::ECDSA, ecdsaKp);
auto ecdh   = Secret::Create(Secret::Type::ECDH, ecdhKp);
```

Concrete types (`Crypter::AES_GCM`, `KeyPair::X25519`, `Signer::ED25519`, …) construct the same way without going through `Create`.

### Random bytes and text

```cpp
#include <StormByte/crypto/random.hxx>

auto bytes = StormByte::Crypto::Random::Bytes(StormByte::ByteSize{32});
auto text = StormByte::Crypto::Random::Text(StormByte::Size{24});
```

`Bytes` returns exactly the requested number of cryptographically secure octets.
`Text` returns exactly the requested number of uniformly sampled ASCII characters
from 33 (`!`) through 126 (`~`), without spaces or embedded NUL. Its trailing NUL
does not count toward the length. Each call returns independently owned storage.

Both functions reject size zero with `StormByte::Crypto::Random::Exception`.
Provider failures throw the same exception, with path `StormByte.Crypto.Random`;
allocation errors propagate unchanged. No partial result is returned on failure,
and temporary provider storage is securely wiped. `Bytes` returns
`Safe::SecureBinary`: discarded/released bytes are automatically zeroed, and
memory locking (`mlock` / `VirtualLock`) is best effort. Locking can fail due to
OS limits; it is not a guarantee against swapping. Moving or swapping into a plain
`Safe::Binary` loses these protections, and copies through borrowed views remain
the caller's responsibility. Direct writes through `data()`, `span()` or indexed
access do not provide a separate wipe-before-overwrite guarantee.
`Text` still returns ordinary `Safe::String`, **not automatically wiped or locked**.

The public API exposes neither the provider nor its RNG. Crypto's internal random
passwords, salts, IVs and hybrid session keys reuse this byte API through a private
secure-buffer adapter. `Crypter::Symmetric::RandomPassword` retains its existing
`noexcept` contract and still accepts length zero (an empty password); a failure
inside that legacy `noexcept` API terminates rather than propagating an exception.

### Password and Vault

`Secure::Password` is Crypto's opaque public container for secret bytes (passphrases, private key DER, shared secrets); `Random::Bytes` exposes generated bytes through Base's `Safe::SecureBinary`. A `Safe::Shared` owner retains Crypto's password buffer; copies share it and the last owner wipes it. `Size()` is `StormByte::ByteSize`. Ordinary `Safe::String` and `Safe::Binary` are not automatically wiped secret containers.

Ingestion distinguishes borrowed text from ceded mutable Safe text. No STL string allocation is adopted or freed inside Crypto.

- `std::string_view` is copied into wiped storage without modifying its source. The caller remains responsible for wiping the original bytes and any other copies. A caller-owned STL string can supply a view, but there is no dedicated `std::string&` constructor and it is not emptied by construction.
- A non-const `StormByte::Safe::String&` is *ceded*: the constructor copies into wiped storage, then overwrites and clears the argument using Base-owned text storage. Other pre-existing copies are not wiped.
- Literals use `explicit Password(const char*)`. They are copied; the source is not wiped (it lives in read-only storage). Use that form for tests and placeholders, not for production secrets kept in source.
- Raw bytes (`const void*` + `ByteSize`) are copied and not wiped; the caller owns the source.

Both `std::string_view` and `Safe::String&` preserve the full stored length, including embedded NUL bytes; only the mutable Safe overload wipes its source. Only the `const char*` overload stops at the first NUL. Use a length-bearing view or raw bytes with an explicit `ByteSize` for binary secrets.

```cpp
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/crypto/secure/vault.hxx>
#include <StormByte/crypto/crypter/symmetric/generic.hxx>

using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;
using StormByte::Crypto::Secure::Vault;

StormByte::Safe::String databaseInput("temporary-database-secret");
Password db(databaseInput);           // databaseInput is emptied and wiped
StormByte::Safe::String safeInput("temporary-secret");
Password safePassword(safeInput);     // safeInput is emptied and wiped
Password placeholder("token-xyz");    // literal: not wiped
const std::string_view borrowed("borrowed-placeholder");
Password borrowedPassword(borrowed);  // source remains unchanged

Vault vault;
vault.Store("database", db);
vault.Store("api", placeholder);

if (auto p = vault.Get("database")) {
	auto aes = Crypter::Create(Crypter::Type::AES_GCM, *p);
}

if (*vault.Get("database") == db)
	; // constant-time compare of the bytes

vault.Remove("api");
vault.Clear();
```

`Vault` is movable, not copyable. Its private member is directly `Safe::Map<Safe::String, Password>` with Base-owned storage, not a PIMPL, `Safe::Unique` or an STL map. Its construction, move, assignment and destruction are exported by Crypto. A move leaves the source empty and reusable. Names are borrowed `std::string_view` and converted to Safe keys inside Crypto. `Get` returns `ExpectedPassword`; a missing name contains `Secure::VaultException`. `Store`, `Get`, `Contains` and `Remove` are not `noexcept`, because Safe key construction or map operations can allocate. `Clear`, `Size` and `Empty` are `noexcept`; `Size` returns `StormByte::Size`. Removing an entry or clearing the vault drops its password owner; a password retained elsewhere remains valid and is wiped only when its last owner is released. As a move-only type, Vault is not a `SafeValue` collection element.

### Hash and compress

```cpp
#include <StormByte/crypto/hasher/generic.hxx>
#include <StormByte/crypto/compressor/generic.hxx>
#include <StormByte/buffer/fifo.hxx>
#include <StormByte/buffer/producer.hxx>

using namespace StormByte::Crypto;

auto sha = Hasher::Create(Hasher::Type::SHA256);
auto zip = Compressor::Create(Compressor::Type::Zlib, 6);

StormByte::Buffer::FIFO digest, packed;
const StormByte::Safe::Binary message("payload");

sha->Hash(message.span(), digest);
zip->Compress(message.span(), packed);

StormByte::Buffer::Producer prod;
prod.Write(message);
prod.Close();
auto hashed = sha->Hash(prod.Consumer());
```

### HMAC

HMAC accepts binary message bytes and a key held by `Secure::Password`. `Compute` returns a full-length binary tag (32 bytes for SHA-256, 48 for SHA-384); `Verify` rejects any other tag length and returns `false` for a full-length mismatch.

```cpp
#include <StormByte/crypto/hmac.hxx>
#include <StormByte/crypto/secure/password.hxx>

using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;

Password key(secretBytes.data(), StormByte::ByteSize{secretBytes.size()});
auto tag = HMAC::Compute(HMAC::Algorithm::SHA256, key, messageBytes);
if (tag) {
	auto verified = HMAC::Verify(HMAC::Algorithm::SHA256, key, messageBytes, *tag);
}
```

Both operations return `StormByte::Expected` with `HMAC::Error` on failure. Empty keys and messages are valid HMAC inputs; longer-than-block-size keys are normalized by HMAC. The API does not expose key bytes or Crypto++ types.

### Raw-key AEAD

`<StormByte/crypto/aead.hxx>` provides `AEAD::Seal(algorithm, key, nonce,
plaintext, aad = {})` and `AEAD::Open(algorithm, key, nonce, ciphertext, tag,
aad = {})`. Algorithms are `AEAD::Algorithm::AES128GCM` (exactly 16 raw key
bytes) and `AES256GCM` (exactly 32). Keys use `Secure::Password`; all other
inputs are synchronous borrowed `std::span<const std::byte>` values supporting
binary NULs. Empty plaintext/ciphertext and AAD are valid.

```cpp
#include <StormByte/crypto/aead.hxx>

using namespace StormByte::Crypto;
Secure::Password key(keyBytes.data(), StormByte::ByteSize{keyBytes.size()});
auto sealed = AEAD::Seal(AEAD::Algorithm::AES128GCM, key, nonceBytes, messageBytes, aadBytes);
if (sealed) {
	auto plaintext = AEAD::Open(AEAD::Algorithm::AES128GCM, key, nonceBytes,
		sealed->ciphertext.span(), sealed->tag.span(), aadBytes);
	// plaintext contains independently owned wiped Safe::SecureBinary only on success.
}
```

Nonces must be exactly **12 bytes** and tags exactly **16 bytes**; shortened
tags are never accepted. **Never reuse a nonce with the same key**, including
across processes or restarts. The caller manages nonces and per-key usage limits.
GCM permits at most `2^36 - 32` message bytes and `2^61 - 1` AAD bytes per call
(also subject to address space/allocation limits). `Seal` returns
`Expected<AEAD::Sealed, AEAD::Error>` containing detached public `Safe::Binary`
ciphertext of exactly plaintext length and a full tag. `Open` returns
`Expected<Safe::SecureBinary, AEAD::Error>`: it authenticates the entire ciphertext
before releasing any plaintext, wiping all tentative plaintext on failure.
Same-length wrong keys/nonces/tags/AAD or modified ciphertext yield
`AuthenticationFailed`; invalid algorithms, sizes and over-limit inputs have
distinct typed errors. Crypto++ exceptions become `BackendFailure`; allocation
and non-backend exceptions propagate, as with HKDF. No mutable shared secret
buffer or backend object is exposed. Plaintext copies own independent wiped
storage (with best-effort page locking); keys share immutable wiped storage.
All returned byte allocations remain Base-owned. Borrowed plaintext views and
copies/moves into plain `Binary` are the caller's responsibility: keep secrets
in `SecureBinary` and do not retain a view beyond its owner's lifetime.
Use compatible ABIs and keep Crypto/Base loaded while values exist.

This API reuses Crypto++'s detached one-shot GCM, private `PasswordAccess`, and
existing secure ownership/wiping rather than duplicating a cipher engine.
The password/stream `CipherOps` derives keys with PBKDF2, writes random
salt/IV envelopes and drains into public buffers, so it is deliberately not
forced into raw-key authenticated secret output. Existing crypters and their
wire formats remain unchanged. This step does not provide ChaCha20-Poly1305,
TLS records/sessions, sequence-number logic, nonce generation or streaming AEAD.

### TLS sessions

`<StormByte/crypto/tls/session.hxx>` provides an OpenSSL-backed TLS 1.3
client/server session. OpenSSL 3.5.9 is pinned and linked statically; its types
and symbols are hidden from the shared Crypto library's exported interface.
`Session` is deliberately transport-independent: it performs no socket, DNS,
HTTP, filesystem, system-clock or trust-store I/O. The consumer owns transport
scheduling, deadlines and retries, and feeds/drains bytes through caller-owned
buffers. Serialize calls on each session; a session is not thread-safe.

The API supports TLS 1.3 only, with validated cipher-suite, group and signature
scheme lists. Defaults contain the complete supported profile in preference
order:

| Independent list | Default entries (preferred first) | Registered IDs |
| --- | --- | --- |
| Version | `Version::TLS13` only | `0x0304` (supported_versions, not record legacy version) |
| Cipher suites | `CipherSuite::TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384` | `0x1301`, `0x1302` |
| Groups | `Group::X25519`, `Secp256r1` (P-256) | `0x001d`, `0x0017` |
| Signature schemes | `SignatureScheme::ECDSA_SECP256R1_SHA256`, `RSA_PSS_RSAE_SHA256` | `0x0403`, `0x0804` |

`TLS::DescribeCipherSuite` returns the **fixed**, inseparable mapping to
`AEAD::Algorithm::AES128GCM` + `HKDF::Algorithm::SHA256`, or `AES256GCM` +
`SHA384`. Configuration accepts suite identifiers, not arbitrary cipher/hash
pairs. SHA-256/SHA-384 designate the transcript and HKDF hash; existing HMAC,
HKDF and raw-key AEAD supply primitives, not the TLS key schedule or records.
Group vocabulary is justified by existing X25519 and secp256r1 ECDH keypair/key
agreement primitives. OpenSSL implements the TLS key schedule, handshake,
CertificateVerify and record protection; the existing standalone `Signer` API
is not used for TLS wire formatting. RSA-PSS/SHA-256 is available for TLS
CertificateVerify, distinct from the existing RSA PKCS#1 v1.5 signing API.
No other suite, group, signature or legacy protocol version is allowed.

```cpp
#include <StormByte/crypto/tls/policy.hxx>

using namespace StormByte::Crypto;
TLS::Configuration configuration;
configuration.cipher_suites = {TLS::CipherSuite::TLS_AES_256_GCM_SHA384};
configuration.groups = {TLS::Group::Secp256r1, TLS::Group::X25519};
auto policy = TLS::Validate(configuration);
if (policy) {
	const auto& allowed = policy->Preferences();
	// The session engine consumes this TLS 1.3 policy.
}
```

`TLS::ClientConfiguration` requires an expected DNS or binary IP SAN identity.
Its `TrustSource` is either the versioned bundled-root set or explicit custom
anchors; these sources are never silently merged. `TLS::ServerConfiguration`
accepts a PEM leaf/intermediate chain and matching private key, and can require
a client certificate against explicit CA anchors. Optional ALPN lists use the
standard length-prefixed wire format. `NegotiatedALPN()` reports the selected
protocol after a successful handshake.

Create a client session, then drive it with the transport's buffers:

```cpp
#include <StormByte/crypto/tls/session.hxx>

using namespace StormByte::Crypto;
TLS::ClientConfiguration options;
options.identity = X509::SubjectAltName(X509::SubjectAltNameType::DNS,
	Safe::Binary("service.example"));
auto session = TLS::Session::CreateClient(options);
// DrainEncrypted() sends pending handshake bytes; FeedEncrypted() supplies
// received bytes; ReadPlaintext() and WritePlaintext() exchange application data.
```

Feed and write operations may consume partial input; zero indicates backpressure
or no current progress. Drain output promptly. Input chunks are capped at 64 KiB,
pending ciphertext at 1 MiB, certificate chains at 18 certificates/256 KiB DER,
and plaintext is processed in records no larger than 16 KiB. Fatal protocol and
peer-validation failures are sticky; pending TLS alert bytes can still be
drained after failure. `Shutdown()` exchanges TLS `close_notify`; the transport
must continue driving the session until both sides close or an external deadline
expires.

Server certificate chain validation combines OpenSSL's path construction with
Crypto's configured trust and TLS peer policy. Expected server identity is
checked against SAN only, with no CN fallback. Revocation is opt-in: when
`require_revocation` is enabled, the caller must supply one fresh, verified CRL
or OCSP response per non-anchor certificate in leaf-to-issuer order before the
handshake. Crypto does not fetch revocation data; the transport/application
must provide it. Missing or invalid required evidence rejects the peer. The
mTLS client-certificate path currently has no revocation-evidence option.

These are stream-engine tests over two in-memory TLS endpoints, not sockets or
an external service. Network integration remains the responsibility of the
consumer.

`Validate` rejects `UnsupportedVersion`; `EmptyCipherSuites`,
`UnsupportedCipherSuite`, `DuplicateCipherSuite`; `EmptyGroups`,
`UnsupportedGroup`, `DuplicateGroup`; and `EmptySignatureSchemes`,
`UnsupportedSignatureScheme`, `DuplicateSignatureScheme`. Undesignated
registered values and unknown casts both yield the relevant unsupported error.
Validation checks version, suites, groups, signatures in that order, then
each list left to right. Allowed nonempty subsets and reordering are preserved
exactly: no sorting, arbitrary algorithm mixing, inserted fallback or selection.

`TLS::Policy{}` retains the default profile. Successful validation copies the
mutable input's `Safe::Vector` lists into a const `Configuration` owned through
`Safe::Shared` on Base's heap. Caller edits and destruction cannot change it.
Policy copies **and moves** share immutable ownership and preserve the source;
assignment replaces an entire snapshot. Mutable Configuration copies are
independent; its moves leave source lists empty. `Preferences()` is read-only:
borrowed references must not outlive their snapshot. Safe Optional/Vector can
retain policies. Keep compatible Crypto/Base providers loaded while these
values exist. Base allocation errors propagate; no native backend type escapes.

`X509::TLSPeerVerifier` and `X509::VerifyPaymentPeer` remain independently useful
offline path/evidence APIs; neither performs TLS key-possession proof or network
fetching. `TLS::Session` composes the configured TLS handshake with trust,
identity and certificate-purpose checks without changing the existing
certificate parser or `VerifyChain` behavior.

### Symmetric encrypt

Password → random salt + PBKDF2-HMAC-SHA256 → key. AES-GCM and ChaCha20-Poly1305 authenticate; a wrong password or a flipped bit returns `false`.

```cpp
#include <StormByte/crypto/crypter/symmetric/aes_gcm.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/buffer/fifo.hxx>
#include <StormByte/buffer/producer.hxx>

using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;

Password password("SecurePassword123!");
Crypter::AES_GCM gcm(password);

StormByte::Buffer::FIFO encrypted, decrypted;
const StormByte::Safe::Binary message("authenticated payload");

gcm.Encrypt(message.span(), encrypted);
const auto ciphertext = encrypted.Data();
gcm.Decrypt(ciphertext.span(), decrypted);

StormByte::Buffer::Producer prod;
prod.Write(message);
prod.Close();
auto cipher = gcm.Encrypt(prod.Consumer());
auto plain  = gcm.Decrypt(cipher);
```

CBC siblings (AES, Camellia, Serpent, Twofish) use the same `Encrypt` / `Decrypt` names.

### Asymmetric encrypt

`Native` is one PK operation per blob (small messages) and is the default strategy. `Hybrid` is a random AES-256-GCM key wrapped with the recipient public key. Pass the strategy to `Encrypt`, not to the constructor. Decrypt reads the header and picks the path.

```cpp
#include <StormByte/crypto/keypair/rsa.hxx>
#include <StormByte/crypto/crypter/asymmetric/rsa.hxx>
#include <StormByte/buffer/fifo.hxx>

using namespace StormByte::Crypto;

auto kp = KeyPair::RSA::Generate(2048);
Crypter::RSA hybrid(kp);

const StormByte::Safe::Binary message("hybrid payload");
StormByte::Buffer::FIFO encrypted, decrypted;
hybrid.Encrypt(message.span(), encrypted, Crypter::Asymmetric::Strategy::Hybrid);
const auto ciphertext = encrypted.Data();
hybrid.Decrypt(ciphertext.span(), decrypted);

StormByte::Buffer::FIFO nativeEncrypted;
hybrid.Encrypt(message.span(), nativeEncrypted, Crypter::Asymmetric::Strategy::Native);
```

ECC (`Crypter::ECC` + `KeyPair::ECC`) is the same API.

### KeyPair on disk

| Format | Meaning |
| --- | --- |
| `PEM` | OpenSSL text (`BEGIN` / Base64). Default. |
| `DER` | Raw ASN.1. Same family as many `.cer` / `.crt` blobs. |

```cpp
#include <StormByte/crypto/keypair/rsa.hxx>
#include <StormByte/crypto/secure/password.hxx>

#include <filesystem>

using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;

const std::filesystem::path directory = std::filesystem::temp_directory_path();
auto kp = KeyPair::RSA::Generate(2048);
kp->Save(directory, "app", KeyPair::StorageFormat::PEM);

Password wrap("disk-secret");
kp->Save(directory, "app-enc", wrap);

auto loaded = KeyPair::Load(directory / "app.pub.pem", directory / "app.pem");
auto enc = KeyPair::Load(directory / "app-enc.pub.pem", directory / "app-enc.pem", wrap);
```

Use an existing application-owned directory in production and check the `Save` boolean / `Load` pointer before proceeding. Explicit `std::filesystem::path` values select the caller-side adapters without relying on conversions from string literals. Direct `KeyPair::PathView` arguments borrow native characters: `wchar_t` on Windows, `char` on Linux/macOS. On Windows use native wide text for a direct view, or build a filesystem path in the caller; do not pass narrow UTF-8 text as though it were a native Windows `PathView`. A direct view's source must stay alive for the call; Crypto copies it before OS operations.

The same keys can live in memory instead of files, for example bytes read from a database or embedded with `#embed`. `SavePublic(format)` and `SavePrivate(format[, password])` return a `StormByte::Safe::SecureBinary` (wiped and page-locked; empty on failure), and `KeyPair::Load` takes `const SecureBinary&` for one key, or a public/private pair where an empty buffer means absent. The file overloads read or write exactly these bytes.

```cpp
#include <StormByte/crypto/keypair/ecdsa.hxx>
#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/safe/secure_binary.hxx>

using namespace StormByte::Crypto;
using StormByte::Safe::SecureBinary;

auto kp = KeyPair::ECDSA::Generate(384);
SecureBinary pub = kp->SavePublic();                      // PEM "PUBLIC KEY"
SecureBinary priv = kp->SavePrivate(KeyPair::StorageFormat::DER);

auto pair = KeyPair::Load(pub, priv);
auto verifyOnly = KeyPair::Load(pub);
// An EC key loads as Type::ECC; rebuild the role you need from its material.
auto ecdsa = KeyPair::ECDSA::MakePointer<KeyPair::ECDSA>(verifyOnly->PublicKey(), std::nullopt);
```

Wrong or missing wrap password fails closed. Type comes from the OID (RSA, DSA, EC, Ed25519, X25519). Generate → Save → Load stays usable for encrypt, sign and share. X25519 also understands raw 32-byte library form. `PublicKey()` is `const StormByte::Safe::String&`; convert with `std::string{std::string_view{kp->PublicKey()}}` if you need a `std::string`.

### Sign and verify

```cpp
#include <StormByte/crypto/keypair/ed25519.hxx>
#include <StormByte/crypto/signer/generic.hxx>
#include <StormByte/buffer/fifo.hxx>

using namespace StormByte::Crypto;

auto kp = KeyPair::ED25519::Generate(256);
auto signer = Signer::Create(Signer::Type::ED25519, kp);

StormByte::Buffer::FIFO sig;
const StormByte::Safe::Binary message("signed payload");
signer->Sign(message.span(), sig);
const auto signature = sig.Data();
bool ok = signer->Verify(message.span(), std::string_view(
	reinterpret_cast<const char*>(signature.data()),
	static_cast<std::size_t>(signature.size())));
```

Streaming: `signer->Sign(consumer)` / `signer->Verify(consumer, signature)`.

`ED25519::Generate(unsigned short bits)` requires an argument, although the current implementation ignores it because the algorithm has a fixed key size. The examples pass `256`; `X25519::Generate` follows the same convention.

### Key agreement

```cpp
#include <StormByte/crypto/keypair/x25519.hxx>
#include <StormByte/crypto/secret/x25519.hxx>

using namespace StormByte::Crypto;

auto alice = KeyPair::X25519::Generate(256);
auto bob   = KeyPair::X25519::Generate(256);

auto secret = Secret::Create(Secret::Type::X25519, alice);
auto shared = secret->Share(bob->PublicKey());
```

`Generic::Share`, `ECDH::Share` and `X25519::Share` take `const StormByte::Safe::String&` and are `const` member functions. `X25519::DeriveSharedSecret(KeyPair::Generic::PointerType, const StormByte::Safe::String&)` is the static alternative. The peer key is Base64 public material, borrowed during the call; `PublicKey()` already returns the required reference. A borrowed `std::string_view` is not the Share signature: construct a `Safe::String` explicitly when starting from a view. The result is `StormByte::Safe::Optional<Secure::Password>`. ECDH is the same with `KeyPair::ECDH::Generate(256|384|521)` and `Secret::Type::ECDH`.

### Certificate chains

```cpp
#include <StormByte/crypto/x509/certificate.hxx>

using namespace StormByte::Crypto;

// anchorPem is trusted (e.g. #embed); leafPem and intermediatePem arrive untrusted.
auto anchor = X509::Load(anchorPem);
auto leaf = X509::Load(leafPem);
auto intermediates = X509::LoadAll(intermediatePem);
bool trusted = anchor && leaf
	&& leaf->VerifyChain(intermediates, *anchor)
	&& leaf->HasKeyUsage(X509::KeyUsage::DigitalSignature);
auto key = trusted ? leaf->PublicKey() : nullptr;	// public-only KeyPair for Signer
```

Expected identities are compared against the subjectAltName extension only, never the common name, and are supplied by the caller (for example from the connection URL), never taken from the certificate:

```cpp
auto dns = leaf->VerifyDNSName("www.example.com");        // Expected<void, X509::IdentityError>
const std::array<std::byte, 4> address{std::byte{192}, std::byte{0}, std::byte{2}, std::byte{10}};
auto ip = leaf->VerifyIPAddress(address);                  // 4 or 16 network-order bytes
```

`VerifyDNSName` drops one trailing dot, rejects empty, malformed, NUL-containing, wildcard or numeric-final-label names, requires ASCII A-labels for internationalized names (no IDNA conversion), and compares case-insensitively; a certificate `*.example.com` matches exactly one non-empty leftmost label. `VerifyIPAddress` compares raw bytes exactly with no textual parsing, DNS fallback or IPv4-mapped equivalence. The extension is validated strictly first, so a malformed entry returns `MalformedSubjectAltName` even when another entry matches; other results are `InvalidExpectedName`, `InvalidExpectedAddress`, `MissingSubjectAltName` and `NoMatch`. This is only a name comparison: it does not verify the chain, validity, key usage or extended key usage and does not authenticate a TLS peer.

`X509::Load` takes DER or the first PEM `CERTIFICATE` block; `LoadAll` returns every block of a bundle and fails as a whole when one is malformed. `VerifyChain` checks every link's signature and name, every validity period (anchor included; pass a `TimePoint` to choose the instant), that each issuer is a v3 CA allowed to sign certificates whose path length covers the CAs below it, and that no certificate carries an unrecognized critical extension. The anchor's own signature is not checked: it is trusted by being supplied. Names are compared byte-for-byte; `VerifyChain` does not process revocation (CRL/OCSP), name constraints or policies, and the leaf's key usage is left to the caller. For explicit offline revocation evidence, use `X509::RevocationVerifier`; payment peer checks combine bundled path validation with mandatory Good status for each non-anchor certificate through `X509::VerifyPaymentPeer`. Neither operation fetches evidence or performs a TLS handshake; see [doc/trust-path-validation.md](doc/trust-path-validation.md) for accepted evidence formats and limitations.

TLS 1.3 signing-purpose validation is separate:

```cpp
auto serverPurpose = leaf->VerifyTLSPurpose(X509::TLSRole::Server); // Expected<void, X509::PurposeError>
auto clientPurpose = leaf->VerifyTLSPurpose(X509::TLSRole::Client);
```

Under RFC 5280 §4.2.1.12, missing EKU is unrestricted. Present EKU must explicitly
include `serverAuth` (`1.3.6.1.5.5.7.3.1`) or `clientAuth` (`1.3.6.1.5.5.7.3.2`)
for the selected role. This conservative policy uses the RFC's permission to
require a particular purpose even when `anyExtendedKeyUsage` (`2.5.29.37.0`) is
present: anyEKU alone is rejected, while anyEKU plus the required explicit purpose
is accepted. `1.3.6.1.5.5.7.3.0` is **not** anyEKU. Unknown well-formed OIDs and
repeated purpose OIDs are allowed but do not grant a role. The complete non-empty
DER sequence and all OID encodings are checked before accepting a match, for both
critical and noncritical EKU. Duplicate extensions remain rejected at parsing.

For **both** TLS 1.3 roles, present KU must permit `digitalSignature` (RFC 8446
§4.4.2.2); `keyEncipherment`-only or `keyAgreement`-only does not suffice. Missing
KU is unrestricted. The purpose check also requires strict DER named BIT STRING
encoding over the nine defined bits: zero padding, at least one set bit, no
undefined bits and no redundant trailing zero bits. Existing `Parse`,
`HasKeyUsage` and `VerifyChain` behavior is unchanged.

Typed errors, in precedence order, are `UnsupportedRole`, `InvalidCertificate`
(empty or moved-from object), `MalformedExtendedKeyUsage`, `MalformedKeyUsage`,
`ExtendedKeyUsageNotAllowed`, and `KeyUsageNotAllowed`. Error allocation failures
propagate as `Safe::AllocationError`. Purpose results do **not** prove trust,
validity, chain-wide EKU restrictions, critical-extension processing, end-entity
classification, name identity, signature/key suitability or TLS authentication;
CA flags are deliberately not consulted. Public RSA and EC keys can be loaded,
but this purpose/path API does not itself implement TLS RSA-PSS or
CertificateVerify. `TLS::Session` provides those through its separate OpenSSL
handshake engine. Applications using the standalone verifier must still
compose trust/chain/time, identity, usage and algorithm policy before
authenticating a peer. Fixture regeneration uses
`python3 test/x509/generate_purpose_fixtures.py` from the repository root; that
generator uses OpenSSL but writes no private keys to the repository. The TLS
session tests also link the bundled OpenSSL library.

An additive **offline, constrained** composition is available through
`<StormByte/crypto/x509/tls_peer.hxx>`:

```cpp
X509::SubjectAltName expected(X509::SubjectAltNameType::DNS,
	Safe::Binary("www.example.com"));
auto peer = X509::TLSPeerVerifier::Verify(*leaf, intermediates, *anchor,
	explicitCallerTime, X509::TLSRole::Server, &expected);
```

This checks the exact caller-ordered path to the explicitly selected anchor,
inclusive time, issuer CA/pathLen/keyCertSign, leaf digitalSignature, chainwide
role-specific EKU and SAN identity. Server identity is mandatory; omitting a
Client identity makes **no client-identity or application-authorization claim**.
Anchor certificate restrictions are deliberate local policy; its self-signature
is not verified. Unsupported path restrictions and unprocessed critical
extensions fail explicitly; benign noncritical hints are not blanket-rejected.
Detailed Safe-owned results retain purpose/identity errors and certificate index.
Existing `VerifyChain` and license behavior is unchanged.

This is **not full RFC 5280 or public HTTPS-ready authentication**: no
handshake/key-possession proof, revocation (a revoked certificate may pass),
path builder, system trust or networking. See the
[supported subset, anchor policy, error map and limitations](doc/tls-peer-verification.md).

## Security notes

- **Decompression of untrusted input is not size-bounded.** Like the underlying zlib/libbzip2, `Compressor` decompresses as much as the stream decodes to; a small malicious input can expand to a very large output ("decompression bomb"). If you decompress data from an untrusted source, bound it yourself: check the expected/maximum size before decompressing, or stop draining the streaming `Consumer` once your own limit is hit.
- `X509` verification only proves a certificate chains to the anchor you pass in. An anchor embedded in your own binary is as trustworthy as the binary itself.
- Private key files written by `KeyPair::Save`/`SavePrivate` are created owner-only (`0600` on POSIX) and refuse to write through a pre-existing symlink at the destination path. Public key files are unaffected by either restriction.
- Prefer ceded mutable `Safe::String` input when the source must be wiped by `Password` construction. Borrowed `string_view`, literals and raw-byte inputs are copied but their sources are not wiped; clear sensitive source storage yourself when it is no longer needed. Merely destroying or clearing an ordinary string does not guarantee that its former bytes are overwritten.

## Contributing

Issues only on this repository. Fork and open a pull request against `master`.

## License

From 2.0.0, original StormByte-Crypto source is dual-licensed:

1. GNU Lesser General Public License version 3 or later. See [LICENSE](LICENSE) and <https://www.gnu.org/licenses/lgpl-3.0.html>.
2. A commercial license from the copyright holder (David C. Manuelda, StormBytePP).

Neither license covers other StormByte modules or third-party material shipped under `thirdparty/` (including Crypto++, bundled libbzip2, and vendored StormByte trees). Those keep their own licenses. Neither license grants patent rights.

Binary releases add THIRD-PARTY beside LICENSE. That file is a notice for what was compiled into the shared library, not another grant. The texts it names are the COPYING.* files in the same archive.

## Support

StormByte is developed in spare time. Sponsorship is optional and does not buy features, priority or support.

- [GitHub Sponsors](https://github.com/sponsors/StormBytePP)
- [PayPal](https://paypal.me/StormBytePP)
