# StormByte-Crypto

![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)
![C++26](https://img.shields.io/badge/C%2B%2B-26-00599C?logo=c%2B%2B&logoColor=white)
![CMake](https://img.shields.io/badge/CMake-3.28+-064F8C?logo=cmake&logoColor=white)
![License: LGPL v3 or commercial](https://img.shields.io/badge/License-LGPL_v3_or_commercial-blue.svg)
[![CI](https://github.com/StormByte-Suite/StormByte-Crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/StormByte-Suite/StormByte-Crypto/actions/workflows/ci.yml)
[![Sponsor](https://img.shields.io/badge/Sponsor-StormBytePP-ea4aaa?logo=githubsponsors)](https://github.com/sponsors/StormBytePP)

This repository is **StormByte Crypto**: hash, compress, encrypt, sign and key agreement for the StormByte C++ suite.

It depends on [StormByte Base ≥ 2.0.0](https://github.com/StormByte-Suite/StormByte/releases/tag/2.0.0), [StormByte Buffer ≥ 2.0.0](https://github.com/StormByte-Suite/StormByte-Buffer/releases/tag/2.0.0) and [StormByte System ≥ 2.0.0](https://github.com/StormByte-Suite/StormByte-System/releases/tag/2.0.0). Public headers live under `StormByte/crypto/`. Crypto++ stays in the private tree: installed headers never mention `CryptoPP::`. With a static Crypto++ link, consumers do not install it.

The suite is split on purpose. Base, Buffer, Config, Database, Logger, Multimedia, Network and System are **other repositories**. This one does not implement them.

## What this module does

- **Hasher** — SHA-256, SHA-512, SHA3-256, SHA3-512, BLAKE2b, BLAKE2s. One-shot hex digest or a `Buffer::Consumer` that yields the digest when the source closes.
- **Compressor** — Zlib, Gzip, BZip2. Same block / stream contract as the rest of the module.
- **Symmetric crypter** — AES CBC, AES-GCM, ChaCha20-Poly1305, Camellia, Serpent, Twofish. Keys from `Secure::Password` via PBKDF2-HMAC-SHA256 (600 000 iterations). Authenticated modes fail closed on a bad tag or a wrong password.
- **Asymmetric crypter** — RSA OAEP-SHA and ECC ECIES. `Strategy::Native` is one PK transform per blob. `Strategy::Hybrid` wraps a random AES-256-GCM session key. Decrypt auto-detects the envelope.
- **Signer** — DSA, RSA PKCS#1 v1.5 + SHA-256, ECDSA, Ed25519. Block and streaming sign / verify.
- **Secret** — ECDH on secp256r1 / secp384r1 / secp521r1, and X25519. The shared secret is a `Secure::Password`, not a `std::string`.
- **KeyPair** — Generate, persist PEM or DER, optional PKCS#8 (PBES2 + PBKDF2 + AES-256-CBC, OpenSSL-compatible). Public key travels as `StormByte::Safe::String` (Base64 SPKI); private key stays in a `Secure::Password`. Handles are `StormByte::Safe::Clonable` with `Safe::Shared` (`KeyPair::Generic::PointerType`).
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
  - [Password and Vault](#password-and-vault)
  - [Hash and compress](#hash-and-compress)
  - [Symmetric encrypt](#symmetric-encrypt)
  - [Asymmetric encrypt](#asymmetric-encrypt)
  - [KeyPair on disk](#keypair-on-disk)
  - [Sign and verify](#sign-and-verify)
  - [Key agreement](#key-agreement)
- [Security notes](#security-notes)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

## Installation

Needs a C++26 compiler, CMake 3.28 or newer, [StormByte Base ≥ 2.0.0](https://github.com/StormByte-Suite/StormByte/releases/tag/2.0.0), [StormByte Buffer ≥ 2.0.0](https://github.com/StormByte-Suite/StormByte-Buffer/releases/tag/2.0.0) and [StormByte System ≥ 2.0.0](https://github.com/StormByte-Suite/StormByte-System/releases/tag/2.0.0). Crypto++ and libbzip2 are build dependencies. Prefer a **static** Crypto++ link when you redistribute.

```sh
git clone --recursive https://github.com/StormByte-Suite/StormByte-Crypto.git
cd StormByte-Crypto
cmake -S . -B build
cmake --build build
```

Shared vs static follows CMake `BUILD_SHARED_LIBS` (declared in `lib/`, default ON). A plain configure builds the shared library. `-DBUILD_SHARED_LIBS=OFF` builds a static archive; on Windows the headers then do not use `dllimport`. Vendored StormByte dependencies follow the same mode. Prefer a **static** Crypto++ link when you redistribute; that is independent of whether StormByte-Crypto itself is shared or static.

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

### Password and Vault

`Secure::Password` is the only public container for secret bytes (passphrases, private key DER, shared secrets). A `Safe::Shared` owner retains Crypto's secure buffer; copies share it and the last owner wipes it. `Size()` is `StormByte::ByteSize`. Ordinary `Safe::String` and `Safe::Binary` are not automatically wiped secret containers.

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

## Security notes

- **Decompression of untrusted input is not size-bounded.** Like the underlying zlib/libbzip2, `Compressor` decompresses as much as the stream decodes to; a small malicious input can expand to a very large output ("decompression bomb"). If you decompress data from an untrusted source, bound it yourself: check the expected/maximum size before decompressing, or stop draining the streaming `Consumer` once your own limit is hit.
- Private key files written by `KeyPair::Save`/`SavePrivate` are created owner-only (`0600` on POSIX) and refuse to write through a pre-existing symlink at the destination path. Public key files are unaffected by either restriction.
- Prefer ceded mutable `Safe::String` input when the source must be wiped by `Password` construction. Borrowed `string_view`, literals and raw-byte inputs are copied but their sources are not wiped; clear sensitive source storage yourself when it is no longer needed. Merely destroying or clearing an ordinary string does not guarantee that its former bytes are overwritten.

## Contributing

Issues only on this repository. Fork and open a pull request against `master`.

## License

From 2.0.0, original StormByte-Crypto source is dual-licensed:

1. GNU Lesser General Public License version 3 or later. See [LICENSE](LICENSE) and <https://www.gnu.org/licenses/lgpl-3.0.html>.
2. A commercial license from the copyright holder (David C. Manuelda, StormBytePP).

Neither license covers other StormByte modules or third-party material shipped under `thirdparty/` (including Crypto++, bundled libbzip2, and vendored StormByte trees). Those keep their own licenses. Neither license grants patent rights.

## Support

StormByte is developed in spare time. Sponsorship is optional and does not buy features, priority or support.

- [GitHub Sponsors](https://github.com/sponsors/StormBytePP)
- [PayPal](https://paypal.me/StormBytePP)
