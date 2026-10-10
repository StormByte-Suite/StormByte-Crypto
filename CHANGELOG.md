# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Summary]

StormByte Crypto is the cryptography module of the StormByte C++ suite.

It depends on [StormByte Base ≥ 2.0.0](https://github.com/StormByte-Suite/StormByte/releases/tag/2.0.0), [StormByte Buffer ≥ 2.0.0](https://github.com/StormByte-Suite/StormByte-Buffer/releases/tag/2.0.0) and [StormByte System ≥ 2.0.0](https://github.com/StormByte-Suite/StormByte-System/releases/tag/2.0.0). This repository is not Base, Buffer, Config, Database, Logger, Multimedia, Network or System.

Public headers under `StormByte/crypto/` cover Hasher, Compressor, Crypter (symmetric and asymmetric), Signer, Secret, KeyPair, Password and Vault. Crypto++ never leaves the private tree.

If you landed here from a release link and have not read the tree:

- What this module is, how to build it, and short examples: [README.md](https://github.com/StormByte-Suite/StormByte-Crypto/blob/master/README.md)
- License: GNU Lesser General Public License version 3 or later, [LICENSE](https://github.com/StormByte-Suite/StormByte-Crypto/blob/master/LICENSE)

## [Unreleased]

[Unreleased]: https://github.com/StormByte-Suite/StormByte-Crypto/compare/2.0.0...HEAD

## [2.0.0] - 2026-10-10

### Changed
- **Breaking**: Port public APIs to StormByte Base, Buffer and System 2.0.0.
  - Public octet payloads use `StormByte::Safe::Binary` instead of Buffer `DataType` / raw vectors. Binary storage is `Safe::Vector<std::byte>` on Base's heap, not an STL alias; lengths and indices use `StormByte::ByteSize`. Explicit STL imports and force-inlined exports copy between heaps rather than adopting the source allocation. Abstract counts use `StormByte::Size`; `Password::Size()` is `ByteSize`.
  - Polymorphic ownership uses `StormByte::Safe::Clonable`, `MakePointer` and `Safe::Shared` instead of `std::shared_ptr`. Factories and keypair / signer / crypter / secret constructors take `KeyPair::Generic::PointerType`; Generate / Load return that pointer type. Public-only views use `Safe::Clonable::MakePointer`.
  - Buffer 2.0 block I/O uses `std::span<const std::byte>` into `Buffer::WriteOnly`. Pipelines take `Buffer::Consumer` and return a consumer; `FIFO::Data()` is `Safe::Binary`.
  - Borrowed text uses `std::string_view` for KeyPair leaf constructors, Vault names (`Store` / `Get` / `Contains` / `Remove`), `KeyPair::Generic::Save` `baseName`, and `Signer::Verify` / `DoVerify` signatures; owned copies are made inside Crypto where needed. `Secret::Generic::Share` and its ECDH/X25519 overrides instead borrow `const StormByte::Safe::String&`, as does the peer-key argument of static `X25519::DeriveSharedSecret`. Owned public text (`PublicKey()`) is `const StormByte::Safe::String&`. Safe and STL strings convert to `string_view`; conversion back to `std::string` is explicit (`std::string{std::string_view{...}}`). Construct a Safe string explicitly when supplying a peer key from a view.
- **Breaking**: Complete conditional DLL-boundary ownership and provider lifecycle contracts. Binary consumers must rebuild.
  - Every public class, including algorithm bases, leaves and exceptions, has an exact `STORMBYTE_DECLARE_MAYBE_SAFE` declaration. These declarations assert provider responsibility, not certification by Base or registration of consumer-derived types. Clone/Move allocation callbacks stay in Crypto; compatible compiler ABIs and loaded provider modules remain required. Safe components retain their own value requirements, including copyability and default construction where required.
  - Public leaf classes are `final`. Public destructors are declared in headers and defined out of line in `.cxx` (`= default`) so vtables and typeinfo stay inside Crypto. KeyPair material construction and value operations also run out of line.
  - KeyPair private material and Secret results use `Safe::Optional<Password>` instead of STL optional layout; private-key byte views retain password snapshots. Secret's `Share` / `DeriveSharedSecret` no longer promise `noexcept`, because constructing a Safe optional result can fail to allocate; invalid keys still return an empty result.
  - Persistence exports native-character `PathView` arguments and keeps `std::filesystem::path` access in force-inlined caller adapters, preserving native Unicode paths on Windows, Linux and macOS.
  - The `SecureContent` forward declaration matches its `class` definition, avoiding struct/class ABI mismatches under MSVC and clang-cl.
- **Breaking**: Rework secure password ingestion, storage and namespaces.
  - `Password` and `Vault` move to `StormByte::Crypto::Secure` (`StormByte/crypto/secure/{password,vault,exception}.{hxx,cxx}`). `Crypto::VaultException` becomes `Crypto::Secure::VaultException` (`what()` is `StormByte.Crypto.Secure.Vault: message`); `Secure::Exception` is `StormByte.Crypto.Secure`. `ExpectedPassword` lives next to Vault. The old `StormByte/crypto/password.hxx` and `StormByte/crypto/vault.hxx` headers are gone.
  - Password uses `Safe::Shared` for its private secure-buffer owner; the last owner wipes the bytes. Empty default construction allocates no storage, compares equal to other empty passwords and supports `Safe::Vector`, `Safe::Optional` and `Safe::Queue`.
  - Password accepts borrowed `std::string_view` and ceded mutable `Safe::String&`, not a dedicated `std::string&` or by-value STL string. Both copy the full length, including embedded NUL bytes, into wiped storage without adopting source allocations. The Safe overload overwrites and clears its source using Base-owned text storage; the view overload leaves its source untouched and the caller remains responsible for wiping it.
  - Literals use `explicit Password(const char*)`, stop at the terminator and are not wiped. Raw bytes (`const void*` + `ByteSize`) are copied and not wiped.
  - Vault directly contains `Safe::Map<Safe::String, Password>` with Base-owned storage, not an STL store or a `Safe::Unique` PIMPL. Construction, movement, assignment and destruction are exported by Crypto; moved-from vaults remain empty and reusable. Named operations construct Safe keys from borrowed views and no longer promise `noexcept`; `Clear`, `Size` and `Empty` remain `noexcept`, with `Size` returning `StormByte::Size`. Returned passwords retain shared ownership after removal or clearing. Vault remains move-only and is not a `SafeValue` collection element.
- Port private engine ownership, temporary storage and workers to Safe components.
  - Crypter operations, compressor stream operations, signer/verification boxes and Crypto++ filters use `Safe::Unique`; hasher operations and deserialized keys use `Safe::Shared`. Private text uses `Safe::String`, binary buffers use `Safe::Binary` / `Safe::Vector`, and `SecureContent` keeps explicitly wiped `Safe::Vector<unsigned char>` storage. Safe allocation by itself does not wipe secrets.
  - Streaming workers use `Safe::Thread`; hasher, crypter and signer callbacks use `Safe::Function<void()>` instead of owning STL functions. Contexts allocate through `Safe::Heap` and bind real Crypto-owned invocation, clone and release callbacks; cloning creates a separate context, and release destroys it in Crypto before freeing Base storage. Safe shared owners retain move-only engine state where copyable callbacks require it. Provider modules must remain loaded until workers and callback copies finish; Crypto++ native types remain private and retain their own internal allocation rules.
  - Crypto input-wait loops use `Safe::this_thread::yield()`. Channel synchronization stays in Buffer's sink/ring/pumper implementations, which use `Safe::Mutex`, `Safe::UniqueLock`, `Safe::ConditionVariable` and Safe atomic state; these are not new locking members or public APIs in Crypto.
- **Breaking**: Update exception paths and backend naming.
  - Exceptions no longer use `StormByte::Component`. `Crypto::Exception` forwards `Path{"Crypto"}` to `StormByte::Exception`. Per-office exceptions (`Compressor::Exception`, `Crypter::Exception`, `Hasher::Exception`, `KeyPair::Exception`, `Secret::Exception`, `Signer::Exception`) live in their own namespace and add only their own segment; Crypto concatenates before forwarding. `what()` is `StormByte.Crypto` or `StormByte.Crypto.<Child>: message`.
  - Exception message constructors accept `std::string_view`; exception copy/move special members are defined out of line in their owning Crypto DLLs.
  - Private backend namespace `Implementation` becomes `Engine` (`StormByte::Crypto::Engine`). Public headers do not mention it.
- Update test coverage to the suite's 2.0.0 contracts.
  - Tests use section headers, snake_case functions and accumulating `main`. Hasher, compressor, crypter, signer, secret, password, vault and keypair coverage (save/load and OpenSSL fixtures) follows the new pins.
  - Password regressions cover long mutable Safe text, borrowed full and partial views, embedded NUL bytes, shared-owner lifetime and Safe collection compatibility. Ceded Safe strings become empty; views preserve their source and produce an independent password copy. The Safe-string regression includes leading, internal and trailing NUL bytes; ordinary test inputs do not append terminators. Binary equality compares equal-length inputs with an internal NUL.
  - KeyPair and Secret regressions check private-key copies and shared-secret snapshots retained after resetting their optional owner. Vault tests cover moved-from reuse and retained passwords after clearing the store.
  - Hybrid encrypt/decrypt tests compare Safe plaintext using `ASSERT_EQUAL`; both the inputs and the deserialization helpers use `Safe::String`, not `std::string`. Comparisons use the Safe text equality path rather than raw C-string comparison, which previously false-failed prefix+4096 payloads on Ubuntu clang while the bytes already matched.
- Align build configuration and API documentation.
  - Shared vs static follows root CMake `BUILD_SHARED_LIBS` (default ON), not a `STORMBYTE_CRYPTO_SHARED` CMake option. Shared builds still define `STORMBYTE_CRYPTO_SHARED` so `visibility.h` distinguishes `dllexport` / `dllimport` / static. CI passes `-DBUILD_SHARED_LIBS=ON`. Vendored Crypto++ and BZip2 remain static BM components; their archives are closed onto consumers by the static sidecar.
  - Doxygen (`ENABLE_DOC`) resolves Buffer, Logger, System and Base headers via `INCLUDE_PATH` and skips `thirdparty`. Dependency tag downloads and cross-module links use verified HTTPS endpoints; Safe registration and force-inline macros are preprocessed explicitly. Warnings remain non-fatal in normal builds; warnings-as-errors is reserved for internal validation. Generation verified without warnings with Doxygen 1.16.1.
  - `CONTRIBUTING.md` and `CODING_STYLE.md` follow Logger's conventions. README and coding guidelines use `Safe::String` / `Safe::WString` instead of removed `CString` / `WCString`; Password documentation describes length-preserving binary ingestion.
  - README block examples retain `Safe::Binary` snapshots and pass `span()` instead of treating `ByteSize` as a standard span length. Each example defines its own input; asymmetric encryption and decryption use separate buffers. Persistence examples use explicit caller-owned filesystem paths and document native Windows wide-character views and source lifetimes.
  - Factory examples include the symmetric/asymmetric factory headers. Asymmetric strategies are selected per `Encrypt` call (`Native` is the default), not in the constructor. Ed25519/X25519 generation examples supply the required size argument, which their fixed-size implementations currently ignore.
- Update repository references and licensing.
  - Repository links use the StormByte-Suite organization; documentation for the retired standalone dependency is removed.
  - Sources and `LICENSE` are dual-licensed: LGPL-3.0-or-later or commercial. Neither covers Crypto++, bundled libbzip2, or vendored StormByte trees under `thirdparty/`.

### Notes

- Installed headers still do not include Crypto++. Crypto++ stays under `lib/private` and `thirdparty`.
- Needs a C++26 compiler, [StormByte Base ≥ 2.0.0](https://github.com/StormByte-Suite/StormByte/releases/tag/2.0.0), [StormByte Buffer ≥ 2.0.0](https://github.com/StormByte-Suite/StormByte-Buffer/releases/tag/2.0.0), [StormByte System ≥ 2.0.0](https://github.com/StormByte-Suite/StormByte-System/releases/tag/2.0.0), and Crypto++ at build time.

[2.0.0]: https://github.com/StormByte-Suite/StormByte-Crypto/compare/1.1.0...2.0.0

## [1.1.0] - 2026-09-13

### Changed

- Exception hierarchy ported to `StormByte::Component`: `Crypto::Exception` names itself `"Crypto"`, and each per-component exception (`CompressorException`, `CrypterException`, `HasherException`, `KeyPairException`, `SecretException`, `SignerException`, `VaultException`) combines its own name with the parent's through its constructor instead of manual string concatenation. Removed the now-unneeded workaround for MSVC constructor-inheritance ambiguity.
- Bumped the StormByte Buffer dependency to 1.1.0.

### Added

- `VaultException`: `Vault::Get` on a missing entry now returns a dedicated exception instead of the generic `Exception`.
- Header-only `StormByte::Type::ByteInputRange` overloads for block hashing, compression, encryption, signing and signature verification. They accept byte-convertible input ranges such as `std::string_view`, `std::vector<uint8_t>` and `std::span`, then delegate to the existing byte-span APIs without changing their ABI.

### Fixed

- **Security hardening of `KeyPair` private-key handling**, found and closed during a full pre-release audit:
  - Private-key material (PKCS#8 DER, PBES2 plaintext/ciphertext) was never actually wiped from memory. The wipe helper constructed a *new* `CryptoPP::SecByteBlock` copy from the buffer's pointer and zeroed that copy instead of the original — `CryptoPP::SecBlock`'s `(pointer, length)` constructor always allocates and copies, it never wraps existing storage. Added a direct `SecureWipe` overload for `std::vector<unsigned char>` and wipe the original buffers (and `std::string` plaintext buffers) in place.
  - The shared `CryptoPP::AutoSeededRandomPool` used for salt/IV/key generation was a single process-wide instance accessed without synchronization. `AutoSeededRandomPool` is not safe for concurrent use, and the streaming encrypt/decrypt paths each spawn their own detached worker thread, so two concurrent streaming operations raced on the RNG's internal state. Made it `thread_local` instead — confirmed race-free with ThreadSanitizer (fully-instrumented `WITH_CRYPTOPP=BUNDLED` build; the `SYSTEM` build previously produced ABI-boundary false positives).
  - Private key files (`KeyPair::Save`/`SavePrivate`, encrypted or not, PEM or DER) were created with the OS-default file permissions, potentially group/world-readable depending on umask. They are now restricted to owner read/write (`0600`) right after writing. Public key files are unaffected. Best-effort on filesystems/platforms without POSIX permission bits.
  - `WriteFileBytes` (used by every `KeyPair::Save`/`SavePublic`/`SavePrivate` path) refuses to write through a pre-existing symlink at the destination path, closing a local TOCTOU attack where a symlink planted at the target filename would redirect the write to an arbitrary file.
- CMake: promote the system BZip2 imported target to global scope so `WITH_BZIP2=SYSTEM` resolves from the top-level directory.
- Tests: silence `-Werror=unused-variable` under GCC in the AES/Camellia/Serpent/Twofish symmetric crypter tests, where the decrypt result is intentionally unchecked (CBC either fails padding or succeeds with garbage).

### Notes

- Decompression of untrusted input is not size-bounded by this module (same as the underlying zlib/libbzip2); callers must bound it themselves. See [README.md](https://github.com/StormByte-Suite/StormByte-Crypto/blob/master/README.md#security-notes).
- Needs a C++26 compiler, [StormByte Base ≥ 1.1.0](https://github.com/StormByte-Suite/StormByte/releases/tag/1.1.0), [StormByte Buffer ≥ 1.1.0](https://github.com/StormByte-Suite/StormByte-Buffer/releases/tag/1.1.0), and Crypto++ at build time.

[1.1.0]: https://github.com/StormByte-Suite/StormByte-Crypto/compare/1.0.0...1.1.0

## [1.0.0] - 2026-09-04

Initial public release of StormByte Crypto.

### Added

- Hasher: SHA-256, SHA-512, SHA3-256, SHA3-512, BLAKE2b, BLAKE2s (block and stream, hex digest)
- Compressor: Zlib, Gzip, BZip2 with configurable level (block and stream)
- Symmetric crypter: AES CBC, AES-GCM, ChaCha20-Poly1305, Camellia, Serpent, Twofish
- Password-based keys via PBKDF2-HMAC-SHA256 (600 000 iterations)
- Asymmetric crypter: RSA OAEP-SHA, ECC ECIES
- `Strategy::Native` and `Strategy::Hybrid` (AES-256-GCM session key wrapped with the public key); decrypt auto-detects
- Signer: DSA, RSA PKCS#1 v1.5 + SHA-256, ECDSA, Ed25519 (block and stream)
- Secret: ECDH (secp256r1 / secp384r1 / secp521r1) and X25519; result is a `Password`
- KeyPair generate: DSA, RSA, ECC, ECDH, ECDSA, Ed25519, X25519
- KeyPair Save / Load: PEM and DER; public Base64; private `Password`; optional PKCS#8 (PBES2 + AES-256-CBC)
- `Password` — shared wiped secret; last owner zeros the bytes
- `Vault` — named `Password` store; movable, not copyable
- Factories: `Create` on Hasher, Compressor, Crypter, Signer, Secret, KeyPair
- StormByte Buffer pipelines (`Consumer` / `Producer`) on every transform
- Exception hierarchy with component prefixes
- Project version read from the `VERSION` file
- CMake 3.28 floor

### Notes

- Installed headers do not include Crypto++. Static Crypto++ means consumers do not install it.
- Authenticated modes and wrapped private keys fail closed on a bad password or a bad tag.
- Needs a C++26 compiler, [StormByte Base ≥ 1.1.0](https://github.com/StormByte-Suite/StormByte/releases/tag/1.1.0), [StormByte Buffer ≥ 1.1.0](https://github.com/StormByte-Suite/StormByte-Buffer/releases/tag/1.1.0), and Crypto++ at build time.

[1.0.0]: https://github.com/StormByte-Suite/StormByte-Crypto/releases/tag/1.0.0
