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

## [2.0.0] - 2026-10-06

### Changed
- Exception message constructors now accept `std::string_view`; exception copy/move special members are defined out of line in their owning Crypto DLLs.
- Port public text to Base's `StormByte::Safe::String` and polymorphic ownership to `StormByte::Safe::Clonable` / `Safe::Shared`; Password accepts mutable `std::string&` for wipeable caller-owned input.
- Updated repository links to the StormByte-Suite organization and removed documentation for the retired standalone dependency.
- Shared vs static follows CMake `BUILD_SHARED_LIBS` (declared in the project root, default ON). There is no `STORMBYTE_CRYPTO_SHARED` CMake option. When the library is shared, the compile definition `STORMBYTE_CRYPTO_SHARED` is still set so `visibility.h` can distinguish `dllexport` / `dllimport` / static. CI passes `-DBUILD_SHARED_LIBS=ON`. Vendored Crypto++ and BZip2 stay static BM components; their archives are closed onto consumers by the static sidecar.
- **Breaking**: Port to StormByte Base 2.0.0, Buffer 2.0.0 and System 2.0.0. Public types follow Base 2.0: `Clonable` + `MakePointer` / `Shared` instead of `std::shared_ptr`, `StormByte::BinaryData` instead of Buffer `DataType` / raw vectors at the public edge, `StormByte::Size` for abstract counts and `StormByte::ByteSize` for octet lengths (`Password::Size()` is `ByteSize`). `std::size` is gone from the public API.
- **Breaking**: Exceptions no longer use `StormByte::Component`. `Crypto::Exception` forwards `Path{"Crypto"}` to `StormByte::Exception`. Per-office exceptions (`Compressor::Exception`, `Crypter::Exception`, `Hasher::Exception`, `KeyPair::Exception`, `Secret::Exception`, `Signer::Exception`) live in their own namespace and add only their own segment; Crypto concatenates before forwarding. `what()` is `StormByte.Crypto` or `StormByte.Crypto.<Child>: message`.
- **Breaking**: Buffer 2.0 streaming contract. Block I/O is `std::span<const std::byte>` into `Buffer::WriteOnly`. Pipelines take `Buffer::Consumer` and return a consumer; `FIFO::Data()` is `BinaryData`.
- **Breaking**: Factories and keypair / signer / crypter / secret constructors take `KeyPair::Generic::PointerType` (`Safe::Shared`), not `std::shared_ptr`. Generate / Load return that pointer type. `Safe::Clonable::MakePointer` is used for public-only views.
- **Breaking**: Public leaf classes are `final`. Destructors of public types are declared in the header and defined out of line in the `.cxx` (`= default`) so the vtable and typeinfo stay on this side of the DLL.
- **Breaking**: Non-secret public text is ingested as `std::string_view` and copied inside the library. That includes KeyPair leaf constructors, `Secret::Share`, Vault names (`Store`/`Get`/`Contains`/`Remove`), `KeyPair::Generic::Save` `baseName`, and `Signer::Verify` / `DoVerify` signatures. `StormByte::Safe::String` and `std::string` convert to `string_view`. Owned public text (`PublicKey()`) is `const StormByte::Safe::String&`. Conversion to `std::string` is explicit (`std::string{std::string_view{...}}`).
- **Breaking**: `Password` no longer takes `std::string` by value. Ingest is a non-const `std::string&`; the bytes are copied into wiped storage and the caller's object is overwritten and cleared. Literals use `explicit Password(const char*)` and are not wiped. Raw bytes (`const void*` + `ByteSize`) are copied and not wiped. `string_view` is rejected so a live password buffer cannot remain in the caller after construction, and so a `std::string` is not moved across the DLL heap.
- **Breaking**: `Password` and `Vault` move to `StormByte::Crypto::Secure` (`StormByte/crypto/secure/{password,vault,exception}.{hxx,cxx}`). `Crypto::VaultException` is now `Crypto::Secure::VaultException` (`what()` is `StormByte.Crypto.Secure.Vault: message`). `Secure::Exception` is `StormByte.Crypto.Secure`. `ExpectedPassword` lives next to Vault. Headers `StormByte/crypto/password.hxx` and `StormByte/crypto/vault.hxx` are gone.
- **Breaking**: Private backend namespace `Implementation` is `Engine` (`StormByte::Crypto::Engine`). Public headers do not mention it.
- Dual license on sources and `LICENSE`: LGPL-3.0-or-later or commercial. Neither covers Crypto++, bundled libbzip2, or vendored StormByte trees under `thirdparty/`.
- Tests rewritten to the suite format (section headers, snake_case functions, accumulating `main`). Coverage of hasher, compressor, crypter, signer, secret, password, vault and keypair (save/load and OpenSSL fixtures) updated to the new pins.
- Hybrid encrypt/decrypt tests compare plaintext with `std::string::operator==` (`ASSERT_TRUE`), not `ASSERT_EQUAL`. The harness C-string path false-failed prefix+4096 payloads on Ubuntu clang while the bytes already matched.
- Doxygen (`ENABLE_DOC`) resolves Buffer, Logger, System and Base headers via `INCLUDE_PATH` and skips `thirdparty`.
- `CONTRIBUTING.md` and `CODING_STYLE.md` aligned with Logger.

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
