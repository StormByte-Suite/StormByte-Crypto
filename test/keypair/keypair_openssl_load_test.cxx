/*
 * Copyright (C) 2024-2026 David C. Manuelda (StormBytePP)
 *
 * This file is part of StormByte-Crypto.
 *
 * StormByte-Crypto original source is dual-licensed:
 *
 * 1. GNU Lesser General Public License v3.0 (or later)
 *    You may redistribute and/or modify this file under the terms of the
 *    GNU Lesser General Public License as published by the Free Software
 *    Foundation, either version 3 of the License, or (at your option)
 *    any later version.
 *
 * 2. Commercial license
 *    Alternatively, this file may be used under the terms of a commercial
 *    license agreement with the copyright holder
 *    (David C. Manuelda <StormByte@gmail.com>).
 *
 * Both licenses apply only to original StormByte-Crypto source in this
 * repository. They do not cover other StormByte modules or any third-party
 * material shipped with this repository (including everything under
 * thirdparty/, in particular Crypto++, bundled libbzip2, the StormByte-Buffer
 * tree and the StormByte suite it vendors), which remains under its own license.
 *
 * Neither license grants any patent rights. Any patent licenses required
 * to use this software or third-party components must be obtained separately
 * from the patent holders.
 *
 * StormByte-Crypto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * version 3 along with StormByte-Crypto. If not, see
 * <https://www.gnu.org/licenses/lgpl-3.0.html>.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-StormByte-Commercial
 */

#include "helpers.hxx"

#include <StormByte/buffer/fifo.hxx>
#include <StormByte/crypto/crypter/asymmetric/ecc.hxx>
#include <StormByte/crypto/crypter/asymmetric/rsa.hxx>
#include <StormByte/crypto/keypair/dsa.hxx>
#include <StormByte/crypto/keypair/ecc.hxx>
#include <StormByte/crypto/keypair/ecdh.hxx>
#include <StormByte/crypto/keypair/ecdsa.hxx>
#include <StormByte/crypto/keypair/ed25519.hxx>
#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/keypair/rsa.hxx>
#include <StormByte/crypto/keypair/x25519.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/crypto/secret/ecdh.hxx>
#include <StormByte/crypto/secret/x25519.hxx>
#include <StormByte/crypto/signer/dsa.hxx>
#include <StormByte/crypto/signer/ecdsa.hxx>
#include <StormByte/crypto/signer/ed25519.hxx>
#include <StormByte/crypto/signer/rsa.hxx>
#include <StormByte/safe/string.hxx>
#include <StormByte/safe/vector.hxx>
#include <StormByte/test_handlers.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string_view>

using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;
using StormByte::Buffer::FIFO;
using StormByte::Safe::String;
using StormByte::Safe::Vector;
namespace fs = std::filesystem;

#ifndef STORMBYTE_TEST_KEYS_DIR
#	error "STORMBYTE_TEST_KEYS_DIR must be defined by CMake"
#endif
#ifndef STORMBYTE_TEST_KEYS_PASSWORD
#	error "STORMBYTE_TEST_KEYS_PASSWORD must be defined by CMake"
#endif

namespace {
	fs::path KeysDir() {
		return fs::path(STORMBYTE_TEST_KEYS_DIR);
	}

	fs::path KeyFile(std::string_view name) {
		return KeysDir() / name;
	}

	bool FileExists(const fs::path& p) {
		return fs::exists(p) && fs::is_regular_file(p);
	}

	Password TestKeysPassword() {
		return Password(STORMBYTE_TEST_KEYS_PASSWORD);
	}

	const String kPlainText = "StormByte OpenSSL key interop test payload";

	std::span<const std::byte> Bytes(std::string_view s) {
		return { reinterpret_cast<const std::byte*>(s.data()), s.size() };
	}

	std::span<const std::byte> Bytes(const String& text) {
		return Bytes(static_cast<std::string_view>(text));
	}

	std::span<const std::byte> Bytes(const FIFO& f) {
		const auto& d = f.Data();
		return { d.data(), static_cast<size_t>(d.size()) };
	}

	bool WriteBytes(const fs::path& path, const Vector<unsigned char>& data) {
		std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
		if (!ofs)
			return false;
		if (!data.empty())
			ofs.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(static_cast<size_t>(data.size())));
		return static_cast<bool>(ofs);
	}

	bool WriteText(const fs::path& path, std::string_view text) {
		std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
		if (!ofs)
			return false;
		ofs.write(text.data(), static_cast<std::streamsize>(text.size()));
		return static_cast<bool>(ofs);
	}

	Vector<unsigned char> ReadAllBytes(const fs::path& path) {
		std::ifstream ifs(path, std::ios::binary);
		if (!ifs)
			return {};
		return Vector<unsigned char>(
			(std::istreambuf_iterator<char>(ifs)),
			std::istreambuf_iterator<char>()
		);
	}

	String ReadAllText(const fs::path& path) {
		const auto bytes = ReadAllBytes(path);
		if (bytes.empty())
			return {};
		return String(std::string_view(reinterpret_cast<const char*>(bytes.data()), static_cast<size_t>(bytes.size())));
	}

	int AssertLoadPair(std::string_view pubName, std::string_view privName,
			KeyPair::Generic::PointerType& out, KeyPair::Type expectedType, bool checkTypeStrict = true) {
		const auto pub = KeyFile(pubName);
		const auto priv = KeyFile(privName);
		ASSERT_TRUE(FileExists(pub));
		ASSERT_TRUE(FileExists(priv));
		out = KeyPair::Load(pub, priv);
		ASSERT_TRUE(static_cast<bool>(out));
		ASSERT_TRUE(out->HasPrivateKey());
		ASSERT_TRUE(!out->PublicKey().empty());
		if (checkTypeStrict)
			ASSERT_TRUE(out->Type() == expectedType);
		return 0;
	}

	template<typename K>
	KeyPair::Generic::PointerType PubOnly(const KeyPair::Generic::PointerType& kp) {
		return K::template MakePointer<K>(kp->PublicKey(), std::nullopt);
	}

	int EncryptRoundTripRsa(KeyPair::Generic::PointerType encKp,
			KeyPair::Generic::PointerType decKp, Crypter::Asymmetric::Strategy strategy,
			std::string_view text = kPlainText) {
		Crypter::RSA enc(encKp);
		Crypter::RSA dec(decKp);
		FIFO cipher;
		FIFO plain;
		ASSERT_TRUE(enc.Encrypt(Bytes(text), cipher, strategy));
		ASSERT_TRUE(dec.Decrypt(Bytes(cipher), plain));
		const String got = DeserializeString(plain.Data());
		// ASSERT_EQUAL goes through the harness C-string path (strcmp / c_str()).
		// Hybrid payloads are kPlainText + 4096 padding; on Ubuntu clang that
		// macro reports a false mismatch while String::operator== is exact.
		// Do not revert this to ASSERT_EQUAL.
		ASSERT_TRUE(static_cast<std::string_view>(got) == text);
		return 0;
	}

	int EncryptRoundTripEcc(KeyPair::Generic::PointerType encKp,
			KeyPair::Generic::PointerType decKp, Crypter::Asymmetric::Strategy strategy) {
		Crypter::ECC enc(encKp);
		Crypter::ECC dec(decKp);
		FIFO cipher;
		FIFO plain;
		ASSERT_TRUE(enc.Encrypt(Bytes(kPlainText), cipher, strategy));
		ASSERT_TRUE(dec.Decrypt(Bytes(cipher), plain));
		const String got = DeserializeString(plain.Data());
		ASSERT_TRUE(got == kPlainText);
		return 0;
	}

	template<typename SignerT, typename KeyT>
	int SignRoundTrip(KeyPair::Generic::PointerType signKp,
			KeyPair::Generic::PointerType verifyKp) {
		SignerT signer(signKp);
		SignerT verifier(PubOnly<KeyT>(verifyKp));
		FIFO signature;
		ASSERT_TRUE(signer.Sign(Bytes(kPlainText), signature));
		ASSERT_TRUE(verifier.Verify(Bytes(kPlainText), DeserializeString(signature.Data())));
		return 0;
	}
}

// ---------------------------------------------------------------------------
// RSA: Load → Encrypt/Decrypt → Sign/Verify
// ---------------------------------------------------------------------------
int test_openssl_rsa_encrypt_decrypt() {
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair("rsa_test.pub.pem", "rsa_test.priv.pem", kp, KeyPair::Type::RSA) != 0)
		return 1;
	Crypter::RSA crypter(kp);
	FIFO encrypted;
	ASSERT_TRUE(crypter.Encrypt(Bytes(kPlainText), encrypted, Crypter::Asymmetric::Strategy::Native));
	ASSERT_FALSE(encrypted.Empty());
	ASSERT_NOT_EQUAL(DeserializeString(encrypted.Data()), kPlainText);
	FIFO decrypted;
	ASSERT_TRUE(crypter.Decrypt(Bytes(encrypted), decrypted));
	ASSERT_EQUAL(DeserializeString(decrypted.Data()), kPlainText);
	RETURN_TEST(0);
}

int test_openssl_rsa_hybrid_encrypt_decrypt() {
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair("rsa_test.pub.pem", "rsa_test.priv.pem", kp, KeyPair::Type::RSA) != 0)
		return 1;
	return EncryptRoundTripRsa(kp, kp, Crypter::Asymmetric::Strategy::Hybrid,
		kPlainText + String(4096, 'A'));
}

int test_openssl_rsa_sign_verify() {
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair("rsa_test.pub.pem", "rsa_test.priv.pem", kp, KeyPair::Type::RSA) != 0)
		return 1;
	Signer::RSA signer(kp);
	FIFO signature;
	ASSERT_TRUE(signer.Sign(Bytes(kPlainText), signature));
	ASSERT_TRUE(!signature.Empty());
	const String sigStr = DeserializeString(signature.Data());
	ASSERT_TRUE(signer.Verify(Bytes(kPlainText), sigStr));
	ASSERT_FALSE(signer.Verify(Bytes(kPlainText + "X"), sigStr));
	RETURN_TEST(0);
}

int test_openssl_rsa_der_round_trip_use() {
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair("rsa_test.pub.der", "rsa_test.priv.der", kp, KeyPair::Type::RSA) != 0)
		return 1;
	return EncryptRoundTripRsa(kp, kp, Crypter::Asymmetric::Strategy::Native);
}

// ---------------------------------------------------------------------------
// DSA: Load → Sign/Verify
// ---------------------------------------------------------------------------
int test_openssl_dsa_sign_verify() {
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair("dsa_test.pub.pem", "dsa_test.priv.pem", kp, KeyPair::Type::DSA) != 0)
		return 1;
	Signer::DSA signer(kp);
	FIFO signature;
	ASSERT_TRUE(signer.Sign(Bytes(kPlainText), signature));
	ASSERT_TRUE(!signature.Empty());
	const String sigStr = DeserializeString(signature.Data());
	ASSERT_TRUE(signer.Verify(Bytes(kPlainText), sigStr));
	ASSERT_FALSE(signer.Verify(std::span<const std::byte>(reinterpret_cast<const std::byte*>("other"), 5), sigStr));
	RETURN_TEST(0);
}

// ---------------------------------------------------------------------------
// ECDSA: Load → Sign/Verify
// ---------------------------------------------------------------------------
int test_openssl_ecdsa_sign_verify() {
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair("ecdsa_test.pub.pem", "ecdsa_test.priv.pem", kp, KeyPair::Type::ECDSA, false) != 0)
		return 1;
	Signer::ECDSA signer(kp);
	FIFO signature;
	ASSERT_TRUE(signer.Sign(Bytes(kPlainText), signature));
	ASSERT_TRUE(!signature.Empty());
	ASSERT_TRUE(signer.Verify(Bytes(kPlainText), DeserializeString(signature.Data())));
	RETURN_TEST(0);
}

// ---------------------------------------------------------------------------
// ECC: Load → Encrypt/Decrypt
// ---------------------------------------------------------------------------
int test_openssl_ecc_encrypt_decrypt() {
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair("ecc_p256_test.pub.pem", "ecc_p256_test.priv.pem", kp, KeyPair::Type::ECC, false) != 0)
		return 1;
	return EncryptRoundTripEcc(kp, kp, Crypter::Asymmetric::Strategy::Native);
}

// ---------------------------------------------------------------------------
// Ed25519: Load → Sign/Verify
// ---------------------------------------------------------------------------
int test_openssl_ed25519_sign_verify() {
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair("ed25519_test.pub.pem", "ed25519_test.priv.pem", kp, KeyPair::Type::ED25519) != 0)
		return 1;
	Signer::ED25519 signer(kp);
	FIFO signature;
	ASSERT_TRUE(signer.Sign(Bytes(kPlainText), signature));
	ASSERT_TRUE(!signature.Empty());
	const String sigStr = DeserializeString(signature.Data());
	ASSERT_TRUE(signer.Verify(Bytes(kPlainText), sigStr));
	ASSERT_FALSE(signer.Verify(std::span<const std::byte>(reinterpret_cast<const std::byte*>("tampered"), 8), sigStr));
	RETURN_TEST(0);
}

int test_openssl_ed25519_der_sign_verify() {
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair("ed25519_test.pub.der", "ed25519_test.priv.der", kp, KeyPair::Type::ED25519) != 0)
		return 1;
	return SignRoundTrip<Signer::ED25519, KeyPair::ED25519>(kp, kp);
}

// ---------------------------------------------------------------------------
// ECDH / X25519: Load local + peer → Share
// ---------------------------------------------------------------------------
int test_openssl_ecdh_share() {
	{
		auto a = KeyPair::ECDH::Generate(256);
		auto b = KeyPair::ECDH::Generate(256);
		ASSERT_TRUE(static_cast<bool>(a));
		ASSERT_TRUE(static_cast<bool>(b));
		Secret::ECDH sa(a);
		Secret::ECDH sb(b);
		auto s1 = sa.Share(b->PublicKey());
		auto s2 = sb.Share(a->PublicKey());
		ASSERT_TRUE(s1.has_value());
		ASSERT_TRUE(s2.has_value());
		ASSERT_TRUE(s1 == s2);
	}

	auto localLoaded = KeyPair::Load(KeyFile("ecdh_test.pub.pem"), KeyFile("ecdh_test.priv.pem"));
	auto peerLoaded = KeyPair::Load(KeyFile("ecdh_peer_test.pub.pem"), KeyFile("ecdh_peer_test.priv.pem"));
	ASSERT_TRUE(static_cast<bool>(localLoaded));
	ASSERT_TRUE(static_cast<bool>(peerLoaded));
	ASSERT_TRUE(localLoaded->HasPrivateKey());
	ASSERT_TRUE(peerLoaded->HasPrivateKey());
	auto local = KeyPair::ECDH::MakePointer<KeyPair::ECDH>(localLoaded->PublicKey(), localLoaded->PrivateKey());
	auto peer = KeyPair::ECDH::MakePointer<KeyPair::ECDH>(peerLoaded->PublicKey(), peerLoaded->PrivateKey());
	Secret::ECDH ecdhLocal(local);
	Secret::ECDH ecdhPeer(peer);
	auto s1 = ecdhLocal.Share(peer->PublicKey());
	auto s2 = ecdhPeer.Share(local->PublicKey());
	ASSERT_TRUE(s1.has_value());
	ASSERT_TRUE(s2.has_value());
	ASSERT_TRUE(s1 == s2);
	ASSERT_TRUE(!s1->Empty());
	RETURN_TEST(0);
}

int test_openssl_x25519_share() {
	auto localLoaded = KeyPair::Load(KeyFile("x25519_test.pub.pem"), KeyFile("x25519_test.priv.pem"));
	auto peerLoaded = KeyPair::Load(KeyFile("x25519_peer_test.pub.pem"), KeyFile("x25519_peer_test.priv.pem"));
	ASSERT_TRUE(static_cast<bool>(localLoaded));
	ASSERT_TRUE(static_cast<bool>(peerLoaded));
	auto local = KeyPair::X25519::MakePointer<KeyPair::X25519>(localLoaded->PublicKey(), localLoaded->PrivateKey());
	auto peer = KeyPair::X25519::MakePointer<KeyPair::X25519>(peerLoaded->PublicKey(), peerLoaded->PrivateKey());
	Secret::X25519 xLocal(local);
	Secret::X25519 xPeer(peer);
	auto s1 = xLocal.Share(peer->PublicKey());
	auto s2 = xPeer.Share(local->PublicKey());
	ASSERT_TRUE(s1.has_value());
	ASSERT_TRUE(s2.has_value());
	ASSERT_TRUE(s1 == s2);
	ASSERT_TRUE(!s1->Empty());
	RETURN_TEST(0);
}

// ---------------------------------------------------------------------------
// Single-file load still usable
// ---------------------------------------------------------------------------
int test_openssl_rsa_private_only_then_encrypt() {
	const auto priv = KeyFile("rsa_test.priv.pem");
	ASSERT_TRUE(FileExists(priv));
	auto kp = KeyPair::Load(priv);
	ASSERT_TRUE(static_cast<bool>(kp));
	ASSERT_TRUE(kp->HasPrivateKey());
	ASSERT_TRUE(!kp->PublicKey().empty());
	return EncryptRoundTripRsa(kp, kp, Crypter::Asymmetric::Strategy::Native);
}

// ---------------------------------------------------------------------------
// Library Save → Load → still works
// ---------------------------------------------------------------------------
int test_library_rsa_save_load_still_encrypts() {
	auto original = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(original));
	const fs::path outDir = KeysDir() / "roundtrip";
	fs::create_directories(outDir);
	ASSERT_TRUE(original->Save(outDir, "lib_rsa", KeyPair::StorageFormat::PEM));
	auto loaded = KeyPair::Load(outDir / "lib_rsa.pub.pem", outDir / "lib_rsa.pem");
	ASSERT_TRUE(static_cast<bool>(loaded));
	return EncryptRoundTripRsa(loaded, loaded, Crypter::Asymmetric::Strategy::Native);
}

// ---------------------------------------------------------------------------
// Encrypted PEM without password must fail
// ---------------------------------------------------------------------------
int test_openssl_encrypted_private_without_password_fails() {
	const auto enc = KeyFile("rsa_test.priv.enc.pem");
	ASSERT_TRUE(FileExists(enc));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(enc)));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(KeyFile("rsa_test.pub.pem"), enc)));
	RETURN_TEST(0);
}

// ---------------------------------------------------------------------------
// Private-only Load: derived public must work as a standalone public key
// ---------------------------------------------------------------------------
int test_openssl_rsa_private_only_derives_public() {
	const auto privPath = KeyFile("rsa_test.priv.pem");
	ASSERT_TRUE(FileExists(privPath));
	auto privKp = KeyPair::Load(privPath);
	ASSERT_TRUE(static_cast<bool>(privKp));
	ASSERT_TRUE(privKp->HasPrivateKey());
	ASSERT_TRUE(!privKp->PublicKey().empty());
	auto pubKp = PubOnly<KeyPair::RSA>(privKp);
	ASSERT_FALSE(pubKp->HasPrivateKey());
	return EncryptRoundTripRsa(pubKp, privKp, Crypter::Asymmetric::Strategy::Native);
}

int test_openssl_dsa_private_only_derives_public() {
	const auto privPath = KeyFile("dsa_test.priv.pem");
	ASSERT_TRUE(FileExists(privPath));
	auto privKp = KeyPair::Load(privPath);
	ASSERT_TRUE(static_cast<bool>(privKp));
	ASSERT_TRUE(privKp->HasPrivateKey());
	ASSERT_TRUE(!privKp->PublicKey().empty());
	auto pubKp = PubOnly<KeyPair::DSA>(privKp);
	ASSERT_FALSE(pubKp->HasPrivateKey());
	return SignRoundTrip<Signer::DSA, KeyPair::DSA>(privKp, pubKp);
}

int test_openssl_ecdsa_private_only_derives_public() {
	const auto privPath = KeyFile("ecdsa_test.priv.pem");
	ASSERT_TRUE(FileExists(privPath));
	auto privKp = KeyPair::Load(privPath);
	ASSERT_TRUE(static_cast<bool>(privKp));
	ASSERT_TRUE(privKp->HasPrivateKey());
	ASSERT_TRUE(!privKp->PublicKey().empty());
	auto pubKp = PubOnly<KeyPair::ECDSA>(privKp);
	ASSERT_FALSE(pubKp->HasPrivateKey());
	return SignRoundTrip<Signer::ECDSA, KeyPair::ECDSA>(privKp, pubKp);
}

int test_openssl_ecc_private_only_derives_public() {
	const auto privPath = KeyFile("ecc_p256_test.priv.pem");
	ASSERT_TRUE(FileExists(privPath));
	auto privKp = KeyPair::Load(privPath);
	ASSERT_TRUE(static_cast<bool>(privKp));
	ASSERT_TRUE(privKp->HasPrivateKey());
	ASSERT_TRUE(!privKp->PublicKey().empty());
	auto pubKp = PubOnly<KeyPair::ECC>(privKp);
	ASSERT_FALSE(pubKp->HasPrivateKey());
	return EncryptRoundTripEcc(pubKp, privKp, Crypter::Asymmetric::Strategy::Native);
}

int test_openssl_ed25519_private_only_derives_public() {
	const auto privPath = KeyFile("ed25519_test.priv.pem");
	ASSERT_TRUE(FileExists(privPath));
	auto privKp = KeyPair::Load(privPath);
	ASSERT_TRUE(static_cast<bool>(privKp));
	ASSERT_TRUE(privKp->HasPrivateKey());
	ASSERT_TRUE(!privKp->PublicKey().empty());
	auto pubKp = PubOnly<KeyPair::ED25519>(privKp);
	ASSERT_FALSE(pubKp->HasPrivateKey());
	return SignRoundTrip<Signer::ED25519, KeyPair::ED25519>(privKp, pubKp);
}

int test_openssl_ecdh_private_only_derives_public() {
	const auto privPath = KeyFile("ecdh_test.priv.pem");
	const auto peerPriv = KeyFile("ecdh_peer_test.priv.pem");
	ASSERT_TRUE(FileExists(privPath));
	ASSERT_TRUE(FileExists(peerPriv));
	auto localPriv = KeyPair::Load(privPath);
	auto peerPrivKp = KeyPair::Load(peerPriv);
	ASSERT_TRUE(static_cast<bool>(localPriv));
	ASSERT_TRUE(static_cast<bool>(peerPrivKp));
	ASSERT_TRUE(!localPriv->PublicKey().empty());
	ASSERT_TRUE(!peerPrivKp->PublicKey().empty());
	auto peerPubOnly = PubOnly<KeyPair::ECDH>(peerPrivKp);
	ASSERT_FALSE(peerPubOnly->HasPrivateKey());
	auto local = KeyPair::ECDH::MakePointer<KeyPair::ECDH>(localPriv->PublicKey(), localPriv->PrivateKey());
	auto peer = KeyPair::ECDH::MakePointer<KeyPair::ECDH>(peerPrivKp->PublicKey(), peerPrivKp->PrivateKey());
	Secret::ECDH a(local, 256);
	Secret::ECDH b(peer, 256);
	auto s1 = a.Share(peerPubOnly->PublicKey());
	auto s2 = b.Share(local->PublicKey());
	ASSERT_TRUE(s1.has_value());
	ASSERT_TRUE(s2.has_value());
	ASSERT_TRUE(s1 == s2);
	RETURN_TEST(0);
}

int test_openssl_x25519_private_only_derives_public() {
	const auto privPath = KeyFile("x25519_test.priv.pem");
	const auto peerPriv = KeyFile("x25519_peer_test.priv.pem");
	ASSERT_TRUE(FileExists(privPath));
	ASSERT_TRUE(FileExists(peerPriv));
	auto localPriv = KeyPair::Load(privPath);
	auto peerPrivKp = KeyPair::Load(peerPriv);
	ASSERT_TRUE(static_cast<bool>(localPriv));
	ASSERT_TRUE(static_cast<bool>(peerPrivKp));
	ASSERT_TRUE(!localPriv->PublicKey().empty());
	ASSERT_TRUE(!peerPrivKp->PublicKey().empty());
	auto peerPubOnly = PubOnly<KeyPair::X25519>(peerPrivKp);
	ASSERT_FALSE(peerPubOnly->HasPrivateKey());
	Secret::X25519 xLocal(localPriv);
	Secret::X25519 xPeer(peerPrivKp);
	auto s1 = xLocal.Share(peerPubOnly->PublicKey());
	auto s2 = xPeer.Share(localPriv->PublicKey());
	ASSERT_TRUE(s1.has_value());
	ASSERT_TRUE(s2.has_value());
	ASSERT_TRUE(s1 == s2);
	RETURN_TEST(0);
}

// ---------------------------------------------------------------------------
// Encrypted private key Load (password) → usable for crypto ops
// ---------------------------------------------------------------------------
int test_openssl_rsa_encrypted_load_encrypt_decrypt() {
	const auto enc = KeyFile("rsa_test.priv.enc.pem");
	const auto pub = KeyFile("rsa_test.pub.pem");
	ASSERT_TRUE(FileExists(enc));
	ASSERT_TRUE(FileExists(pub));
	auto kp = KeyPair::Load(pub, enc, TestKeysPassword());
	ASSERT_TRUE(static_cast<bool>(kp));
	ASSERT_TRUE(kp->HasPrivateKey());
	ASSERT_TRUE(!kp->PublicKey().empty());
	return EncryptRoundTripRsa(PubOnly<KeyPair::RSA>(kp), kp, Crypter::Asymmetric::Strategy::Native);
}

int test_openssl_rsa_encrypted_load_private_only() {
	const auto enc = KeyFile("rsa_test.priv.enc.pem");
	ASSERT_TRUE(FileExists(enc));
	auto kp = KeyPair::Load(enc, TestKeysPassword());
	ASSERT_TRUE(static_cast<bool>(kp));
	ASSERT_TRUE(kp->HasPrivateKey());
	ASSERT_TRUE(!kp->PublicKey().empty());
	return EncryptRoundTripRsa(PubOnly<KeyPair::RSA>(kp), kp, Crypter::Asymmetric::Strategy::Native);
}

int test_openssl_rsa_encrypted_wrong_password_fails() {
	const auto enc = KeyFile("rsa_test.priv.enc.pem");
	ASSERT_TRUE(FileExists(enc));
	Password wrong("DefinitelyNotTheRightPassphrase");
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(enc, wrong)));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(KeyFile("rsa_test.pub.pem"), enc, wrong)));
	RETURN_TEST(0);
}

int test_openssl_rsa_encrypted_sign_verify() {
	auto kp = KeyPair::Load(KeyFile("rsa_test.priv.enc.pem"), TestKeysPassword());
	ASSERT_TRUE(static_cast<bool>(kp));
	return SignRoundTrip<Signer::RSA, KeyPair::RSA>(kp, kp);
}

int test_openssl_dsa_encrypted_sign_verify() {
	auto kp = KeyPair::Load(KeyFile("dsa_test.priv.enc.pem"), TestKeysPassword());
	ASSERT_TRUE(static_cast<bool>(kp));
	return SignRoundTrip<Signer::DSA, KeyPair::DSA>(kp, kp);
}

int test_openssl_ecdsa_encrypted_sign_verify() {
	auto kp = KeyPair::Load(KeyFile("ecdsa_test.priv.enc.pem"), TestKeysPassword());
	ASSERT_TRUE(static_cast<bool>(kp));
	return SignRoundTrip<Signer::ECDSA, KeyPair::ECDSA>(kp, kp);
}

int test_openssl_ecc_encrypted_encrypt_decrypt() {
	auto kp = KeyPair::Load(KeyFile("ecc_p256_test.priv.enc.pem"), TestKeysPassword());
	ASSERT_TRUE(static_cast<bool>(kp));
	return EncryptRoundTripEcc(PubOnly<KeyPair::ECC>(kp), kp, Crypter::Asymmetric::Strategy::Native);
}

int test_openssl_ed25519_encrypted_sign_verify() {
	auto kp = KeyPair::Load(KeyFile("ed25519_test.priv.enc.pem"), TestKeysPassword());
	ASSERT_TRUE(static_cast<bool>(kp));
	return SignRoundTrip<Signer::ED25519, KeyPair::ED25519>(kp, kp);
}

int test_openssl_ecdh_encrypted_share() {
	auto local = KeyPair::Load(KeyFile("ecdh_test.priv.enc.pem"), TestKeysPassword());
	auto peer = KeyPair::Load(KeyFile("ecdh_peer_test.priv.pem"));
	ASSERT_TRUE(static_cast<bool>(local));
	ASSERT_TRUE(static_cast<bool>(peer));
	auto localKp = KeyPair::ECDH::MakePointer<KeyPair::ECDH>(local->PublicKey(), local->PrivateKey());
	auto peerKp = KeyPair::ECDH::MakePointer<KeyPair::ECDH>(peer->PublicKey(), peer->PrivateKey());
	auto peerPub = PubOnly<KeyPair::ECDH>(peer);
	Secret::ECDH a(localKp, 256);
	Secret::ECDH b(peerKp, 256);
	auto s1 = a.Share(peerPub->PublicKey());
	auto s2 = b.Share(localKp->PublicKey());
	ASSERT_TRUE(s1.has_value());
	ASSERT_TRUE(s2.has_value());
	ASSERT_TRUE(s1 == s2);
	RETURN_TEST(0);
}

int test_openssl_x25519_encrypted_share() {
	auto local = KeyPair::Load(KeyFile("x25519_test.priv.enc.pem"), TestKeysPassword());
	auto peer = KeyPair::Load(KeyFile("x25519_peer_test.priv.pem"));
	ASSERT_TRUE(static_cast<bool>(local));
	ASSERT_TRUE(static_cast<bool>(peer));
	auto peerPub = PubOnly<KeyPair::X25519>(peer);
	Secret::X25519 xLocal(local);
	Secret::X25519 xPeer(peer);
	auto s1 = xLocal.Share(peerPub->PublicKey());
	auto s2 = xPeer.Share(local->PublicKey());
	ASSERT_TRUE(s1.has_value());
	ASSERT_TRUE(s2.has_value());
	ASSERT_TRUE(s1 == s2);
	RETURN_TEST(0);
}

// ---------------------------------------------------------------------------
// Truncated / invalid OpenSSL private keys must not load
// ---------------------------------------------------------------------------
int test_openssl_rsa_truncated_private_fails() {
	ASSERT_TRUE(FileExists(KeyFile("rsa_test.priv.truncated.pem")));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(KeyFile("rsa_test.priv.truncated.pem"))));
	RETURN_TEST(0);
}

int test_openssl_dsa_truncated_private_fails() {
	ASSERT_TRUE(FileExists(KeyFile("dsa_test.priv.truncated.pem")));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(KeyFile("dsa_test.priv.truncated.pem"))));
	RETURN_TEST(0);
}

int test_openssl_ecc_truncated_private_fails() {
	ASSERT_TRUE(FileExists(KeyFile("ecc_p256_test.priv.truncated.pem")));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(KeyFile("ecc_p256_test.priv.truncated.pem"))));
	RETURN_TEST(0);
}

int test_openssl_ecdsa_truncated_private_fails() {
	ASSERT_TRUE(FileExists(KeyFile("ecdsa_test.priv.truncated.pem")));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(KeyFile("ecdsa_test.priv.truncated.pem"))));
	RETURN_TEST(0);
}

int test_openssl_ecdh_truncated_private_fails() {
	ASSERT_TRUE(FileExists(KeyFile("ecdh_test.priv.truncated.pem")));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(KeyFile("ecdh_test.priv.truncated.pem"))));
	RETURN_TEST(0);
}

int test_openssl_ed25519_truncated_private_fails() {
	ASSERT_TRUE(FileExists(KeyFile("ed25519_test.priv.truncated.pem")));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(KeyFile("ed25519_test.priv.truncated.pem"))));
	RETURN_TEST(0);
}

int test_openssl_x25519_truncated_private_fails() {
	ASSERT_TRUE(FileExists(KeyFile("x25519_test.priv.truncated.pem")));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(KeyFile("x25519_test.priv.truncated.pem"))));
	RETURN_TEST(0);
}

// ---------------------------------------------------------------------------
// OpenSSL edge cases
// ---------------------------------------------------------------------------
int test_openssl_edge_mismatched_pub_priv_fail() {
	auto kp = KeyPair::Load(KeyFile("rsa_test.pub.pem"), KeyFile("dsa_test.priv.pem"));
	ASSERT_FALSE(static_cast<bool>(kp));
	RETURN_TEST(0);
}

int test_openssl_edge_public_only_usable() {
	auto pubOnly = KeyPair::Load(KeyFile("rsa_test.pub.pem"));
	ASSERT_TRUE(static_cast<bool>(pubOnly));
	ASSERT_FALSE(pubOnly->HasPrivateKey());
	auto full = KeyPair::Load(KeyFile("rsa_test.pub.pem"), KeyFile("rsa_test.priv.pem"));
	ASSERT_TRUE(static_cast<bool>(full));
	ASSERT_TRUE(full->HasPrivateKey());
	return EncryptRoundTripRsa(pubOnly, full, Crypter::Asymmetric::Strategy::Native);
}

int test_openssl_edge_concatenated_pem_round_trip() {
	const String priv = ReadAllText(KeyFile("rsa_test.priv.pem"));
	const String pub = ReadAllText(KeyFile("rsa_test.pub.pem"));
	ASSERT_FALSE(priv.empty() || pub.empty());
	const fs::path combined = KeysDir() / "rsa_test.combined.pem";
	ASSERT_TRUE(WriteText(combined, priv + pub));
	auto kp = KeyPair::Load(combined);
	ASSERT_TRUE(static_cast<bool>(kp));
	ASSERT_TRUE(kp->HasPrivateKey());
	return EncryptRoundTripRsa(kp, kp, Crypter::Asymmetric::Strategy::Native);
}

int test_openssl_edge_truncated_encrypted_private_fails() {
	auto bytes = ReadAllBytes(KeyFile("rsa_test.priv.enc.pem"));
	ASSERT_FALSE(bytes.empty());
	bytes.resize(std::max<size_t>(1, bytes.size() / 2));
	const fs::path truncated = KeysDir() / "rsa_test.priv.enc.truncated.pem";
	ASSERT_TRUE(WriteBytes(truncated, bytes));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(truncated, TestKeysPassword())));
	RETURN_TEST(0);
}

int test_openssl_edge_empty_password_on_encrypted_fails() {
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(KeyFile("rsa_test.priv.enc.pem"), Password(""))));
	RETURN_TEST(0);
}

int test_openssl_edge_password_on_plain_private_still_loads() {
	auto kp = KeyPair::Load(KeyFile("rsa_test.priv.pem"), TestKeysPassword());
	ASSERT_TRUE(static_cast<bool>(kp));
	ASSERT_TRUE(kp->HasPrivateKey());
	return EncryptRoundTripRsa(kp, kp, Crypter::Asymmetric::Strategy::Native);
}

int test_openssl_edge_swapped_paths_fail() {
	auto kp = KeyPair::Load(KeyFile("rsa_test.priv.pem"), KeyFile("rsa_test.pub.pem"));
	ASSERT_FALSE(static_cast<bool>(kp));
	RETURN_TEST(0);
}

int test_openssl_edge_load_then_library_save_reload() {
	auto original = KeyPair::Load(KeyFile("rsa_test.pub.pem"), KeyFile("rsa_test.priv.pem"));
	ASSERT_TRUE(static_cast<bool>(original));
	const fs::path outDir = KeysDir() / "edge_resave";
	fs::create_directories(outDir);
	ASSERT_TRUE(original->Save(outDir, "rsa_resave", KeyPair::StorageFormat::PEM));
	auto reloaded = KeyPair::Load(outDir / "rsa_resave.pub.pem", outDir / "rsa_resave.pem");
	ASSERT_TRUE(static_cast<bool>(reloaded));
	return EncryptRoundTripRsa(reloaded, reloaded, Crypter::Asymmetric::Strategy::Native);
}

// ---------------------------------------------------------------------------
// PKCS#1 / traditional private key Load
// ---------------------------------------------------------------------------
int test_openssl_rsa_pkcs1_der_encrypt_decrypt() {
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair("rsa_test.pub.der", "rsa_test.priv.pkcs1.der", kp, KeyPair::Type::RSA) != 0)
		return 1;
	return EncryptRoundTripRsa(kp, kp, Crypter::Asymmetric::Strategy::Native);
}

int test_openssl_rsa_pkcs1_pem_encrypt_decrypt() {
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair("rsa_test.pub.pem", "rsa_test.priv.pkcs1.pem", kp, KeyPair::Type::RSA) != 0)
		return 1;
	return EncryptRoundTripRsa(kp, kp, Crypter::Asymmetric::Strategy::Native);
}

int test_openssl_rsa_pkcs1_der_sign_verify() {
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair("rsa_test.pub.der", "rsa_test.priv.pkcs1.der", kp, KeyPair::Type::RSA) != 0)
		return 1;
	return SignRoundTrip<Signer::RSA, KeyPair::RSA>(kp, kp);
}

int test_openssl_ecc_sec1_der_encrypt_decrypt() {
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair("ecc_p256_test.pub.der", "ecc_p256_test.priv.sec1.der", kp, KeyPair::Type::ECC, false) != 0)
		return 1;
	ASSERT_TRUE(kp->HasPrivateKey());
	return EncryptRoundTripEcc(kp, kp, Crypter::Asymmetric::Strategy::Hybrid);
}

int test_openssl_ecdsa_sec1_der_sign_verify() {
	KeyPair::Generic::PointerType kp;
	if (AssertLoadPair("ecdsa_test.pub.der", "ecdsa_test.priv.sec1.der", kp, KeyPair::Type::ECDSA, false) != 0)
		return 1;
	return SignRoundTrip<Signer::ECDSA, KeyPair::ECDSA>(kp, kp);
}

int test_openssl_ecdh_sec1_der_share() {
	KeyPair::Generic::PointerType local;
	if (AssertLoadPair("ecdh_test.pub.der", "ecdh_test.priv.sec1.der", local, KeyPair::Type::ECDH, false) != 0)
		return 1;
	auto peerFull = KeyPair::Load(KeyFile("ecdh_peer_test.pub.der"), KeyFile("ecdh_peer_test.priv.der"));
	ASSERT_TRUE(static_cast<bool>(peerFull));
	Secret::ECDH a(local);
	Secret::ECDH peerSide(peerFull);
	auto s1 = a.Share(peerFull->PublicKey());
	auto s2 = peerSide.Share(local->PublicKey());
	ASSERT_TRUE(s1.has_value());
	ASSERT_TRUE(s2.has_value());
	ASSERT_TRUE(s1 == s2);
	RETURN_TEST(0);
}

int main() {
	int result = 0;

	// ---------------------------------------------------------------------------
	// RSA: Load → Encrypt/Decrypt → Sign/Verify
	// ---------------------------------------------------------------------------
	result += test_openssl_rsa_encrypt_decrypt();
	result += test_openssl_rsa_hybrid_encrypt_decrypt();
	result += test_openssl_rsa_sign_verify();
	result += test_openssl_rsa_der_round_trip_use();
	result += test_openssl_rsa_private_only_then_encrypt();

	// ---------------------------------------------------------------------------
	// DSA / ECDSA / ECC / Ed25519
	// ---------------------------------------------------------------------------
	result += test_openssl_dsa_sign_verify();
	result += test_openssl_ecdsa_sign_verify();
	result += test_openssl_ecc_encrypt_decrypt();
	result += test_openssl_ed25519_sign_verify();
	result += test_openssl_ed25519_der_sign_verify();

	// ---------------------------------------------------------------------------
	// ECDH / X25519
	// ---------------------------------------------------------------------------
	result += test_openssl_ecdh_share();
	result += test_openssl_x25519_share();
	result += test_library_rsa_save_load_still_encrypts();
	result += test_openssl_encrypted_private_without_password_fails();

	// ---------------------------------------------------------------------------
	// Private-only Load: derived public
	// ---------------------------------------------------------------------------
	result += test_openssl_rsa_private_only_derives_public();
	result += test_openssl_dsa_private_only_derives_public();
	result += test_openssl_ecdsa_private_only_derives_public();
	result += test_openssl_ecc_private_only_derives_public();
	result += test_openssl_ed25519_private_only_derives_public();
	result += test_openssl_ecdh_private_only_derives_public();
	result += test_openssl_x25519_private_only_derives_public();

	// ---------------------------------------------------------------------------
	// Encrypted private key Load
	// ---------------------------------------------------------------------------
	result += test_openssl_rsa_encrypted_load_encrypt_decrypt();
	result += test_openssl_rsa_encrypted_load_private_only();
	result += test_openssl_rsa_encrypted_wrong_password_fails();
	result += test_openssl_rsa_encrypted_sign_verify();
	result += test_openssl_dsa_encrypted_sign_verify();
	result += test_openssl_ecdsa_encrypted_sign_verify();
	result += test_openssl_ecc_encrypted_encrypt_decrypt();
	result += test_openssl_ed25519_encrypted_sign_verify();
	result += test_openssl_ecdh_encrypted_share();
	result += test_openssl_x25519_encrypted_share();

	// ---------------------------------------------------------------------------
	// Truncated / invalid OpenSSL private keys
	// ---------------------------------------------------------------------------
	result += test_openssl_rsa_truncated_private_fails();
	result += test_openssl_dsa_truncated_private_fails();
	result += test_openssl_ecc_truncated_private_fails();
	result += test_openssl_ecdsa_truncated_private_fails();
	result += test_openssl_ecdh_truncated_private_fails();
	result += test_openssl_ed25519_truncated_private_fails();
	result += test_openssl_x25519_truncated_private_fails();

	// ---------------------------------------------------------------------------
	// OpenSSL edge cases
	// ---------------------------------------------------------------------------
	result += test_openssl_edge_mismatched_pub_priv_fail();
	result += test_openssl_edge_public_only_usable();
	result += test_openssl_edge_concatenated_pem_round_trip();
	result += test_openssl_edge_truncated_encrypted_private_fails();
	result += test_openssl_edge_empty_password_on_encrypted_fails();
	result += test_openssl_edge_password_on_plain_private_still_loads();
	result += test_openssl_edge_swapped_paths_fail();
	result += test_openssl_edge_load_then_library_save_reload();

	// ---------------------------------------------------------------------------
	// PKCS#1 / traditional private key Load
	// ---------------------------------------------------------------------------
	result += test_openssl_rsa_pkcs1_der_encrypt_decrypt();
	result += test_openssl_rsa_pkcs1_pem_encrypt_decrypt();
	result += test_openssl_rsa_pkcs1_der_sign_verify();
	result += test_openssl_ecc_sec1_der_encrypt_decrypt();
	result += test_openssl_ecdsa_sec1_der_sign_verify();
	result += test_openssl_ecdh_sec1_der_share();

	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}

	return result;
}
