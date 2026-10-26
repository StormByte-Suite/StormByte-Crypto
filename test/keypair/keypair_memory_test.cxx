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
 */

#include "helpers.hxx"

#include <StormByte/buffer/fifo.hxx>
#include <StormByte/crypto/crypter/asymmetric/rsa.hxx>
#include <StormByte/crypto/keypair/ecdh.hxx>
#include <StormByte/crypto/keypair/ecdsa.hxx>
#include <StormByte/crypto/keypair/ed25519.hxx>
#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/keypair/rsa.hxx>
#include <StormByte/crypto/keypair/x25519.hxx>
#include <StormByte/crypto/secret/ecdh.hxx>
#include <StormByte/crypto/secret/x25519.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/crypto/signer/ecdsa.hxx>
#include <StormByte/crypto/signer/ed25519.hxx>
#include <StormByte/safe/secure_binary.hxx>
#include <StormByte/test_handlers.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <string_view>

using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;
using StormByte::Buffer::FIFO;
using StormByte::Safe::SecureBinary;
namespace fs = std::filesystem;

#ifndef STORMBYTE_TEST_KEYS_DIR
#	error "STORMBYTE_TEST_KEYS_DIR must be defined by CMake"
#endif
#ifndef STORMBYTE_TEST_KEYS_PASSWORD
#	error "STORMBYTE_TEST_KEYS_PASSWORD must be defined by CMake"
#endif

namespace {
	constexpr std::string_view kPlain = "StormByte in-memory Save/Load payload";

	fs::path KeysDir() {
		return fs::path(STORMBYTE_TEST_KEYS_DIR);
	}

	Password TestPassword() {
		return Password(STORMBYTE_TEST_KEYS_PASSWORD);
	}

	std::span<const std::byte> Bytes(std::string_view s) {
		return { reinterpret_cast<const std::byte*>(s.data()), s.size() };
	}

	SecureBinary ReadFile(const fs::path& path) {
		std::ifstream in(path, std::ios::binary);
		const std::string text{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
		return SecureBinary(std::string_view(text));
	}

	bool StartsWith(const SecureBinary& data, std::string_view prefix) {
		const auto span = data.span();
		return span.size() >= prefix.size()
			&& std::string_view(reinterpret_cast<const char*>(span.data()), prefix.size()) == prefix;
	}

	template<typename SignerT, typename KeyT>
	int SignVerify(const KeyPair::Generic::PointerType& signKp, const KeyPair::Generic::PointerType& verifyKp) {
		SignerT signer(KeyT::template MakePointer<KeyT>(signKp->PublicKey(), signKp->PrivateKey()));
		SignerT verifier(KeyT::template MakePointer<KeyT>(verifyKp->PublicKey(), std::nullopt));
		FIFO signature;
		ASSERT_TRUE(signer.Sign(Bytes(kPlain), signature));
		ASSERT_TRUE(verifier.Verify(Bytes(kPlain), DeserializeString(signature.Data())));
		return 0;
	}
}

int test_memory_rsa_pem_roundtrip() {
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(kp));
	const SecureBinary pub = kp->SavePublic();
	const auto priv = kp->SavePrivate();
	ASSERT_TRUE(StartsWith(pub, "-----BEGIN PUBLIC KEY-----"));
	ASSERT_TRUE(StartsWith(priv, "-----BEGIN PRIVATE KEY-----"));
	auto loaded = KeyPair::Load(pub, priv);
	ASSERT_TRUE(static_cast<bool>(loaded));
	ASSERT_TRUE(loaded->Type() == KeyPair::Type::RSA);
	ASSERT_EQUAL(loaded->PublicKey(), kp->PublicKey());
	ASSERT_TRUE(loaded->PrivateKey().has_value());

	Crypter::RSA enc(KeyPair::RSA::MakePointer<KeyPair::RSA>(kp->PublicKey(), std::nullopt));
	Crypter::RSA dec(loaded);
	FIFO cipher, plain;
	ASSERT_TRUE(enc.Encrypt(Bytes(kPlain), cipher, Crypter::Asymmetric::Strategy::Native));
	ASSERT_TRUE(dec.Decrypt(cipher.Data().span(), plain));
	ASSERT_TRUE(static_cast<std::string_view>(DeserializeString(plain.Data())) == kPlain);
	return 0;
}

int test_memory_ecdsa_p384_der_roundtrip() {
	auto kp = KeyPair::ECDSA::Generate(384);
	ASSERT_TRUE(static_cast<bool>(kp));
	auto loaded = KeyPair::Load(kp->SavePublic(KeyPair::StorageFormat::DER), kp->SavePrivate(KeyPair::StorageFormat::DER));
	ASSERT_TRUE(static_cast<bool>(loaded));
	ASSERT_EQUAL(loaded->PublicKey(), kp->PublicKey());
	return SignVerify<Signer::ECDSA, KeyPair::ECDSA>(loaded, kp);
}

int test_memory_public_only_verifies() {
	auto kp = KeyPair::ECDSA::Generate(384);
	ASSERT_TRUE(static_cast<bool>(kp));
	auto pub = KeyPair::Load(kp->SavePublic());
	ASSERT_TRUE(static_cast<bool>(pub));
	ASSERT_FALSE(pub->PrivateKey().has_value());
	return SignVerify<Signer::ECDSA, KeyPair::ECDSA>(kp, pub);
}

int test_memory_private_only_derives_public() {
	auto kp = KeyPair::ED25519::Generate(256);
	ASSERT_TRUE(static_cast<bool>(kp));
	auto loaded = KeyPair::Load(kp->SavePrivate());
	ASSERT_TRUE(static_cast<bool>(loaded));
	ASSERT_EQUAL(loaded->PublicKey(), kp->PublicKey());
	return SignVerify<Signer::ED25519, KeyPair::ED25519>(loaded, kp);
}

int test_memory_concatenated_pem_loads_pair() {
	auto kp = KeyPair::ED25519::Generate(256);
	ASSERT_TRUE(static_cast<bool>(kp));
	SecureBinary both = kp->SavePublic();
	both += kp->SavePrivate();
	auto loaded = KeyPair::Load(both);
	ASSERT_TRUE(static_cast<bool>(loaded));
	ASSERT_EQUAL(loaded->PublicKey(), kp->PublicKey());
	ASSERT_TRUE(loaded->PrivateKey().has_value());
	return 0;
}

int test_memory_encrypted_private_roundtrip() {
	auto kp = KeyPair::ECDSA::Generate(384);
	ASSERT_TRUE(static_cast<bool>(kp));
	const auto encrypted = kp->SavePrivate(TestPassword());
	ASSERT_TRUE(StartsWith(encrypted, "-----BEGIN ENCRYPTED PRIVATE KEY-----"));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(encrypted)));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(encrypted, Password("wrong password"))));
	auto loaded = KeyPair::Load(encrypted, TestPassword());
	ASSERT_TRUE(static_cast<bool>(loaded));
	ASSERT_EQUAL(loaded->PublicKey(), kp->PublicKey());
	auto pair = KeyPair::Load(kp->SavePublic(), encrypted, TestPassword());
	ASSERT_TRUE(static_cast<bool>(pair));
	return SignVerify<Signer::ECDSA, KeyPair::ECDSA>(pair, kp);
}

int test_memory_encrypted_der_pair_roundtrip() {
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(kp));
	const auto encrypted = kp->SavePrivate(TestPassword(), KeyPair::StorageFormat::DER);
	ASSERT_FALSE(encrypted.empty());
	auto loaded = KeyPair::Load(kp->SavePublic(KeyPair::StorageFormat::DER), encrypted, TestPassword());
	ASSERT_TRUE(static_cast<bool>(loaded));
	ASSERT_EQUAL(loaded->PublicKey(), kp->PublicKey());
	return 0;
}

int test_memory_ecdh_p384_shared_secret() {
	auto a = KeyPair::ECDH::Generate(384);
	auto b = KeyPair::ECDH::Generate(384);
	ASSERT_TRUE(static_cast<bool>(a));
	ASSERT_TRUE(static_cast<bool>(b));
	auto la = KeyPair::Load(a->SavePublic(), a->SavePrivate());
	auto lb = KeyPair::Load(b->SavePublic());
	ASSERT_TRUE(static_cast<bool>(la));
	ASSERT_TRUE(static_cast<bool>(lb));
	Secret::ECDH sa(KeyPair::ECDH::MakePointer<KeyPair::ECDH>(la->PublicKey(), la->PrivateKey()), 384);
	Secret::ECDH sb(b, 384);
	auto s1 = sa.Share(lb->PublicKey());
	auto s2 = sb.Share(la->PublicKey());
	ASSERT_TRUE(s1.has_value());
	ASSERT_TRUE(s2.has_value());
	ASSERT_TRUE(s1 == s2);
	return 0;
}

int test_memory_x25519_der_shared_secret() {
	auto a = KeyPair::X25519::Generate(256);
	auto b = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(static_cast<bool>(a));
	ASSERT_TRUE(static_cast<bool>(b));
	auto la = KeyPair::Load(a->SavePublic(KeyPair::StorageFormat::DER), a->SavePrivate(KeyPair::StorageFormat::DER));
	ASSERT_TRUE(static_cast<bool>(la));
	ASSERT_EQUAL(la->PublicKey(), a->PublicKey());
	Secret::X25519 sa(la);
	Secret::X25519 sb(b);
	auto s1 = sa.Share(b->PublicKey());
	auto s2 = sb.Share(la->PublicKey());
	ASSERT_TRUE(s1.has_value());
	ASSERT_TRUE(s1 == s2);
	return 0;
}

int test_memory_matches_file_output() {
	auto kp = KeyPair::ECDSA::Generate(384);
	ASSERT_TRUE(static_cast<bool>(kp));
	const fs::path dir = KeysDir();
	ASSERT_TRUE(kp->SavePublic(dir / "file.pub.pem"));
	ASSERT_TRUE(kp->SavePrivate(dir / "file.pem"));
	ASSERT_TRUE(kp->SavePublic(dir / "file.pub.der", KeyPair::StorageFormat::DER));
	ASSERT_TRUE(ReadFile(dir / "file.pub.pem") == kp->SavePublic());
	ASSERT_TRUE(ReadFile(dir / "file.pem") == kp->SavePrivate());
	ASSERT_TRUE(ReadFile(dir / "file.pub.der") == kp->SavePublic(KeyPair::StorageFormat::DER));

	auto fromFile = KeyPair::Load(dir / "file.pub.pem", dir / "file.pem");
	auto fromMemory = KeyPair::Load(ReadFile(dir / "file.pub.pem"), ReadFile(dir / "file.pem"));
	ASSERT_TRUE(static_cast<bool>(fromFile));
	ASSERT_TRUE(static_cast<bool>(fromMemory));
	ASSERT_EQUAL(fromFile->PublicKey(), fromMemory->PublicKey());
	return 0;
}

int test_memory_public_only_has_no_private_output() {
	auto kp = KeyPair::ECDSA::Generate(384);
	ASSERT_TRUE(static_cast<bool>(kp));
	auto pub = KeyPair::Load(kp->SavePublic());
	ASSERT_TRUE(static_cast<bool>(pub));
	ASSERT_TRUE(pub->SavePrivate().empty());
	ASSERT_TRUE(pub->SavePrivate(TestPassword()).empty());
	ASSERT_FALSE(pub->SavePublic().empty());
	return 0;
}

int test_memory_invalid_input_fails() {
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(SecureBinary())));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(SecureBinary(), SecureBinary())));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(SecureBinary(std::string_view("not a key")))));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(
		SecureBinary(std::string_view("-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----\n")))));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(SecureBinary(), SecureBinary(), TestPassword())));

	auto kp = KeyPair::ECDSA::Generate(384);
	ASSERT_TRUE(static_cast<bool>(kp));
	const SecureBinary der = kp->SavePublic(KeyPair::StorageFormat::DER);
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(SecureBinary(der.span().first(der.size() / 2)))));
	return 0;
}

int main() {
	fs::remove_all(KeysDir());
	fs::create_directories(KeysDir());
	int result = 0;

	result += test_memory_rsa_pem_roundtrip();
	result += test_memory_ecdsa_p384_der_roundtrip();
	result += test_memory_public_only_verifies();
	result += test_memory_private_only_derives_public();
	result += test_memory_concatenated_pem_loads_pair();
	result += test_memory_encrypted_private_roundtrip();
	result += test_memory_encrypted_der_pair_roundtrip();
	result += test_memory_ecdh_p384_shared_secret();
	result += test_memory_x25519_der_shared_secret();
	result += test_memory_matches_file_output();
	result += test_memory_public_only_has_no_private_output();
	result += test_memory_invalid_input_fails();

	fs::remove_all(KeysDir());
	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
