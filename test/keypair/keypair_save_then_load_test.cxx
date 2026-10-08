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
#include <StormByte/test_handlers.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string_view>

using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;
using StormByte::Buffer::FIFO;
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

	fs::path SaveDir() {
		return KeysDir() / "save_roundtrip";
	}

	bool FileExists(const fs::path& p) {
		return fs::exists(p) && fs::is_regular_file(p);
	}

	Password TestKeysPassword() {
		return Password(STORMBYTE_TEST_KEYS_PASSWORD);
	}

	const StormByte::Safe::String kPlain = "StormByte Save/Load round-trip payload";
	KeyPair::Generic::PointerType g_rsa;
	KeyPair::Generic::PointerType g_dsa;
	KeyPair::Generic::PointerType g_ecc;
	KeyPair::Generic::PointerType g_ecdsa;
	KeyPair::Generic::PointerType g_ecdh_a;
	KeyPair::Generic::PointerType g_ecdh_b;
	KeyPair::Generic::PointerType g_ed25519;
	KeyPair::Generic::PointerType g_x25519_a;
	KeyPair::Generic::PointerType g_x25519_b;

	std::span<const std::byte> Bytes(std::string_view s) {
		return { reinterpret_cast<const std::byte*>(s.data()), s.size() };
	}

	int GenerateAll() {
		g_rsa = KeyPair::RSA::Generate(2048);
		ASSERT_TRUE(static_cast<bool>(g_rsa));
		g_dsa = KeyPair::DSA::Generate(2048);
		ASSERT_TRUE(static_cast<bool>(g_dsa));
		g_ecc = KeyPair::ECC::Generate(256);
		ASSERT_TRUE(static_cast<bool>(g_ecc));
		g_ecdsa = KeyPair::ECDSA::Generate(256);
		ASSERT_TRUE(static_cast<bool>(g_ecdsa));
		g_ecdh_a = KeyPair::ECDH::Generate(256);
		g_ecdh_b = KeyPair::ECDH::Generate(256);
		ASSERT_TRUE(static_cast<bool>(g_ecdh_a));
		ASSERT_TRUE(static_cast<bool>(g_ecdh_b));
		g_ed25519 = KeyPair::ED25519::Generate(256);
		ASSERT_TRUE(static_cast<bool>(g_ed25519));
		g_x25519_a = KeyPair::X25519::Generate(256);
		g_x25519_b = KeyPair::X25519::Generate(256);
		ASSERT_TRUE(static_cast<bool>(g_x25519_a));
		ASSERT_TRUE(static_cast<bool>(g_x25519_b));
		return 0;
	}

	int SaveAll() {
		const fs::path out = SaveDir();
		std::error_code ec;
		fs::remove_all(out, ec);
		fs::create_directories(out, ec);
		ASSERT_TRUE(fs::is_directory(out));
		ASSERT_TRUE(g_rsa->Save(out, "rsa", KeyPair::StorageFormat::PEM));
		ASSERT_TRUE(g_dsa->Save(out, "dsa", KeyPair::StorageFormat::PEM));
		ASSERT_TRUE(g_ecc->Save(out, "ecc", KeyPair::StorageFormat::PEM));
		ASSERT_TRUE(g_ecdsa->Save(out, "ecdsa", KeyPair::StorageFormat::PEM));
		ASSERT_TRUE(g_ecdh_a->Save(out, "ecdh_a", KeyPair::StorageFormat::PEM));
		ASSERT_TRUE(g_ecdh_b->Save(out, "ecdh_b", KeyPair::StorageFormat::PEM));
		ASSERT_TRUE(g_ed25519->Save(out, "ed25519", KeyPair::StorageFormat::PEM));
		ASSERT_TRUE(g_x25519_a->Save(out, "x25519_a", KeyPair::StorageFormat::PEM));
		ASSERT_TRUE(g_x25519_b->Save(out, "x25519_b", KeyPair::StorageFormat::PEM));
		ASSERT_TRUE(g_rsa->Save(out, "rsa_der", KeyPair::StorageFormat::DER));
		ASSERT_TRUE(g_ed25519->Save(out, "ed25519_der", KeyPair::StorageFormat::DER));
		ASSERT_TRUE(FileExists(out / "rsa.pub.pem"));
		ASSERT_TRUE(FileExists(out / "rsa.pem"));
		ASSERT_TRUE(FileExists(out / "rsa_der.pub.der"));
		ASSERT_TRUE(FileExists(out / "rsa_der.der"));
		return 0;
	}

	template<typename K>
	KeyPair::Generic::PointerType PubOnly(const KeyPair::Generic::PointerType& kp) {
		return K::template MakePointer<K>(kp->PublicKey(), std::nullopt);
	}

	template<typename CrypterT>
	int EncryptDecrypt(KeyPair::Generic::PointerType encKp,
			KeyPair::Generic::PointerType decKp, Crypter::Asymmetric::Strategy strategy,
			std::string_view text = kPlain) {
		CrypterT enc(encKp);
		CrypterT dec(decKp);
		FIFO cipher;
		FIFO plain;
		ASSERT_TRUE(enc.Encrypt(Bytes(text), cipher, strategy));
		ASSERT_TRUE(dec.Decrypt(cipher.Data().span(), plain));
		const StormByte::Safe::String got = DeserializeString(plain.Data());
		ASSERT_TRUE(static_cast<std::string_view>(got) == text);
		return 0;
	}

	template<typename SignerT, typename KeyT>
	int SignVerify(KeyPair::Generic::PointerType signKp,
			KeyPair::Generic::PointerType verifyKp) {
		SignerT signer(signKp);
		SignerT verifier(PubOnly<KeyT>(verifyKp));
		FIFO signature;
		ASSERT_TRUE(signer.Sign(Bytes(kPlain), signature));
		ASSERT_TRUE(verifier.Verify(Bytes(kPlain), DeserializeString(signature.Data())));
		return 0;
	}

	int ShareX25519(KeyPair::Generic::PointerType a, KeyPair::Generic::PointerType b) {
		Secret::X25519 sa(a);
		Secret::X25519 sb(b);
		auto s1 = sa.Share(b->PublicKey());
		auto s2 = sb.Share(a->PublicKey());
		ASSERT_TRUE(s1.has_value());
		ASSERT_TRUE(s2.has_value());
		ASSERT_TRUE(s1 == s2);
		return 0;
	}

	int ShareEcdh(KeyPair::Generic::PointerType a, KeyPair::Generic::PointerType b) {
		auto ea = KeyPair::ECDH::MakePointer<KeyPair::ECDH>(a->PublicKey(), a->PrivateKey());
		auto eb = KeyPair::ECDH::MakePointer<KeyPair::ECDH>(b->PublicKey(), b->PrivateKey());
		Secret::ECDH sa(ea, 256);
		Secret::ECDH sb(eb, 256);
		auto s1 = sa.Share(eb->PublicKey());
		auto s2 = sb.Share(ea->PublicKey());
		ASSERT_TRUE(s1.has_value());
		ASSERT_TRUE(s2.has_value());
		ASSERT_TRUE(s1 == s2);
		return 0;
	}
}

// ---------------------------------------------------------------------------
// File permissions
// ---------------------------------------------------------------------------
int test_private_key_files_are_owner_only() {
#ifndef WINDOWS
	const auto priv = fs::status(SaveDir() / "rsa.pem").permissions();
	const auto forbidden = fs::perms::group_read | fs::perms::group_write | fs::perms::group_exec
		| fs::perms::others_read | fs::perms::others_write | fs::perms::others_exec;
	ASSERT_TRUE((priv & forbidden) == fs::perms::none);
	ASSERT_TRUE((priv & fs::perms::owner_read) != fs::perms::none);
	ASSERT_TRUE((priv & fs::perms::owner_write) != fs::perms::none);
	ASSERT_TRUE((fs::status(SaveDir() / "rsa.pub.pem").permissions() & fs::perms::owner_read) != fs::perms::none);
#endif
	RETURN_TEST(0);
}

int test_save_refuses_to_follow_symlink() {
#ifndef WINDOWS
	const fs::path out = SaveDir() / "symlink_target";
	std::error_code ec;
	fs::remove_all(out, ec);
	fs::create_directories(out, ec);
	const fs::path decoy = out / "decoy.txt";
	{
		std::ofstream stream(decoy);
		stream << "do not overwrite me";
	}
	const fs::path priv = out / "rsa.pem";
	fs::create_symlink(decoy, priv, ec);
	ASSERT_TRUE(!ec);
	ASSERT_FALSE(g_rsa->Save(out, "rsa", KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(fs::is_symlink(priv));
	std::ifstream in(decoy);
	StormByte::Safe::String content;
	char byte;
	while (in.get(byte))
		content.push_back(byte);
	ASSERT_EQUAL(content, StormByte::Safe::String("do not overwrite me"));
#endif
	RETURN_TEST(0);
}

// ---------------------------------------------------------------------------
// RSA
// ---------------------------------------------------------------------------
int test_save_load_rsa_encrypt_decrypt() {
	auto loaded = KeyPair::Load(SaveDir() / "rsa.pub.pem", SaveDir() / "rsa.pem");
	ASSERT_TRUE(static_cast<bool>(loaded));
	ASSERT_TRUE(loaded->HasPrivateKey());
	ASSERT_EQUAL(loaded->PublicKey(), g_rsa->PublicKey());
	return EncryptDecrypt<Crypter::RSA>(loaded, loaded, Crypter::Asymmetric::Strategy::Native);
}

int test_save_load_rsa_hybrid_encrypt_decrypt() {
	auto loaded = KeyPair::Load(SaveDir() / "rsa.pub.pem", SaveDir() / "rsa.pem");
	ASSERT_TRUE(static_cast<bool>(loaded));
	return EncryptDecrypt<Crypter::RSA>(loaded, loaded, Crypter::Asymmetric::Strategy::Hybrid,
		kPlain + StormByte::Safe::String(StormByte::Size{4096}, 'B'));
}

int test_save_load_rsa_sign_verify() {
	auto loaded = KeyPair::Load(SaveDir() / "rsa.pub.pem", SaveDir() / "rsa.pem");
	ASSERT_TRUE(static_cast<bool>(loaded));
	return SignVerify<Signer::RSA, KeyPair::RSA>(loaded, loaded);
}

int test_save_load_rsa_der_encrypt_decrypt() {
	auto loaded = KeyPair::Load(SaveDir() / "rsa_der.pub.der", SaveDir() / "rsa_der.der");
	ASSERT_TRUE(static_cast<bool>(loaded));
	return EncryptDecrypt<Crypter::RSA>(loaded, loaded, Crypter::Asymmetric::Strategy::Native);
}

int test_save_load_rsa_private_only() {
	auto loaded = KeyPair::Load(SaveDir() / "rsa.pem");
	ASSERT_TRUE(static_cast<bool>(loaded));
	ASSERT_TRUE(loaded->HasPrivateKey());
	ASSERT_TRUE(!loaded->PublicKey().empty());
	return EncryptDecrypt<Crypter::RSA>(PubOnly<KeyPair::RSA>(loaded), loaded,
		Crypter::Asymmetric::Strategy::Native);
}

// ---------------------------------------------------------------------------
// DSA / ECDSA / Ed25519
// ---------------------------------------------------------------------------
int test_save_load_dsa_sign_verify() {
	auto loaded = KeyPair::Load(SaveDir() / "dsa.pub.pem", SaveDir() / "dsa.pem");
	ASSERT_TRUE(static_cast<bool>(loaded));
	ASSERT_EQUAL(loaded->PublicKey(), g_dsa->PublicKey());
	return SignVerify<Signer::DSA, KeyPair::DSA>(loaded, loaded);
}

int test_save_load_ecdsa_sign_verify() {
	auto loaded = KeyPair::Load(SaveDir() / "ecdsa.pub.pem", SaveDir() / "ecdsa.pem");
	ASSERT_TRUE(static_cast<bool>(loaded));
	return SignVerify<Signer::ECDSA, KeyPair::ECDSA>(loaded, loaded);
}

int test_save_load_ed25519_sign_verify() {
	auto loaded = KeyPair::Load(SaveDir() / "ed25519.pub.pem", SaveDir() / "ed25519.pem");
	ASSERT_TRUE(static_cast<bool>(loaded));
	ASSERT_EQUAL(loaded->PublicKey(), g_ed25519->PublicKey());
	return SignVerify<Signer::ED25519, KeyPair::ED25519>(loaded, loaded);
}

int test_save_load_ed25519_der_sign_verify() {
	auto loaded = KeyPair::Load(SaveDir() / "ed25519_der.pub.der", SaveDir() / "ed25519_der.der");
	ASSERT_TRUE(static_cast<bool>(loaded));
	return SignVerify<Signer::ED25519, KeyPair::ED25519>(loaded, loaded);
}

// ---------------------------------------------------------------------------
// ECC / ECDH / X25519
// ---------------------------------------------------------------------------
int test_save_load_ecc_encrypt_decrypt() {
	auto loaded = KeyPair::Load(SaveDir() / "ecc.pub.pem", SaveDir() / "ecc.pem");
	ASSERT_TRUE(static_cast<bool>(loaded));
	return EncryptDecrypt<Crypter::ECC>(PubOnly<KeyPair::ECC>(loaded), loaded,
		Crypter::Asymmetric::Strategy::Native);
}

int test_save_load_ecdh_share() {
	auto a = KeyPair::Load(SaveDir() / "ecdh_a.pub.pem", SaveDir() / "ecdh_a.pem");
	auto b = KeyPair::Load(SaveDir() / "ecdh_b.pub.pem", SaveDir() / "ecdh_b.pem");
	ASSERT_TRUE(static_cast<bool>(a));
	ASSERT_TRUE(static_cast<bool>(b));
	return ShareEcdh(a, b);
}

int test_save_load_x25519_share() {
	auto a = KeyPair::Load(SaveDir() / "x25519_a.pub.pem", SaveDir() / "x25519_a.pem");
	auto b = KeyPair::Load(SaveDir() / "x25519_b.pub.pem", SaveDir() / "x25519_b.pem");
	ASSERT_TRUE(static_cast<bool>(a));
	ASSERT_TRUE(static_cast<bool>(b));
	return ShareX25519(a, b);
}

// ---------------------------------------------------------------------------
// SavePublic / SavePrivate
// ---------------------------------------------------------------------------
int test_save_public_only_then_load() {
	const auto pubPath = SaveDir() / "rsa_public_only.pem";
	ASSERT_TRUE(g_rsa->SavePublic(pubPath, KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(FileExists(pubPath));
	auto loaded = KeyPair::Load(pubPath);
	ASSERT_TRUE(static_cast<bool>(loaded));
	ASSERT_FALSE(loaded->HasPrivateKey());
	ASSERT_EQUAL(loaded->PublicKey(), g_rsa->PublicKey());
	return EncryptDecrypt<Crypter::RSA>(loaded, g_rsa, Crypter::Asymmetric::Strategy::Native);
}

int test_save_private_only_then_load() {
	const auto privPath = SaveDir() / "rsa_private_only.pem";
	ASSERT_TRUE(g_rsa->SavePrivate(privPath, KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(FileExists(privPath));
	auto loaded = KeyPair::Load(privPath);
	ASSERT_TRUE(static_cast<bool>(loaded));
	ASSERT_TRUE(loaded->HasPrivateKey());
	ASSERT_TRUE(!loaded->PublicKey().empty());
	return EncryptDecrypt<Crypter::RSA>(PubOnly<KeyPair::RSA>(loaded), loaded,
		Crypter::Asymmetric::Strategy::Native);
}

// ---------------------------------------------------------------------------
// Encrypted save
// ---------------------------------------------------------------------------
int test_save_encrypted_rsa_private_load_decrypt() {
	const auto encPath = SaveDir() / "rsa_priv_enc.pem";
	const Password pass = TestKeysPassword();
	ASSERT_TRUE(g_rsa->SavePrivate(encPath, pass, KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(FileExists(encPath));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(encPath)));
	auto loaded = KeyPair::Load(encPath, pass);
	ASSERT_TRUE(static_cast<bool>(loaded));
	ASSERT_TRUE(loaded->HasPrivateKey());
	return EncryptDecrypt<Crypter::RSA>(PubOnly<KeyPair::RSA>(loaded), loaded,
		Crypter::Asymmetric::Strategy::Native);
}

int test_save_encrypted_rsa_pair_load_sign_verify() {
	const Password pass = TestKeysPassword();
	ASSERT_TRUE(g_rsa->Save(SaveDir(), "rsa_enc_pair", pass, KeyPair::StorageFormat::PEM));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(SaveDir() / "rsa_enc_pair.pub.pem", SaveDir() / "rsa_enc_pair.pem")));
	auto loaded = KeyPair::Load(SaveDir() / "rsa_enc_pair.pub.pem", SaveDir() / "rsa_enc_pair.pem", pass);
	ASSERT_TRUE(static_cast<bool>(loaded));
	return SignVerify<Signer::RSA, KeyPair::RSA>(loaded, loaded);
}

int test_save_encrypted_wrong_password_fails() {
	const auto encPath = SaveDir() / "rsa_priv_enc_wrong.pem";
	const Password pass = TestKeysPassword();
	ASSERT_TRUE(g_rsa->SavePrivate(encPath, pass, KeyPair::StorageFormat::PEM));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(encPath, Password("DefinitelyNotTheRightPassphrase!"))));
	ASSERT_TRUE(static_cast<bool>(KeyPair::Load(encPath, pass)));
	RETURN_TEST(0);
}

int test_save_encrypted_different_passwords_independent() {
	const Password passA = TestKeysPassword();
	const Password passB("StormByteAltTestPassphrase!");
	const auto pathA = SaveDir() / "rsa_enc_A.pem";
	const auto pathB = SaveDir() / "rsa_enc_B.pem";
	ASSERT_TRUE(g_rsa->SavePrivate(pathA, passA, KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(g_rsa->SavePrivate(pathB, passB, KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(static_cast<bool>(KeyPair::Load(pathA, passA)));
	ASSERT_TRUE(static_cast<bool>(KeyPair::Load(pathB, passB)));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(pathA, passB)));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(pathB, passA)));
	RETURN_TEST(0);
}

int test_save_encrypted_ed25519_sign_verify() {
	const Password pass = TestKeysPassword();
	ASSERT_TRUE(g_ed25519->SavePrivate(SaveDir() / "ed25519_enc.pem", pass, KeyPair::StorageFormat::PEM));
	auto loaded = KeyPair::Load(SaveDir() / "ed25519_enc.pem", pass);
	ASSERT_TRUE(static_cast<bool>(loaded));
	return SignVerify<Signer::ED25519, KeyPair::ED25519>(loaded, loaded);
}

int test_save_encrypted_dsa_sign_verify() {
	const Password pass = TestKeysPassword();
	ASSERT_TRUE(g_dsa->SavePrivate(SaveDir() / "dsa_enc.pem", pass, KeyPair::StorageFormat::PEM));
	auto loaded = KeyPair::Load(SaveDir() / "dsa_enc.pem", pass);
	ASSERT_TRUE(static_cast<bool>(loaded));
	return SignVerify<Signer::DSA, KeyPair::DSA>(loaded, loaded);
}

int test_save_encrypted_ecc_encrypt_decrypt() {
	const Password pass = TestKeysPassword();
	ASSERT_TRUE(g_ecc->SavePrivate(SaveDir() / "ecc_enc.pem", pass, KeyPair::StorageFormat::PEM));
	auto loaded = KeyPair::Load(SaveDir() / "ecc_enc.pem", pass);
	ASSERT_TRUE(static_cast<bool>(loaded));
	return EncryptDecrypt<Crypter::ECC>(PubOnly<KeyPair::ECC>(loaded), loaded,
		Crypter::Asymmetric::Strategy::Native);
}

int test_save_encrypted_x25519_share() {
	const Password passA = TestKeysPassword();
	const Password passB("StormByteAltTestPassphrase!");
	ASSERT_TRUE(g_x25519_a->SavePrivate(SaveDir() / "x25519_a_enc.pem", passA, KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(g_x25519_b->SavePrivate(SaveDir() / "x25519_b_enc.pem", passB, KeyPair::StorageFormat::PEM));
	auto a = KeyPair::Load(SaveDir() / "x25519_a_enc.pem", passA);
	auto b = KeyPair::Load(SaveDir() / "x25519_b_enc.pem", passB);
	ASSERT_TRUE(static_cast<bool>(a));
	ASSERT_TRUE(static_cast<bool>(b));
	return ShareX25519(a, b);
}

int test_save_encrypted_public_stays_plain() {
	ASSERT_TRUE(g_rsa->Save(SaveDir(), "rsa_enc_pubcheck", TestKeysPassword(), KeyPair::StorageFormat::PEM));
	auto pubOnly = KeyPair::Load(SaveDir() / "rsa_enc_pubcheck.pub.pem");
	ASSERT_TRUE(static_cast<bool>(pubOnly));
	ASSERT_FALSE(pubOnly->HasPrivateKey());
	ASSERT_EQUAL(pubOnly->PublicKey(), g_rsa->PublicKey());
	RETURN_TEST(0);
}

// ---------------------------------------------------------------------------
// Cross-format PEM / DER
// ---------------------------------------------------------------------------
int test_cross_format_rsa_pem_encrypt_der_decrypt() {
	ASSERT_TRUE(g_rsa->Save(SaveDir(), "rsa_cross_pem", KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(g_rsa->Save(SaveDir(), "rsa_cross_der", KeyPair::StorageFormat::DER));
	auto pem = KeyPair::Load(SaveDir() / "rsa_cross_pem.pub.pem", SaveDir() / "rsa_cross_pem.pem");
	auto der = KeyPair::Load(SaveDir() / "rsa_cross_der.pub.der", SaveDir() / "rsa_cross_der.der");
	ASSERT_TRUE(static_cast<bool>(pem));
	ASSERT_TRUE(static_cast<bool>(der));
	if (EncryptDecrypt<Crypter::RSA>(pem, der, Crypter::Asymmetric::Strategy::Native) != 0)
		return 1;
	return EncryptDecrypt<Crypter::RSA>(der, pem, Crypter::Asymmetric::Strategy::Native);
}

int test_cross_format_rsa_encrypted_pem_der() {
	const Password pass = TestKeysPassword();
	ASSERT_TRUE(g_rsa->SavePrivate(SaveDir() / "rsa_enc_cross.pem", pass, KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(g_rsa->SavePrivate(SaveDir() / "rsa_enc_cross.der", pass, KeyPair::StorageFormat::DER));
	auto pem = KeyPair::Load(SaveDir() / "rsa_enc_cross.pem", pass);
	auto der = KeyPair::Load(SaveDir() / "rsa_enc_cross.der", pass);
	ASSERT_TRUE(static_cast<bool>(pem));
	ASSERT_TRUE(static_cast<bool>(der));
	return EncryptDecrypt<Crypter::RSA>(PubOnly<KeyPair::RSA>(pem), der,
		Crypter::Asymmetric::Strategy::Native);
}

int test_cross_format_rsa_pem_sign_der_verify() {
	ASSERT_TRUE(g_rsa->Save(SaveDir(), "rsa_sig_pem", KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(g_rsa->Save(SaveDir(), "rsa_sig_der", KeyPair::StorageFormat::DER));
	auto pem = KeyPair::Load(SaveDir() / "rsa_sig_pem.pub.pem", SaveDir() / "rsa_sig_pem.pem");
	auto der = KeyPair::Load(SaveDir() / "rsa_sig_der.pub.der", SaveDir() / "rsa_sig_der.der");
	ASSERT_TRUE(static_cast<bool>(pem));
	ASSERT_TRUE(static_cast<bool>(der));
	return SignVerify<Signer::RSA, KeyPair::RSA>(pem, der);
}

int test_cross_format_dsa_pem_sign_der_verify() {
	ASSERT_TRUE(g_dsa->Save(SaveDir(), "dsa_cross_pem", KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(g_dsa->Save(SaveDir(), "dsa_cross_der", KeyPair::StorageFormat::DER));
	auto pem = KeyPair::Load(SaveDir() / "dsa_cross_pem.pub.pem", SaveDir() / "dsa_cross_pem.pem");
	auto der = KeyPair::Load(SaveDir() / "dsa_cross_der.pub.der", SaveDir() / "dsa_cross_der.der");
	ASSERT_TRUE(static_cast<bool>(pem));
	ASSERT_TRUE(static_cast<bool>(der));
	return SignVerify<Signer::DSA, KeyPair::DSA>(pem, der);
}

int test_cross_format_dsa_encrypted_pem_der() {
	const Password pass = TestKeysPassword();
	ASSERT_TRUE(g_dsa->SavePrivate(SaveDir() / "dsa_enc_cross.pem", pass, KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(g_dsa->SavePrivate(SaveDir() / "dsa_enc_cross.der", pass, KeyPair::StorageFormat::DER));
	auto pem = KeyPair::Load(SaveDir() / "dsa_enc_cross.pem", pass);
	auto der = KeyPair::Load(SaveDir() / "dsa_enc_cross.der", pass);
	ASSERT_TRUE(static_cast<bool>(pem));
	ASSERT_TRUE(static_cast<bool>(der));
	return SignVerify<Signer::DSA, KeyPair::DSA>(pem, der);
}

int test_cross_format_ecdsa_pem_sign_der_verify() {
	ASSERT_TRUE(g_ecdsa->Save(SaveDir(), "ecdsa_cross_pem", KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(g_ecdsa->Save(SaveDir(), "ecdsa_cross_der", KeyPair::StorageFormat::DER));
	auto pem = KeyPair::Load(SaveDir() / "ecdsa_cross_pem.pub.pem", SaveDir() / "ecdsa_cross_pem.pem");
	auto der = KeyPair::Load(SaveDir() / "ecdsa_cross_der.pub.der", SaveDir() / "ecdsa_cross_der.der");
	ASSERT_TRUE(static_cast<bool>(pem));
	ASSERT_TRUE(static_cast<bool>(der));
	return SignVerify<Signer::ECDSA, KeyPair::ECDSA>(pem, der);
}

int test_cross_format_ed25519_pem_sign_der_verify() {
	ASSERT_TRUE(g_ed25519->Save(SaveDir(), "ed25519_cross_pem", KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(g_ed25519->Save(SaveDir(), "ed25519_cross_der", KeyPair::StorageFormat::DER));
	auto pem = KeyPair::Load(SaveDir() / "ed25519_cross_pem.pub.pem", SaveDir() / "ed25519_cross_pem.pem");
	auto der = KeyPair::Load(SaveDir() / "ed25519_cross_der.pub.der", SaveDir() / "ed25519_cross_der.der");
	ASSERT_TRUE(static_cast<bool>(pem));
	ASSERT_TRUE(static_cast<bool>(der));
	return SignVerify<Signer::ED25519, KeyPair::ED25519>(pem, der);
}

int test_cross_format_ed25519_encrypted_pem_der() {
	const Password pass = TestKeysPassword();
	ASSERT_TRUE(g_ed25519->SavePrivate(SaveDir() / "ed25519_enc_cross.pem", pass, KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(g_ed25519->SavePrivate(SaveDir() / "ed25519_enc_cross.der", pass, KeyPair::StorageFormat::DER));
	auto pem = KeyPair::Load(SaveDir() / "ed25519_enc_cross.pem", pass);
	auto der = KeyPair::Load(SaveDir() / "ed25519_enc_cross.der", pass);
	ASSERT_TRUE(static_cast<bool>(pem));
	ASSERT_TRUE(static_cast<bool>(der));
	return SignVerify<Signer::ED25519, KeyPair::ED25519>(pem, der);
}

int test_cross_format_ecc_pem_encrypt_der_decrypt() {
	ASSERT_TRUE(g_ecc->Save(SaveDir(), "ecc_cross_pem", KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(g_ecc->Save(SaveDir(), "ecc_cross_der", KeyPair::StorageFormat::DER));
	auto pem = KeyPair::Load(SaveDir() / "ecc_cross_pem.pub.pem", SaveDir() / "ecc_cross_pem.pem");
	auto der = KeyPair::Load(SaveDir() / "ecc_cross_der.pub.der", SaveDir() / "ecc_cross_der.der");
	ASSERT_TRUE(static_cast<bool>(pem));
	ASSERT_TRUE(static_cast<bool>(der));
	return EncryptDecrypt<Crypter::ECC>(PubOnly<KeyPair::ECC>(pem), der,
		Crypter::Asymmetric::Strategy::Native);
}

int test_cross_format_ecdh_pem_der_share() {
	ASSERT_TRUE(g_ecdh_a->Save(SaveDir(), "ecdh_a_cross_pem", KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(g_ecdh_a->Save(SaveDir(), "ecdh_a_cross_der", KeyPair::StorageFormat::DER));
	ASSERT_TRUE(g_ecdh_b->Save(SaveDir(), "ecdh_b_cross_pem", KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(g_ecdh_b->Save(SaveDir(), "ecdh_b_cross_der", KeyPair::StorageFormat::DER));
	auto a = KeyPair::Load(SaveDir() / "ecdh_a_cross_pem.pub.pem", SaveDir() / "ecdh_a_cross_pem.pem");
	auto b = KeyPair::Load(SaveDir() / "ecdh_b_cross_der.pub.der", SaveDir() / "ecdh_b_cross_der.der");
	ASSERT_TRUE(static_cast<bool>(a));
	ASSERT_TRUE(static_cast<bool>(b));
	return ShareEcdh(a, b);
}

int test_cross_format_x25519_pem_der_share() {
	ASSERT_TRUE(g_x25519_a->Save(SaveDir(), "x25519_a_cross_pem", KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(g_x25519_a->Save(SaveDir(), "x25519_a_cross_der", KeyPair::StorageFormat::DER));
	ASSERT_TRUE(g_x25519_b->Save(SaveDir(), "x25519_b_cross_pem", KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(g_x25519_b->Save(SaveDir(), "x25519_b_cross_der", KeyPair::StorageFormat::DER));
	auto a = KeyPair::Load(SaveDir() / "x25519_a_cross_pem.pub.pem", SaveDir() / "x25519_a_cross_pem.pem");
	auto b = KeyPair::Load(SaveDir() / "x25519_b_cross_der.pub.der", SaveDir() / "x25519_b_cross_der.der");
	ASSERT_TRUE(static_cast<bool>(a));
	ASSERT_TRUE(static_cast<bool>(b));
	return ShareX25519(a, b);
}

int test_cross_format_x25519_encrypted_pem_der_share() {
	const Password pass = TestKeysPassword();
	ASSERT_TRUE(g_x25519_a->SavePrivate(SaveDir() / "x25519_a_enc_cross.pem", pass, KeyPair::StorageFormat::PEM));
	ASSERT_TRUE(g_x25519_b->SavePrivate(SaveDir() / "x25519_b_enc_cross.der", pass, KeyPair::StorageFormat::DER));
	auto a = KeyPair::Load(SaveDir() / "x25519_a_enc_cross.pem", pass);
	auto b = KeyPair::Load(SaveDir() / "x25519_b_enc_cross.der", pass);
	ASSERT_TRUE(static_cast<bool>(a));
	ASSERT_TRUE(static_cast<bool>(b));
	return ShareX25519(a, b);
}

// ---------------------------------------------------------------------------
// Save edge cases
// ---------------------------------------------------------------------------
int test_save_to_missing_directory_fails() {
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(kp));
	const auto missing = KeysDir() / "does_not_exist_subdir";
	ASSERT_FALSE(fs::exists(missing));
	ASSERT_FALSE(kp->Save(missing, "rsa_missing_dir"));
	RETURN_TEST(0);
}

int test_save_public_only_then_load_has_no_private() {
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(kp));
	const auto out = KeysDir() / "save_public_only";
	fs::create_directories(out);
	ASSERT_TRUE(kp->SavePublic(out / "rsa.pub.pem"));
	auto loaded = KeyPair::Load(out / "rsa.pub.pem");
	ASSERT_TRUE(static_cast<bool>(loaded));
	ASSERT_FALSE(loaded->PrivateKey().has_value());
	RETURN_TEST(0);
}

int test_save_private_only_then_load_derives_public_and_encrypts() {
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(kp));
	const auto out = KeysDir() / "save_private_only";
	fs::create_directories(out);
	ASSERT_TRUE(kp->SavePrivate(out / "rsa.pem"));
	auto loaded = KeyPair::Load(out / "rsa.pem");
	ASSERT_TRUE(static_cast<bool>(loaded));
	ASSERT_TRUE(loaded->PrivateKey().has_value());
	ASSERT_TRUE(!loaded->PublicKey().empty());
	return EncryptDecrypt<Crypter::RSA>(loaded, loaded, Crypter::Asymmetric::Strategy::Native,
		"private-only-roundtrip");
}

int test_save_overwrite_same_base_name_still_usable() {
	auto kp1 = KeyPair::RSA::Generate(2048);
	auto kp2 = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(kp1));
	ASSERT_TRUE(static_cast<bool>(kp2));
	const auto out = KeysDir() / "save_overwrite";
	fs::create_directories(out);
	ASSERT_TRUE(kp1->Save(out, "rsa_ow"));
	ASSERT_TRUE(kp2->Save(out, "rsa_ow"));
	auto loaded = KeyPair::Load(out / "rsa_ow.pub.pem", out / "rsa_ow.pem");
	ASSERT_TRUE(static_cast<bool>(loaded));
	return EncryptDecrypt<Crypter::RSA>(loaded, loaded, Crypter::Asymmetric::Strategy::Native,
		"overwrite-check");
}

int test_save_encrypted_empty_password_fails() {
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(kp));
	const auto out = KeysDir() / "save_enc_empty_pass";
	fs::create_directories(out);
	ASSERT_FALSE(kp->Save(out, "rsa_empty", Password("")));
	RETURN_TEST(0);
}

int test_save_encrypted_different_passwords_both_work() {
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(kp));
	const Password passA = TestKeysPassword();
	const Password passB("AnotherStormBytePass!");
	const auto out = KeysDir() / "save_enc_two_pass";
	fs::create_directories(out);
	ASSERT_TRUE(kp->Save(out, "rsa_a", passA));
	ASSERT_TRUE(kp->Save(out, "rsa_b", passB));
	ASSERT_TRUE(static_cast<bool>(KeyPair::Load(out / "rsa_a.pub.pem", out / "rsa_a.pem", passA)));
	ASSERT_TRUE(static_cast<bool>(KeyPair::Load(out / "rsa_b.pub.pem", out / "rsa_b.pem", passB)));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(out / "rsa_a.pub.pem", out / "rsa_a.pem", passB)));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(out / "rsa_b.pub.pem", out / "rsa_b.pem", passA)));
	RETURN_TEST(0);
}

int test_generate_invalid_bits_then_nothing_to_save() {
	ASSERT_FALSE(static_cast<bool>(KeyPair::RSA::Generate(0)));
	ASSERT_FALSE(static_cast<bool>(KeyPair::RSA::Generate(9999)));
	ASSERT_FALSE(static_cast<bool>(KeyPair::ECDH::Generate(0)));
	ASSERT_FALSE(static_cast<bool>(KeyPair::ECDH::Generate(123)));
	RETURN_TEST(0);
}

int test_save_ecdh_round_trip_share() {
	auto a0 = KeyPair::ECDH::Generate(256);
	auto b0 = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(static_cast<bool>(a0));
	ASSERT_TRUE(static_cast<bool>(b0));
	const auto out = KeysDir() / "save_ecdh_share";
	fs::create_directories(out);
	ASSERT_TRUE(a0->Save(out, "ecdh_a"));
	ASSERT_TRUE(b0->Save(out, "ecdh_b"));
	auto a = KeyPair::Load(out / "ecdh_a.pub.pem", out / "ecdh_a.pem");
	auto b = KeyPair::Load(out / "ecdh_b.pub.pem", out / "ecdh_b.pem");
	ASSERT_TRUE(static_cast<bool>(a));
	ASSERT_TRUE(static_cast<bool>(b));
	Secret::ECDH ecdhA(a);
	Secret::ECDH ecdhB(b);
	auto s1 = ecdhA.Share(b->PublicKey());
	auto s2 = ecdhB.Share(a->PublicKey());
	ASSERT_TRUE(s1.has_value());
	ASSERT_TRUE(s2.has_value());
	ASSERT_TRUE(s1 == s2);
	RETURN_TEST(0);
}

template<typename KeyPairT>
int test_private_optional_copy_move() {
	static_assert(StormByte::Type::MaybeSafe<KeyPair::Generic>);
	static_assert(StormByte::Type::MaybeSafe<KeyPairT>);
	static_assert(StormByte::Type::SameAs<
		decltype(std::declval<const KeyPairT&>().PrivateKey()),
		const StormByte::Safe::Optional<Password>&>);
	static_assert(StormByte::Type::SameAs<
		decltype(*std::declval<const StormByte::Safe::Optional<Password>&>()), Password>);
	const Password expected("retained-private-material");
	StormByte::Safe::Optional<Password> retained;
	Password snapshot;
	{
		StormByte::Safe::Optional<Password> source(Password("retained-private-material"));
		KeyPairT original("public-material", source);
		source.reset();
		ASSERT_TRUE(original.HasPrivateKey());
		ASSERT_TRUE(original.PrivateKey().value() == expected);

		KeyPairT copied(original);
		KeyPairT moved(std::move(copied));
		ASSERT_FALSE(copied.HasPrivateKey());
		ASSERT_TRUE(moved.PrivateKey().value() == expected);
		ASSERT_TRUE(moved.PublicKey() == original.PublicKey());

		KeyPairT assigned("replacement", Password("old-private-material"));
		assigned = original;
		KeyPairT moveAssigned("replacement", Password("old-private-material"));
		moveAssigned = std::move(assigned);
		ASSERT_FALSE(assigned.HasPrivateKey());
		ASSERT_TRUE(moveAssigned.PrivateKey().value() == expected);
		ASSERT_TRUE(moveAssigned.PublicKey() == original.PublicKey());

		auto clone = original.Clone();
		ASSERT_TRUE(static_cast<bool>(clone));
		auto transferred = clone->Move();
		ASSERT_TRUE(static_cast<bool>(transferred));
		ASSERT_FALSE(clone->HasPrivateKey());
		ASSERT_TRUE(transferred->PrivateKey().value() == expected);

		StormByte::Safe::Optional<Password> optionalCopy(transferred->PrivateKey());
		StormByte::Safe::Optional<Password> optionalMove(std::move(optionalCopy));
		ASSERT_FALSE(optionalCopy.has_value());
		retained = optionalMove;
		optionalMove.reset();
		snapshot = *retained;
	}
	ASSERT_TRUE(retained.value() == expected);
	retained.reset();
	ASSERT_TRUE(snapshot == expected);
	ASSERT_TRUE(snapshot.Size() == expected.Size());
	KeyPairT publicOnly("public-material");
	ASSERT_FALSE(publicOnly.HasPrivateKey());
	KeyPairT emptyCopy(publicOnly);
	KeyPairT emptyMove(std::move(emptyCopy));
	ASSERT_FALSE(emptyMove.HasPrivateKey());
	RETURN_TEST(0);
}

int main() {
	{
		if (GenerateAll() != 0 || SaveAll() != 0)
			return 1;
	}

	int result = 0;

	// ---------------------------------------------------------------------------
	// Private optional copy / move
	// ---------------------------------------------------------------------------
	result += test_private_optional_copy_move<KeyPair::DSA>();
	result += test_private_optional_copy_move<KeyPair::ECC>();
	result += test_private_optional_copy_move<KeyPair::ECDH>();
	result += test_private_optional_copy_move<KeyPair::ECDSA>();
	result += test_private_optional_copy_move<KeyPair::ED25519>();
	result += test_private_optional_copy_move<KeyPair::RSA>();
	result += test_private_optional_copy_move<KeyPair::X25519>();

	// ---------------------------------------------------------------------------
	// File permissions
	// ---------------------------------------------------------------------------
	result += test_private_key_files_are_owner_only();
	result += test_save_refuses_to_follow_symlink();

	// ---------------------------------------------------------------------------
	// RSA
	// ---------------------------------------------------------------------------
	result += test_save_load_rsa_encrypt_decrypt();
	result += test_save_load_rsa_hybrid_encrypt_decrypt();
	result += test_save_load_rsa_sign_verify();
	result += test_save_load_rsa_der_encrypt_decrypt();
	result += test_save_load_rsa_private_only();

	// ---------------------------------------------------------------------------
	// DSA / ECDSA / Ed25519
	// ---------------------------------------------------------------------------
	result += test_save_load_dsa_sign_verify();
	result += test_save_load_ecdsa_sign_verify();
	result += test_save_load_ed25519_sign_verify();
	result += test_save_load_ed25519_der_sign_verify();

	// ---------------------------------------------------------------------------
	// ECC / ECDH / X25519
	// ---------------------------------------------------------------------------
	result += test_save_load_ecc_encrypt_decrypt();
	result += test_save_load_ecdh_share();
	result += test_save_load_x25519_share();

	// ---------------------------------------------------------------------------
	// SavePublic / SavePrivate
	// ---------------------------------------------------------------------------
	result += test_save_public_only_then_load();
	result += test_save_private_only_then_load();

	// ---------------------------------------------------------------------------
	// Encrypted save
	// ---------------------------------------------------------------------------
	result += test_save_encrypted_rsa_private_load_decrypt();
	result += test_save_encrypted_rsa_pair_load_sign_verify();
	result += test_save_encrypted_wrong_password_fails();
	result += test_save_encrypted_different_passwords_independent();
	result += test_save_encrypted_ed25519_sign_verify();
	result += test_save_encrypted_dsa_sign_verify();
	result += test_save_encrypted_ecc_encrypt_decrypt();
	result += test_save_encrypted_x25519_share();
	result += test_save_encrypted_public_stays_plain();

	// ---------------------------------------------------------------------------
	// Cross-format PEM / DER
	// ---------------------------------------------------------------------------
	result += test_cross_format_rsa_pem_encrypt_der_decrypt();
	result += test_cross_format_rsa_encrypted_pem_der();
	result += test_cross_format_rsa_pem_sign_der_verify();
	result += test_cross_format_dsa_pem_sign_der_verify();
	result += test_cross_format_dsa_encrypted_pem_der();
	result += test_cross_format_ecdsa_pem_sign_der_verify();
	result += test_cross_format_ed25519_pem_sign_der_verify();
	result += test_cross_format_ed25519_encrypted_pem_der();
	result += test_cross_format_ecc_pem_encrypt_der_decrypt();
	result += test_cross_format_ecdh_pem_der_share();
	result += test_cross_format_x25519_pem_der_share();
	result += test_cross_format_x25519_encrypted_pem_der_share();

	// ---------------------------------------------------------------------------
	// Save edge cases
	// ---------------------------------------------------------------------------
	result += test_save_to_missing_directory_fails();
	result += test_save_public_only_then_load_has_no_private();
	result += test_save_private_only_then_load_derives_public_and_encrypts();
	result += test_save_overwrite_same_base_name_still_usable();
	result += test_save_encrypted_empty_password_fails();
	result += test_save_encrypted_different_passwords_both_work();
	result += test_generate_invalid_bits_then_nothing_to_save();
	result += test_save_ecdh_round_trip_share();

	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}

	return result;
}
