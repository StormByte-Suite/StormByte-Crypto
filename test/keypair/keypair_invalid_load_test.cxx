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

#include <StormByte/crypto/keypair/dsa.hxx>
#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/keypair/rsa.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/safe/binary.hxx>
#include <StormByte/test_handlers.h>

#include <algorithm>
#include <filesystem>
#include <fstream>

using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;
namespace fs = std::filesystem;

#ifndef STORMBYTE_TEST_KEYS_DIR
#	error "STORMBYTE_TEST_KEYS_DIR must be defined by CMake"
#endif

static fs::path keys_dir() {
	const fs::path dir{STORMBYTE_TEST_KEYS_DIR};
	fs::create_directories(dir);
	return dir;
}

#ifdef STORMBYTE_TEST_KEYS_PASSWORD
static Password test_keys_password() {
	return Password(STORMBYTE_TEST_KEYS_PASSWORD);
}
#else
static Password test_keys_password() {
	return Password("StormByteTestPassphrase!");
}
#endif

// -------------------
// Garbage input
// -------------------

int test_load_directory_as_path_fails() {
	const auto dir = keys_dir() / "as_dir";
	fs::create_directories(dir);
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(dir)));
	RETURN_TEST(0);
}

int test_load_empty_file_fails() {
	const auto path = keys_dir() / "empty.pem";
	{
		std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
		ASSERT_TRUE(static_cast<bool>(ofs));
	}
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(path)));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(path, path)));
	RETURN_TEST(0);
}

int test_load_malformed_pem_header_fails() {
	const auto path = keys_dir() / "bad_pem.pem";
	{
		std::ofstream ofs(path);
		ofs << "-----BEGIN NOT A KEY-----\n"
			<< "YWJjZGVmZ2hpams=\n"
			<< "-----END NOT A KEY-----\n";
		ASSERT_TRUE(static_cast<bool>(ofs));
	}
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(path)));
	RETURN_TEST(0);
}

int test_load_nonexistent_path_fails() {
	const auto path = keys_dir() / "no_such_file.pem";
	ASSERT_FALSE(fs::exists(path));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(path)));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(path, path)));
	RETURN_TEST(0);
}

int test_load_pem_embedded_nul_fails() {
	const auto path = keys_dir() / "pem_nul.pem";
	const char malformed[] = "-----BEGIN PRIVATE\0 KEY-----\nYWJj\n-----END PRIVATE KEY-----\n";
	{
		std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
		ofs.write(malformed, static_cast<std::streamsize>(sizeof(malformed) - 1));
		ASSERT_TRUE(static_cast<bool>(ofs));
	}
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(path)));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(path, path)));
	RETURN_TEST(0);
}

int test_load_pem_invalid_base64_fails() {
	const auto path = keys_dir() / "pem_bad_b64.pem";
	{
		std::ofstream ofs(path);
		ofs << "-----BEGIN PRIVATE KEY-----\n"
			<< "@@@@not-valid-base64@@@@\n"
			<< "-----END PRIVATE KEY-----\n";
		ASSERT_TRUE(static_cast<bool>(ofs));
	}
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(path)));
	RETURN_TEST(0);
}

int test_load_pem_missing_end_fails() {
	const auto path = keys_dir() / "pem_no_end.pem";
	{
		std::ofstream ofs(path);
		ofs << "-----BEGIN PRIVATE KEY-----\n"
			<< "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7\n";
		ASSERT_TRUE(static_cast<bool>(ofs));
	}
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(path)));
	RETURN_TEST(0);
}

int test_load_random_garbage_fails() {
	const auto path = keys_dir() / "garbage.bin";
	{
		std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
		const char junk[] = "this-is-not-a-key\x00\x01\x02\xff";
		ofs.write(junk, static_cast<std::streamsize>(sizeof(junk) - 1));
		ASSERT_TRUE(static_cast<bool>(ofs));
	}
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(path)));
	RETURN_TEST(0);
}

// -------------------
// Truncated / mismatched
// -------------------

int test_load_encrypted_without_password_fails() {
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(kp));
	const auto out = keys_dir() / "enc_no_pass";
	fs::create_directories(out);
	ASSERT_TRUE(kp->Save(out, "rsa", test_keys_password()));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(out / "rsa.pub.pem", out / "rsa.pem")));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(out / "rsa.pem")));
	RETURN_TEST(0);
}

int test_load_mismatched_rsa_pub_dsa_priv_fails() {
	auto rsa = KeyPair::RSA::Generate(2048);
	auto dsa = KeyPair::DSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(rsa));
	ASSERT_TRUE(static_cast<bool>(dsa));
	const auto out = keys_dir() / "mismatch_rsa_dsa";
	fs::create_directories(out);
	ASSERT_TRUE(rsa->SavePublic(out / "rsa.pub.pem"));
	ASSERT_TRUE(dsa->SavePrivate(out / "dsa.pem"));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(out / "rsa.pub.pem", out / "dsa.pem")));
	RETURN_TEST(0);
}

int test_load_truncated_der_fails() {
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(kp));
	const auto out = keys_dir() / "trunc_der";
	fs::create_directories(out);
	ASSERT_TRUE(kp->Save(out, "rsa", KeyPair::StorageFormat::DER));
	const auto priv_path = out / "rsa.der";
	StormByte::Safe::Binary bytes;
	{
		std::ifstream ifs(priv_path, std::ios::binary);
		ASSERT_TRUE(static_cast<bool>(ifs));
		char byte;
		while (ifs.get(byte))
			bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(byte)));
		ASSERT_TRUE(ifs.eof());
	}
	ASSERT_FALSE(bytes.empty());
	bytes.resize(StormByte::ByteSize{std::min<size_t>(static_cast<size_t>(bytes.size()), 8)});
	const auto trunc_path = out / "rsa_trunc.der";
	{
		std::ofstream ofs(trunc_path, std::ios::binary | std::ios::trunc);
		ofs.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(static_cast<size_t>(bytes.size())));
		ASSERT_TRUE(static_cast<bool>(ofs));
	}
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(trunc_path)));
	ASSERT_FALSE(static_cast<bool>(KeyPair::Load(out / "rsa.pub.der", trunc_path)));
	RETURN_TEST(0);
}

int main() {
	fs::remove_all(keys_dir());
	fs::create_directories(keys_dir());
	int result = 0;

	// -------------------
	// Garbage input
	// -------------------
	result += test_load_directory_as_path_fails();
	result += test_load_empty_file_fails();
	result += test_load_malformed_pem_header_fails();
	result += test_load_nonexistent_path_fails();
	result += test_load_pem_embedded_nul_fails();
	result += test_load_pem_invalid_base64_fails();
	result += test_load_pem_missing_end_fails();
	result += test_load_random_garbage_fails();

	// -------------------
	// Truncated / mismatched
	// -------------------
	result += test_load_encrypted_without_password_fails();
	result += test_load_mismatched_rsa_pub_dsa_priv_fails();
	result += test_load_truncated_der_fails();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
