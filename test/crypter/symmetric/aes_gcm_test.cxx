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

#include <StormByte/crypto/crypter/symmetric/aes_gcm.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/safe/vector.hxx>
#include <StormByte/test_handlers.h>

#include <cstdint>
#include <string_view>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;

// -------------------
// Round trip
// -------------------

int test_aes_gcm_encrypt_decrypt_consistency() {
	const StormByte::Safe::String original = "The quick brown fox jumps over the lazy dog";
	Password password("SecurePassword123!");
	Crypter::AES_GCM aes_gcm(password);
	FIFO encrypted_data;
	ASSERT_TRUE(aes_gcm.Encrypt(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(original.data()), static_cast<std::size_t>(original.size())), encrypted_data));
	ASSERT_FALSE(encrypted_data.Empty());
	FIFO decrypted_data;
	ASSERT_TRUE(aes_gcm.Decrypt(encrypted_data.Data(), decrypted_data));
	ASSERT_FALSE(decrypted_data.Empty());
	ASSERT_EQUAL(DeserializeString(decrypted_data.Data()), original);
	RETURN_TEST(0);
}

int test_aes_gcm_byte_input_ranges() {
	const std::string_view input = "AES-GCM byte input range";
	const StormByte::Safe::Vector<std::uint8_t> bytes(input.begin(), input.end());
	Password password("SecurePassword123!");
	Crypter::AES_GCM aes_gcm(password);
	FIFO encrypted;
	ASSERT_TRUE(aes_gcm.Encrypt(input, encrypted));
	FIFO decrypted;
	ASSERT_TRUE(aes_gcm.Decrypt(encrypted.Data(), decrypted));
	ASSERT_EQUAL(DeserializeString(decrypted.Data()), StormByte::Safe::String(input));
	FIFO span_encrypted;
	ASSERT_TRUE(aes_gcm.Encrypt(std::span<const std::uint8_t>(bytes), span_encrypted));
	FIFO span_decrypted;
	ASSERT_TRUE(aes_gcm.Decrypt(std::span<const std::byte>(span_encrypted.Data()), span_decrypted));
	ASSERT_EQUAL(DeserializeString(span_decrypted.Data()), StormByte::Safe::String(input));
	RETURN_TEST(0);
}

int test_aes_gcm_encryption_produces_different_content() {
	Password password("SecurePassword123!");
	const StormByte::Safe::String original_data = "Important data to encrypt";
	Crypter::AES_GCM aes_gcm(password);
	FIFO encrypted_data;
	ASSERT_TRUE(aes_gcm.Encrypt(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(original_data.data()), static_cast<std::size_t>(original_data.size())), encrypted_data));
	const StormByte::Safe::String encrypted_string = DeserializeString(encrypted_data.Data());
	ASSERT_FALSE(encrypted_string.empty());
	ASSERT_NOT_EQUAL(encrypted_string, original_data);
	RETURN_TEST(0);
}

// -------------------
// Authentication
// -------------------

int test_aes_gcm_wrong_password() {
	const StormByte::Safe::String original = "AES-GCM provides authenticated encryption";
	Password password("CorrectPassword");
	Password wrongPassword("WrongPassword");
	Crypter::AES_GCM aes_gcm(password);
	Crypter::AES_GCM wrongAESGCM(wrongPassword);
	FIFO encrypted_data;
	ASSERT_TRUE(aes_gcm.Encrypt(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(original.data()), static_cast<std::size_t>(original.size())), encrypted_data));
	FIFO unused;
	ASSERT_FALSE(wrongAESGCM.Decrypt(encrypted_data.Data(), unused));
	RETURN_TEST(0);
}

int test_aes_gcm_authentication_integrity() {
	const StormByte::Safe::String original = "Data integrity is crucial";
	Password password("MyPassword");
	Crypter::AES_GCM aes_gcm(password);
	FIFO encrypted_data;
	ASSERT_TRUE(aes_gcm.Encrypt(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(original.data()), static_cast<std::size_t>(original.size())), encrypted_data));
	StormByte::Safe::String corrupted = DeserializeString(encrypted_data.Data());
	if (corrupted.size() > 30)
		corrupted[30] = static_cast<char>(~corrupted[30]);
	FIFO corrupted_data;
	ASSERT_FALSE(aes_gcm.Decrypt(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(corrupted.data()), static_cast<std::size_t>(corrupted.size())), corrupted_data));
	RETURN_TEST(0);
}

int main() {
	int result = 0;

	// -------------------
	// Round trip
	// -------------------
	result += test_aes_gcm_encrypt_decrypt_consistency();
	result += test_aes_gcm_byte_input_ranges();
	result += test_aes_gcm_encryption_produces_different_content();

	// -------------------
	// Authentication
	// -------------------
	result += test_aes_gcm_wrong_password();
	result += test_aes_gcm_authentication_integrity();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
