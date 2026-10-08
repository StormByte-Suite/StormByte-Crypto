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

#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/crypter/symmetric/aes.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/test_handlers.h>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;

// -------------------
// Empty
// -------------------

int test_aes_empty_round_trip() {
	Crypter::AES aes(Password("SecurePassword123!"));
	FIFO encrypted;
	ASSERT_TRUE(aes.Encrypt(StormByte::Safe::Binary{}.span(), encrypted));
	FIFO decrypted;
	ASSERT_TRUE(aes.Decrypt(encrypted.Data().span(), decrypted));
	ASSERT_TRUE(decrypted.Empty());
	RETURN_TEST(0);
}

// -------------------
// Failure modes
// -------------------

int test_aes_decryption_with_corrupted_data() {
	Password password("StrongPassword123!");
	const StormByte::Safe::Binary original_data("Important confidential data");
	Crypter::AES aes(password);
	FIFO encrypted_data;
	ASSERT_TRUE(aes.Encrypt(original_data.span(), encrypted_data));
	auto corrupted = encrypted_data.Data();
	ASSERT_FALSE(corrupted.empty());
	if (static_cast<std::size_t>(corrupted.size()) > 33) {
		corrupted.back() = ~corrupted.back();
		corrupted[StormByte::ByteSize{static_cast<std::size_t>(corrupted.size()) - 2}] =
			~corrupted[StormByte::ByteSize{static_cast<std::size_t>(corrupted.size()) - 2}];
	}
	else
		corrupted.front() = ~corrupted.front();
	FIFO corrupted_data;
	(void)aes.Decrypt(corrupted.span(), corrupted_data);
	ASSERT_NOT_EQUAL(original_data, corrupted_data.Data());
	RETURN_TEST(0);
}

int test_aes_truncated_ciphertext() {
	Crypter::AES aes(Password("SecurePassword123!"));
	FIFO decrypted;
	ASSERT_FALSE(aes.Decrypt(StormByte::Safe::Binary("short").span(), decrypted));
	ASSERT_TRUE(decrypted.Empty());
	RETURN_TEST(0);
}

int test_aes_wrong_decryption_password() {
	Crypter::AES aes(Password("SecurePassword123!"));
	Crypter::AES aes_wrong(Password("WrongPassword456!"));
	const StormByte::Safe::Binary original_data("This is sensitive data.");
	FIFO encrypted_data;
	ASSERT_TRUE(aes.Encrypt(original_data.span(), encrypted_data));
	ASSERT_FALSE(encrypted_data.Empty());
	FIFO decrypted;
	(void)aes_wrong.Decrypt(encrypted_data.Data().span(), decrypted);
	ASSERT_NOT_EQUAL(original_data, decrypted.Data());
	RETURN_TEST(0);
}

// -------------------
// Reuse
// -------------------

int test_aes_reuse_after_failure() {
	Crypter::AES aes(Password("SecurePassword123!"));
	FIFO rejected;
	ASSERT_FALSE(aes.Decrypt(StormByte::Safe::Binary{}.span(), rejected));
	const StormByte::Safe::Binary input("valid after failure");
	for (int iteration = 0; iteration < 2; ++iteration) {
		FIFO encrypted;
		ASSERT_TRUE(aes.Encrypt(input.span(), encrypted));
		FIFO decrypted;
		ASSERT_TRUE(aes.Decrypt(encrypted.Data().span(), decrypted));
		ASSERT_EQUAL(input, decrypted.Data());
	}
	RETURN_TEST(0);
}

// -------------------
// Round trip
// -------------------

int test_aes_encrypt_decrypt_consistency() {
	Crypter::AES aes(Password("SecurePassword123!"));
	const StormByte::Safe::Binary original_data("Confidential information to encrypt and decrypt.");
	FIFO encrypted;
	ASSERT_TRUE(aes.Encrypt(original_data.span(), encrypted));
	ASSERT_FALSE(encrypted.Empty());
	FIFO decrypted;
	ASSERT_TRUE(aes.Decrypt(encrypted.Data().span(), decrypted));
	ASSERT_EQUAL(original_data, decrypted.Data());
	RETURN_TEST(0);
}

int test_aes_encryption_produces_different_content() {
	Crypter::AES aes(Password("SecurePassword123!"));
	const StormByte::Safe::Binary original_data("Important data to encrypt");
	FIFO encrypted;
	ASSERT_TRUE(aes.Encrypt(original_data.span(), encrypted));
	ASSERT_FALSE(encrypted.Empty());
	ASSERT_NOT_EQUAL(original_data, encrypted.Data());
	RETURN_TEST(0);
}

// -------------------
// Stream
// -------------------

int test_aes_empty_stream() {
	Crypter::AES aes(Password("SecurePassword123!"));
	StormByte::Buffer::Producer producer;
	producer.Close();
	auto encrypted = aes.Encrypt(producer.Consumer());
	auto decrypted = aes.Decrypt(encrypted);
	ASSERT_TRUE(ReadAllFromConsumer(decrypted).Empty());
	RETURN_TEST(0);
}

int test_aes_encrypt_decrypt_using_consumer_producer() {
	const StormByte::Safe::String input_data = "This is some data to encrypt using the Consumer/Producer model.";
	Password password("SecurePassword123!");
	Crypter::AES aes(password);
	StormByte::Buffer::Producer producer;
	producer.Write(static_cast<std::string_view>(input_data));
	producer.Close();
	auto encrypted_consumer = aes.Encrypt(producer.Consumer());
	ASSERT_TRUE(encrypted_consumer.IsWritable() || !encrypted_consumer.Empty());
	auto decrypted_consumer = aes.Decrypt(encrypted_consumer);
	ASSERT_TRUE(decrypted_consumer.IsWritable() || !decrypted_consumer.Empty());
	ASSERT_EQUAL(input_data, DeserializeString(ReadAllFromConsumer(decrypted_consumer)));
	RETURN_TEST(0);
}

int main() {
	int result = 0;

	// -------------------
	// Empty
	// -------------------
	result += test_aes_empty_round_trip();

	// -------------------
	// Failure modes
	// -------------------
	result += test_aes_decryption_with_corrupted_data();
	result += test_aes_truncated_ciphertext();
	result += test_aes_wrong_decryption_password();

	// -------------------
	// Reuse
	// -------------------
	result += test_aes_reuse_after_failure();

	// -------------------
	// Round trip
	// -------------------
	result += test_aes_encrypt_decrypt_consistency();
	result += test_aes_encryption_produces_different_content();

	// -------------------
	// Stream
	// -------------------
	result += test_aes_empty_stream();
	result += test_aes_encrypt_decrypt_using_consumer_producer();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
