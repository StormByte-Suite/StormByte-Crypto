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
#include <StormByte/crypto/crypter/symmetric/camellia.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/test_handlers.h>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;
using StormByte::Safe::Binary;
using StormByte::Safe::String;

// -------------------
// Failure modes
// -------------------

int test_camellia_decryption_with_corrupted_data() {
	Password password("StrongPassword123!");
	const String original_data = "Important confidential data";
	Crypter::Camellia camellia(password);
	FIFO encrypted_data;
	ASSERT_TRUE(camellia.Encrypt(std::as_bytes(std::span<const char>(original_data.data(),
		static_cast<std::size_t>(original_data.size()))), encrypted_data));
	Binary corrupted_data = encrypted_data.Data();
	ASSERT_FALSE(corrupted_data.empty());
	const auto count = static_cast<std::size_t>(corrupted_data.size());
	if (count > 33) {
		corrupted_data[StormByte::ByteSize{count - 1}] ^= std::byte{0xff};
		corrupted_data[StormByte::ByteSize{count - 2}] ^= std::byte{0xff};
	}
	else
		corrupted_data[StormByte::ByteSize{0}] ^= std::byte{0xff};
	FIFO decrypted_data;
	(void)camellia.Decrypt(static_cast<std::span<const std::byte>>(corrupted_data), decrypted_data);
	ASSERT_NOT_EQUAL(DeserializeString(decrypted_data.Data()), original_data);
	RETURN_TEST(0);
}

int test_camellia_empty_ciphertext() {
	Password password("SecurePassword123!");
	Crypter::Camellia camellia(password);
	FIFO decrypted_data;
	ASSERT_FALSE(camellia.Decrypt(std::span<const std::byte>{}, decrypted_data));
	ASSERT_TRUE(decrypted_data.Empty());
	RETURN_TEST(0);
}

int test_camellia_truncated_ciphertext() {
	Password password("SecurePassword123!");
	Crypter::Camellia camellia(password);
	const Binary short_header(StormByte::ByteSize{1}, std::byte{0});
	FIFO decrypted_data;
	ASSERT_FALSE(camellia.Decrypt(static_cast<std::span<const std::byte>>(short_header), decrypted_data));
	ASSERT_TRUE(decrypted_data.Empty());
	const Binary original("A message with complete CBC blocks and padding.");
	FIFO encrypted_data;
	ASSERT_TRUE(camellia.Encrypt(static_cast<std::span<const std::byte>>(original), encrypted_data));
	Binary truncated = encrypted_data.Data();
	truncated.resize(truncated.size() - StormByte::ByteSize{1});
	ASSERT_FALSE(camellia.Decrypt(static_cast<std::span<const std::byte>>(truncated), decrypted_data));
	RETURN_TEST(0);
}

int test_camellia_wrong_decryption_password() {
	Password password("SecurePassword123!");
	Password wrong_password("WrongPassword456!");
	const String original_data = "This is sensitive data.";
	Crypter::Camellia camellia(password);
	Crypter::Camellia camellia_wrong(wrong_password);
	FIFO encrypted_data;
	ASSERT_TRUE(camellia.Encrypt(std::as_bytes(std::span<const char>(original_data.data(),
		static_cast<std::size_t>(original_data.size()))), encrypted_data));
	const String encrypted_string = DeserializeString(encrypted_data.Data());
	ASSERT_FALSE(encrypted_string.empty());
	FIFO decrypted_d;
	(void)camellia_wrong.Decrypt(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(encrypted_string.data()), static_cast<std::size_t>(encrypted_string.size())), decrypted_d);
	ASSERT_NOT_EQUAL(DeserializeString(decrypted_d.Data()), original_data);
	RETURN_TEST(0);
}

// -------------------
// Reuse
// -------------------

int test_camellia_reuse_after_failure() {
	Password password("SecurePassword123!");
	Crypter::Camellia camellia(password);
	FIFO rejected;
	ASSERT_FALSE(camellia.Decrypt(std::span<const std::byte>{}, rejected));
	const Binary original("Repeated calls must use independent cipher state.");
	Binary previous;
	for (int attempt = 0; attempt < 2; ++attempt) {
		FIFO encrypted_data;
		ASSERT_TRUE(camellia.Encrypt(static_cast<std::span<const std::byte>>(original), encrypted_data));
		const Binary ciphertext = encrypted_data.Data();
		ASSERT_NOT_EQUAL(previous, ciphertext);
		FIFO decrypted_data;
		ASSERT_TRUE(camellia.Decrypt(static_cast<std::span<const std::byte>>(ciphertext), decrypted_data));
		ASSERT_EQUAL(original, decrypted_data.Data());
		previous = ciphertext;
	}
	RETURN_TEST(0);
}

// -------------------
// Round trip
// -------------------

int test_camellia_empty_plaintext() {
	Password password("SecurePassword123!");
	Crypter::Camellia camellia(password);
	FIFO encrypted_data;
	ASSERT_TRUE(camellia.Encrypt(std::span<const std::byte>{}, encrypted_data));
	ASSERT_FALSE(encrypted_data.Empty());
	FIFO decrypted_data;
	ASSERT_TRUE(camellia.Decrypt(static_cast<std::span<const std::byte>>(encrypted_data.Data()), decrypted_data));
	ASSERT_TRUE(decrypted_data.Empty());
	RETURN_TEST(0);
}

int test_camellia_encrypt_decrypt_consistency() {
	Password password("SecurePassword123!");
	const String original_data = "Confidential information to encrypt and decrypt.";
	Crypter::Camellia camellia(password);
	FIFO encrypted_data;
	ASSERT_TRUE(camellia.Encrypt(std::as_bytes(std::span<const char>(original_data.data(),
		static_cast<std::size_t>(original_data.size()))), encrypted_data));
	const String encrypted_string = DeserializeString(encrypted_data.Data());
	ASSERT_FALSE(encrypted_string.empty());
	FIFO decrypted_d;
	ASSERT_TRUE(camellia.Decrypt(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(encrypted_string.data()), static_cast<std::size_t>(encrypted_string.size())), decrypted_d));
	ASSERT_EQUAL(DeserializeString(decrypted_d.Data()), original_data);
	RETURN_TEST(0);
}

int test_camellia_encryption_produces_different_content() {
	Password password("SecurePassword123!");
	const String original_data = "Important data to encrypt";
	Crypter::Camellia camellia(password);
	FIFO encrypted_data;
	ASSERT_TRUE(camellia.Encrypt(std::as_bytes(std::span<const char>(original_data.data(),
		static_cast<std::size_t>(original_data.size()))), encrypted_data));
	const String encrypted_string = DeserializeString(encrypted_data.Data());
	ASSERT_FALSE(encrypted_string.empty());
	ASSERT_NOT_EQUAL(encrypted_string, original_data);
	RETURN_TEST(0);
}

// -------------------
// Stream
// -------------------

int test_camellia_encrypt_decrypt_using_consumer_producer() {
	const String input_data = "This is some data to encrypt using the Consumer/Producer model.";
	Password password("SecurePassword123!");
	Crypter::Camellia camellia(password);
	StormByte::Buffer::Producer producer;
	ASSERT_TRUE(producer.Write(static_cast<std::string_view>(input_data)));
	producer.Close();
	auto encrypted_consumer = camellia.Encrypt(producer.Consumer());
	ASSERT_TRUE(encrypted_consumer.IsWritable() || !encrypted_consumer.Empty());
	auto decrypted_consumer = camellia.Decrypt(encrypted_consumer);
	ASSERT_TRUE(decrypted_consumer.IsWritable() || !decrypted_consumer.Empty());
	ASSERT_EQUAL(input_data, DeserializeString(ReadAllFromConsumer(decrypted_consumer)));
	RETURN_TEST(0);
}

int test_camellia_stream_binary_chunks() {
	Password password("SecurePassword123!");
	Crypter::Camellia camellia(password);
	Binary input(StormByte::ByteSize{8193}, std::byte{0x80});
	input[StormByte::ByteSize{0}] = std::byte{0};
	input[StormByte::ByteSize{4096}] = std::byte{0xff};
	const auto bytes = static_cast<std::span<const std::byte>>(input);
	StormByte::Buffer::Producer producer;
	ASSERT_TRUE(producer.Write(bytes.first(1)));
	ASSERT_TRUE(producer.Write(bytes.subspan(1, 4095)));
	ASSERT_TRUE(producer.Write(bytes.subspan(4096)));
	producer.Close();
	auto decrypted = camellia.Decrypt(camellia.Encrypt(producer.Consumer()));
	const FIFO output = ReadAllFromConsumer(decrypted);
	ASSERT_EQUAL(input, output.Data());
	RETURN_TEST(0);
}

int test_camellia_stream_empty_plaintext() {
	Password password("SecurePassword123!");
	Crypter::Camellia camellia(password);
	StormByte::Buffer::Producer producer;
	producer.Close();
	const FIFO encrypted = ReadAllFromConsumer(camellia.Encrypt(producer.Consumer()));
	ASSERT_FALSE(encrypted.Empty());
	StormByte::Buffer::Producer ciphertext;
	ASSERT_TRUE(ciphertext.Write(encrypted.Data()));
	ciphertext.Close();
	const FIFO decrypted = ReadAllFromConsumer(camellia.Decrypt(ciphertext.Consumer()));
	ASSERT_TRUE(decrypted.Empty());
	RETURN_TEST(0);
}

int test_camellia_stream_truncated_header() {
	Password password("SecurePassword123!");
	Crypter::Camellia camellia(password);
	StormByte::Buffer::Producer producer;
	ASSERT_TRUE(producer.Write(Binary{std::byte{0}}));
	producer.Close();
	const FIFO decrypted = ReadAllFromConsumer(camellia.Decrypt(producer.Consumer()));
	ASSERT_TRUE(decrypted.Empty());
	RETURN_TEST(0);
}

int main() {
	int result = 0;

	// -------------------
	// Failure modes
	// -------------------
	result += test_camellia_decryption_with_corrupted_data();
	result += test_camellia_empty_ciphertext();
	result += test_camellia_truncated_ciphertext();
	result += test_camellia_wrong_decryption_password();

	// -------------------
	// Reuse
	// -------------------
	result += test_camellia_reuse_after_failure();

	// -------------------
	// Round trip
	// -------------------
	result += test_camellia_empty_plaintext();
	result += test_camellia_encrypt_decrypt_consistency();
	result += test_camellia_encryption_produces_different_content();

	// -------------------
	// Stream
	// -------------------
	result += test_camellia_encrypt_decrypt_using_consumer_producer();
	result += test_camellia_stream_binary_chunks();
	result += test_camellia_stream_empty_plaintext();
	result += test_camellia_stream_truncated_header();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
