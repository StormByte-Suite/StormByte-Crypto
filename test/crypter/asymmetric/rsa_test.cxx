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
#include <StormByte/crypto/crypter/asymmetric/rsa.hxx>
#include <StormByte/test_handlers.h>

using StormByte::Buffer::FIFO;
using StormByte::Safe::String;
using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;

namespace {
	/**
	 * @brief Borrow the bytes of text without discarding embedded NUL characters.
	 * @param text Text whose storage must outlive the returned view.
	 * @return View of all text bytes.
	 */
	std::span<const std::byte> Bytes(const String& text) {
		return { reinterpret_cast<const std::byte*>(text.data()), static_cast<std::size_t>(text.size()) };
	}
}

// -------------------
// Native
// -------------------

int test_rsa_encrypt_decrypt(KeyPair::Generic::PointerType kp) {
	const String message = "This is a test message.";
	Crypter::RSA rsa(kp);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(rsa.Encrypt(Bytes(message), encrypted));
	ASSERT_TRUE(rsa.Decrypt(encrypted.Data().span(), decrypted));
	ASSERT_EQUAL(DeserializeString(decrypted.Data()), message);
	RETURN_TEST(0);
}

int test_rsa_encryption_produces_different_content(KeyPair::Generic::PointerType kp) {
	const String original = "Sensitive message";
	Crypter::RSA rsa(kp);
	FIFO encrypted;
	ASSERT_TRUE(rsa.Encrypt(Bytes(original), encrypted));
	ASSERT_NOT_EQUAL(DeserializeString(encrypted.Data()), original);
	RETURN_TEST(0);
}

int test_rsa_encrypt_decrypt_using_consumer_producer(KeyPair::Generic::PointerType kp) {
	const String input = "This is some data to encrypt using the Consumer/Producer model.";
	Crypter::RSA rsa(kp);
	StormByte::Buffer::Producer producer;
	producer.Write(static_cast<std::string_view>(input));
	producer.Close();
	auto encrypted = rsa.Encrypt(producer.Consumer());
	auto decrypted = rsa.Decrypt(encrypted);
	auto data = ReadAllFromConsumer(decrypted);
	ASSERT_FALSE(data.Empty());
	ASSERT_EQUAL(input, DeserializeString(data));
	RETURN_TEST(0);
}

int test_rsa_encrypt_decrypt_native_explicit(KeyPair::Generic::PointerType kp) {
	const String message = "Explicit Native strategy round-trip for RSA.";
	Crypter::RSA rsa(kp);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(rsa.Encrypt(Bytes(message), encrypted, Crypter::Asymmetric::Strategy::Native));
	ASSERT_FALSE(encrypted.Empty());
	ASSERT_TRUE(rsa.Decrypt(encrypted.Data().span(), decrypted));
	ASSERT_EQUAL(DeserializeString(decrypted.Data()), message);
	RETURN_TEST(0);
}

int test_rsa_encrypt_decrypt_native_explicit_streaming(KeyPair::Generic::PointerType kp) {
	const String input = "Native explicit streaming with auto-detect decrypt (RSA).";
	Crypter::RSA rsa(kp);
	StormByte::Buffer::Producer producer;
	producer.Write(static_cast<std::string_view>(input));
	producer.Close();
	auto encrypted = rsa.Encrypt(producer.Consumer(), Crypter::Asymmetric::Strategy::Native);
	auto decrypted = rsa.Decrypt(encrypted);
	auto data = ReadAllFromConsumer(decrypted);
	ASSERT_FALSE(data.Empty());
	ASSERT_EQUAL(input, DeserializeString(data));
	RETURN_TEST(0);
}

// -------------------
// Hybrid
// -------------------

int test_rsa_encrypt_decrypt_hybrid(KeyPair::Generic::PointerType kp) {
	const String message = "This is a hybrid envelope test message for RSA.";
	Crypter::RSA rsa(kp);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(rsa.Encrypt(Bytes(message), encrypted, Crypter::Asymmetric::Strategy::Hybrid));
	ASSERT_FALSE(encrypted.Empty());
	ASSERT_TRUE(rsa.Decrypt(encrypted.Data().span(), decrypted));
	ASSERT_EQUAL(DeserializeString(decrypted.Data()), message);
	RETURN_TEST(0);
}

int test_rsa_encrypt_decrypt_hybrid_streaming(KeyPair::Generic::PointerType kp) {
	const String input = "This is some data to encrypt using Hybrid envelope with Consumer/Producer model (RSA).";
	Crypter::RSA rsa(kp);
	StormByte::Buffer::Producer producer;
	producer.Write(static_cast<std::string_view>(input));
	producer.Close();
	auto encrypted = rsa.Encrypt(producer.Consumer(), Crypter::Asymmetric::Strategy::Hybrid);
	auto decrypted = rsa.Decrypt(encrypted);
	auto data = ReadAllFromConsumer(decrypted);
	ASSERT_FALSE(data.Empty());
	ASSERT_EQUAL(input, DeserializeString(data));
	RETURN_TEST(0);
}

int test_rsa_hybrid_vs_native_different_output(KeyPair::Generic::PointerType kp) {
	const String message = "Same message for both modes";
	Crypter::RSA rsa(kp);
	FIFO native_encrypted, hybrid_encrypted;
	ASSERT_TRUE(rsa.Encrypt(Bytes(message), native_encrypted, Crypter::Asymmetric::Strategy::Native));
	ASSERT_TRUE(rsa.Encrypt(Bytes(message), hybrid_encrypted, Crypter::Asymmetric::Strategy::Hybrid));
	ASSERT_NOT_EQUAL(DeserializeString(native_encrypted.Data()), DeserializeString(hybrid_encrypted.Data()));
	RETURN_TEST(0);
}

// -------------------
// Failure modes
// -------------------

int test_rsa_decryption_with_corrupted_data(KeyPair::Generic::PointerType kp) {
	const String message = "Important message!";
	Crypter::RSA rsa(kp);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(rsa.Encrypt(Bytes(message), encrypted));
	auto corrupted = DeserializeString(encrypted.Data());
	ASSERT_FALSE(corrupted.empty());
	corrupted[0] = static_cast<char>(~corrupted[0]);
	ASSERT_FALSE(rsa.Decrypt(Bytes(corrupted), decrypted));
	RETURN_TEST(0);
}

int test_rsa_decrypt_with_mismatched_key(KeyPair::Generic::PointerType kp) {
	const String message = "Sensitive message.";
	Crypter::RSA rsa(kp);
	auto kp2 = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(kp2));
	Crypter::RSA rsa2(kp2);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(rsa.Encrypt(Bytes(message), encrypted));
	ASSERT_FALSE(rsa2.Decrypt(encrypted.Data().span(), decrypted));
	RETURN_TEST(0);
}

int test_rsa_with_corrupted_keys(KeyPair::Generic::PointerType kp) {
	const String message = "This is a test message.";
	Crypter::RSA rsa(kp);
	String corrupted_public { std::string_view{kp->PublicKey()} };
	if (!corrupted_public.empty())
		corrupted_public[0] = static_cast<char>(~corrupted_public[0]);
	auto badKp = KeyPair::RSA::MakePointer<KeyPair::RSA>(
		std::move(corrupted_public),
		Password("not-a-valid-rsa-private-key")
	);
	Crypter::RSA corrupted_rsa(badKp);
	FIFO encrypted;
	ASSERT_FALSE(corrupted_rsa.Encrypt(Bytes(message), encrypted));
	FIFO encrypted_valid, decrypted;
	ASSERT_TRUE(rsa.Encrypt(Bytes(message), encrypted_valid));
	ASSERT_FALSE(corrupted_rsa.Decrypt(encrypted_valid.Data().span(), decrypted));
	RETURN_TEST(0);
}

int test_rsa_corrupted_hybrid_envelope_fails(KeyPair::Generic::PointerType kp) {
	const String message = "Hybrid envelope that will be corrupted.";
	Crypter::RSA rsa(kp);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(rsa.Encrypt(Bytes(message), encrypted, Crypter::Asymmetric::Strategy::Hybrid));
	auto corrupted = DeserializeString(encrypted.Data());
	ASSERT_FALSE(corrupted.empty());
	const auto corrupted_size = static_cast<std::size_t>(corrupted.size());
	if (corrupted_size > 8) {
		corrupted[0] = static_cast<char>(~corrupted[0]);
		corrupted[corrupted_size / 3] = static_cast<char>(corrupted[corrupted_size / 3] ^ 0x5A);
		corrupted[corrupted_size - 1] = static_cast<char>(~corrupted[corrupted_size - 1]);
	}
	else
		corrupted[0] = static_cast<char>(~corrupted[0]);
	ASSERT_FALSE(rsa.Decrypt(Bytes(corrupted), decrypted));
	RETURN_TEST(0);
}

int test_rsa_corrupted_native_fails_auto_detect(KeyPair::Generic::PointerType kp) {
	const String message = "Native ciphertext that will be corrupted.";
	Crypter::RSA rsa(kp);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(rsa.Encrypt(Bytes(message), encrypted, Crypter::Asymmetric::Strategy::Native));
	auto corrupted = DeserializeString(encrypted.Data());
	ASSERT_FALSE(corrupted.empty());
	corrupted[0] = static_cast<char>(~corrupted[0]);
	const auto corrupted_size = static_cast<std::size_t>(corrupted.size());
	if (corrupted_size > 2)
		corrupted[corrupted_size / 2] = static_cast<char>(corrupted[corrupted_size / 2] ^ 0xFF);
	ASSERT_FALSE(rsa.Decrypt(Bytes(corrupted), decrypted));
	RETURN_TEST(0);
}

int test_rsa_hybrid_decrypt_with_mismatched_key(KeyPair::Generic::PointerType kp) {
	const String message = "Hybrid ciphertext, wrong private key.";
	Crypter::RSA rsa(kp);
	auto kp2 = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(kp2));
	Crypter::RSA rsa2(kp2);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(rsa.Encrypt(Bytes(message), encrypted, Crypter::Asymmetric::Strategy::Hybrid));
	ASSERT_FALSE(rsa2.Decrypt(encrypted.Data().span(), decrypted));
	RETURN_TEST(0);
}

int main() {
	auto kp = KeyPair::RSA::Generate(2048);
	if (!kp) {
		std::cerr << "Failed to generate RSA asymmetric keypair" << std::endl;
		return 1;
	}
	int result = 0;

	// -------------------
	// Native
	// -------------------
	result += test_rsa_encrypt_decrypt(kp);
	result += test_rsa_encryption_produces_different_content(kp);
	result += test_rsa_encrypt_decrypt_using_consumer_producer(kp);
	result += test_rsa_encrypt_decrypt_native_explicit(kp);
	result += test_rsa_encrypt_decrypt_native_explicit_streaming(kp);

	// -------------------
	// Hybrid
	// -------------------
	result += test_rsa_encrypt_decrypt_hybrid(kp);
	result += test_rsa_encrypt_decrypt_hybrid_streaming(kp);
	result += test_rsa_hybrid_vs_native_different_output(kp);

	// -------------------
	// Failure modes
	// -------------------
	result += test_rsa_decryption_with_corrupted_data(kp);
	result += test_rsa_decrypt_with_mismatched_key(kp);
	result += test_rsa_with_corrupted_keys(kp);
	result += test_rsa_corrupted_hybrid_envelope_fails(kp);
	result += test_rsa_corrupted_native_fails_auto_detect(kp);
	result += test_rsa_hybrid_decrypt_with_mismatched_key(kp);

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
