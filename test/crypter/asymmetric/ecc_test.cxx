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
#include <StormByte/crypto/crypter/asymmetric/ecc.hxx>
#include <StormByte/test_handlers.h>

using StormByte::Buffer::FIFO;
using StormByte::Safe::String;
using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;

namespace {
	/**
	 * @brief Curve size used to generate test key pairs.
	 */
	constexpr unsigned short CurveBits = 256;

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

int test_ecc_encrypt_decrypt() {
	const String message = "This is a test message.";
	auto kp = KeyPair::ECC::Generate(CurveBits);
	ASSERT_TRUE(static_cast<bool>(kp));
	Crypter::ECC ecc(kp);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(ecc.Encrypt(Bytes(message), encrypted));
	ASSERT_TRUE(ecc.Decrypt(encrypted.Data().span(), decrypted));
	ASSERT_EQUAL(DeserializeString(decrypted.Data()), message);
	RETURN_TEST(0);
}

int test_ecc_encryption_produces_different_content() {
	const String original = "ECC test message";
	auto kp = KeyPair::ECC::Generate(CurveBits);
	ASSERT_TRUE(static_cast<bool>(kp));
	Crypter::ECC ecc(kp);
	FIFO encrypted;
	ASSERT_TRUE(ecc.Encrypt(Bytes(original), encrypted));
	ASSERT_NOT_EQUAL(original, DeserializeString(encrypted.Data()));
	RETURN_TEST(0);
}

int test_ecc_encrypt_decrypt_using_consumer_producer() {
	const String input = "This is some data to encrypt using the Consumer/Producer model.";
	auto kp = KeyPair::ECC::Generate(CurveBits);
	ASSERT_TRUE(static_cast<bool>(kp));
	Crypter::ECC ecc(kp);
	StormByte::Buffer::Producer producer;
	producer.Write(static_cast<std::string_view>(input));
	producer.Close();
	auto encrypted = ecc.Encrypt(producer.Consumer());
	auto decrypted = ecc.Decrypt(encrypted);
	auto data = ReadAllFromConsumer(decrypted);
	ASSERT_FALSE(data.Empty());
	ASSERT_EQUAL(input, DeserializeString(data));
	RETURN_TEST(0);
}

int test_ecc_encrypt_decrypt_native_explicit() {
	const String message = "Explicit Native strategy round-trip for ECC.";
	auto kp = KeyPair::ECC::Generate(CurveBits);
	ASSERT_TRUE(static_cast<bool>(kp));
	Crypter::ECC ecc(kp);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(ecc.Encrypt(Bytes(message), encrypted, Crypter::Asymmetric::Strategy::Native));
	ASSERT_FALSE(encrypted.Empty());
	ASSERT_TRUE(ecc.Decrypt(encrypted.Data().span(), decrypted));
	ASSERT_EQUAL(DeserializeString(decrypted.Data()), message);
	RETURN_TEST(0);
}

int test_ecc_encrypt_decrypt_native_explicit_streaming() {
	const String input = "Native explicit streaming with auto-detect decrypt.";
	auto kp = KeyPair::ECC::Generate(CurveBits);
	ASSERT_TRUE(static_cast<bool>(kp));
	Crypter::ECC ecc(kp);
	StormByte::Buffer::Producer producer;
	producer.Write(static_cast<std::string_view>(input));
	producer.Close();
	auto encrypted = ecc.Encrypt(producer.Consumer(), Crypter::Asymmetric::Strategy::Native);
	auto decrypted = ecc.Decrypt(encrypted);
	auto data = ReadAllFromConsumer(decrypted);
	ASSERT_FALSE(data.Empty());
	ASSERT_EQUAL(input, DeserializeString(data));
	RETURN_TEST(0);
}

// -------------------
// Hybrid
// -------------------

int test_ecc_encrypt_decrypt_hybrid() {
	const String message = "This is a hybrid envelope test message for ECC.";
	auto kp = KeyPair::ECC::Generate(CurveBits);
	ASSERT_TRUE(static_cast<bool>(kp));
	Crypter::ECC ecc(kp);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(ecc.Encrypt(Bytes(message), encrypted, Crypter::Asymmetric::Strategy::Hybrid));
	ASSERT_FALSE(encrypted.Empty());
	ASSERT_TRUE(ecc.Decrypt(encrypted.Data().span(), decrypted));
	ASSERT_EQUAL(DeserializeString(decrypted.Data()), message);
	RETURN_TEST(0);
}

int test_ecc_encrypt_decrypt_hybrid_streaming() {
	const String input = "This is some data to encrypt using Hybrid envelope with Consumer/Producer model.";
	auto kp = KeyPair::ECC::Generate(CurveBits);
	ASSERT_TRUE(static_cast<bool>(kp));
	Crypter::ECC ecc(kp);
	StormByte::Buffer::Producer producer;
	producer.Write(static_cast<std::string_view>(input));
	producer.Close();
	auto encrypted = ecc.Encrypt(producer.Consumer(), Crypter::Asymmetric::Strategy::Hybrid);
	auto decrypted = ecc.Decrypt(encrypted);
	auto data = ReadAllFromConsumer(decrypted);
	ASSERT_FALSE(data.Empty());
	ASSERT_EQUAL(input, DeserializeString(data));
	RETURN_TEST(0);
}

int test_ecc_hybrid_vs_native_different_output() {
	const String message = "Same message for both modes";
	auto kp = KeyPair::ECC::Generate(CurveBits);
	ASSERT_TRUE(static_cast<bool>(kp));
	Crypter::ECC ecc(kp);
	FIFO native_encrypted, hybrid_encrypted;
	ASSERT_TRUE(ecc.Encrypt(Bytes(message), native_encrypted, Crypter::Asymmetric::Strategy::Native));
	ASSERT_TRUE(ecc.Encrypt(Bytes(message), hybrid_encrypted, Crypter::Asymmetric::Strategy::Hybrid));
	ASSERT_NOT_EQUAL(DeserializeString(native_encrypted.Data()), DeserializeString(hybrid_encrypted.Data()));
	RETURN_TEST(0);
}

// -------------------
// Failure modes
// -------------------

int test_ecc_decryption_with_corrupted_data() {
	const String message = "Important message!";
	auto kp = KeyPair::ECC::Generate(CurveBits);
	ASSERT_TRUE(static_cast<bool>(kp));
	Crypter::ECC ecc(kp);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(ecc.Encrypt(Bytes(message), encrypted));
	auto corrupted = DeserializeString(encrypted.Data());
	ASSERT_FALSE(corrupted.empty());
	corrupted[0] = static_cast<char>(~corrupted[0]);
	ASSERT_FALSE(ecc.Decrypt(Bytes(corrupted), decrypted));
	RETURN_TEST(0);
}

int test_ecc_decrypt_with_mismatched_key() {
	const String message = "Sensitive message.";
	auto kp = KeyPair::ECC::Generate(CurveBits);
	auto kp2 = KeyPair::ECC::Generate(CurveBits);
	ASSERT_TRUE(static_cast<bool>(kp));
	ASSERT_TRUE(static_cast<bool>(kp2));
	Crypter::ECC ecc(kp);
	Crypter::ECC ecc2(kp2);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(ecc.Encrypt(Bytes(message), encrypted));
	ASSERT_FALSE(ecc2.Decrypt(encrypted.Data().span(), decrypted));
	RETURN_TEST(0);
}

int test_ecc_with_corrupted_keys() {
	const String message = "This is a test message.";
	auto kp = KeyPair::ECC::Generate(CurveBits);
	ASSERT_TRUE(static_cast<bool>(kp));
	String corrupted_public { std::string_view{kp->PublicKey()} };
	if (!corrupted_public.empty())
		corrupted_public[0] = static_cast<char>(~corrupted_public[0]);
	auto badKp = KeyPair::ECC::MakePointer<KeyPair::ECC>(
		std::move(corrupted_public),
		Password("not-a-valid-ecc-private-key")
	);
	Crypter::ECC ecc(badKp);
	FIFO encrypted;
	ASSERT_FALSE(ecc.Encrypt(Bytes(message), encrypted));
	RETURN_TEST(0);
}

int test_ecc_corrupted_hybrid_envelope_fails() {
	const String message = "Hybrid envelope that will be corrupted.";
	auto kp = KeyPair::ECC::Generate(CurveBits);
	ASSERT_TRUE(static_cast<bool>(kp));
	Crypter::ECC ecc(kp);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(ecc.Encrypt(Bytes(message), encrypted, Crypter::Asymmetric::Strategy::Hybrid));
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
	ASSERT_FALSE(ecc.Decrypt(Bytes(corrupted), decrypted));
	RETURN_TEST(0);
}

int test_ecc_corrupted_native_fails_auto_detect() {
	const String message = "Native ciphertext that will be corrupted.";
	auto kp = KeyPair::ECC::Generate(CurveBits);
	ASSERT_TRUE(static_cast<bool>(kp));
	Crypter::ECC ecc(kp);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(ecc.Encrypt(Bytes(message), encrypted, Crypter::Asymmetric::Strategy::Native));
	auto corrupted = DeserializeString(encrypted.Data());
	ASSERT_FALSE(corrupted.empty());
	corrupted[0] = static_cast<char>(~corrupted[0]);
	const auto corrupted_size = static_cast<std::size_t>(corrupted.size());
	if (corrupted_size > 2)
		corrupted[corrupted_size / 2] = static_cast<char>(corrupted[corrupted_size / 2] ^ 0xFF);
	ASSERT_FALSE(ecc.Decrypt(Bytes(corrupted), decrypted));
	RETURN_TEST(0);
}

int test_ecc_hybrid_decrypt_with_mismatched_key() {
	const String message = "Hybrid ciphertext, wrong private key.";
	auto kp = KeyPair::ECC::Generate(CurveBits);
	auto kp2 = KeyPair::ECC::Generate(CurveBits);
	ASSERT_TRUE(static_cast<bool>(kp));
	ASSERT_TRUE(static_cast<bool>(kp2));
	Crypter::ECC ecc(kp);
	Crypter::ECC ecc2(kp2);
	FIFO encrypted, decrypted;
	ASSERT_TRUE(ecc.Encrypt(Bytes(message), encrypted, Crypter::Asymmetric::Strategy::Hybrid));
	ASSERT_FALSE(ecc2.Decrypt(encrypted.Data().span(), decrypted));
	RETURN_TEST(0);
}

int main() {
	int result = 0;

	// -------------------
	// Native
	// -------------------
	result += test_ecc_encrypt_decrypt();
	result += test_ecc_encryption_produces_different_content();
	result += test_ecc_encrypt_decrypt_using_consumer_producer();
	result += test_ecc_encrypt_decrypt_native_explicit();
	result += test_ecc_encrypt_decrypt_native_explicit_streaming();

	// -------------------
	// Hybrid
	// -------------------
	result += test_ecc_encrypt_decrypt_hybrid();
	result += test_ecc_encrypt_decrypt_hybrid_streaming();
	result += test_ecc_hybrid_vs_native_different_output();

	// -------------------
	// Failure modes
	// -------------------
	result += test_ecc_decryption_with_corrupted_data();
	result += test_ecc_decrypt_with_mismatched_key();
	result += test_ecc_with_corrupted_keys();
	result += test_ecc_corrupted_hybrid_envelope_fails();
	result += test_ecc_corrupted_native_fails_auto_detect();
	result += test_ecc_hybrid_decrypt_with_mismatched_key();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
