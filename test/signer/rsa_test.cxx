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
#include <StormByte/crypto/signer/rsa.hxx>
#include <StormByte/safe/binary.hxx>
#include <StormByte/safe/string.hxx>
#include <StormByte/safe/vector.hxx>
#include <StormByte/test_handlers.h>

#include <array>
#include <cstdint>
#include <iostream>
#include <string_view>
#include <utility>

using StormByte::Buffer::FIFO;
using namespace StormByte;
using namespace StormByte::Crypto;

// -------------------
// Class surface
// -------------------

int test_rsa_copy_move_and_clone() {
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(kp));
	Signer::RSA original(kp);
	Signer::RSA copied(original);
	Signer::RSA copy_assigned(kp);
	copy_assigned = original;
	Signer::RSA moved(std::move(copied));
	Signer::RSA move_assigned(kp);
	move_assigned = std::move(copy_assigned);
	auto cloned = original.Clone();
	ASSERT_TRUE(static_cast<bool>(cloned));
	ASSERT_NOT_EQUAL(&original, cloned.get());
	Signer::RSA move_source(original);
	auto relocated = move_source.Move();
	ASSERT_TRUE(static_cast<bool>(relocated));
	const Safe::Binary message("Class surface message");
	const std::array<const Signer::Generic*, 5> signers {
		&original, &moved, &move_assigned, cloned.get(), relocated.get()
	};
	for (const auto* signer: signers) {
		ASSERT_TRUE(static_cast<bool>(signer->KeyPair()));
		ASSERT_EQUAL(kp->PublicKey(), signer->KeyPair()->PublicKey());
		FIFO signed_data;
		ASSERT_TRUE(signer->Sign(message.span(), signed_data));
		const Safe::String signature = DeserializeString(signed_data.Data());
		ASSERT_FALSE(signature.empty());
		ASSERT_TRUE(original.Verify(message.span(), static_cast<std::string_view>(signature)));
		ASSERT_TRUE(signer->Verify(message.span(), static_cast<std::string_view>(signature)));
	}
	RETURN_TEST(0);
}

// -------------------
// Failure modes
// -------------------

int test_rsa_sign_verify_with_corrupted_message() {
	const Safe::Binary message("This is a message to sign.");
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(kp));
	Signer::RSA rsa(kp);
	FIFO signed_data;
	ASSERT_TRUE(rsa.Sign(message.span(), signed_data));
	const Safe::String signature = DeserializeString(signed_data.Data());
	Safe::Binary corrupted_message = message;
	ASSERT_FALSE(corrupted_message.empty());
	corrupted_message.front() = ~corrupted_message.front();
	ASSERT_FALSE(rsa.Verify(corrupted_message.span(), static_cast<std::string_view>(signature)));
	RETURN_TEST(0);
}

int test_rsa_sign_verify_with_different_key_pair() {
	const Safe::Binary message("This is a message to sign.");
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(kp));
	Signer::RSA rsa(kp);
	auto kp2 = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(kp2));
	Signer::RSA rsa2(kp2);
	FIFO signed_data;
	ASSERT_TRUE(rsa.Sign(message.span(), signed_data));
	const Safe::String signature = DeserializeString(signed_data.Data());
	ASSERT_FALSE(rsa2.Verify(message.span(), static_cast<std::string_view>(signature)));
	RETURN_TEST(0);
}

int test_rsa_sign_with_public_only_key() {
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(kp));
	const KeyPair::RSA public_key(static_cast<std::string_view>(kp->PublicKey()));
	ASSERT_FALSE(public_key.HasPrivateKey());
	Signer::RSA signer(public_key);
	const Safe::Binary message("Public-only key");
	FIFO signed_data;
	ASSERT_FALSE(signer.Sign(message.span(), signed_data));
	ASSERT_TRUE(signed_data.Data().empty());
	RETURN_TEST(0);
}

int test_rsa_verify_with_invalid_signatures() {
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(kp));
	Signer::RSA signer(kp);
	const Safe::Binary message("Malformed signatures");
	FIFO signed_data;
	ASSERT_TRUE(signer.Sign(message.span(), signed_data));
	const Safe::String signature = DeserializeString(signed_data.Data());
	ASSERT_FALSE(signature.empty());
	ASSERT_TRUE(signer.Verify(message.span(), static_cast<std::string_view>(signature)));
	ASSERT_FALSE(signer.Verify(message.span(), std::string_view{}));
	const Safe::String malformed(signature.size(), '\0');
	ASSERT_FALSE(signer.Verify(message.span(), static_cast<std::string_view>(malformed)));
	Safe::String corrupted = signature;
	corrupted.front() = static_cast<char>(~corrupted.front());
	ASSERT_FALSE(signer.Verify(message.span(), static_cast<std::string_view>(corrupted)));
	Safe::String truncated = signature;
	truncated.pop_back();
	ASSERT_FALSE(signer.Verify(message.span(), static_cast<std::string_view>(truncated)));
	Safe::String extended = signature;
	extended.push_back('\0');
	ASSERT_FALSE(signer.Verify(message.span(), static_cast<std::string_view>(extended)));
	ASSERT_TRUE(signer.Verify(message.span(), static_cast<std::string_view>(signature)));
	RETURN_TEST(0);
}

int test_rsa_verify_with_malformed_keys() {
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(kp));
	Signer::RSA signer(kp);
	const Safe::Binary message("Malformed keys");
	FIFO signed_data;
	ASSERT_TRUE(signer.Sign(message.span(), signed_data));
	const Safe::String signature = DeserializeString(signed_data.Data());
	ASSERT_FALSE(signature.empty());
	const std::array<std::string_view, 3> materials {
		std::string_view{}, "not a key", std::string_view("bad\0key", 7)
	};
	for (const auto material: materials) {
		const KeyPair::RSA invalid_key(material);
		Signer::RSA invalid_signer(invalid_key);
		ASSERT_FALSE(invalid_signer.Verify(message.span(), static_cast<std::string_view>(signature)));
		FIFO failed_output;
		ASSERT_FALSE(invalid_signer.Sign(message.span(), failed_output));
		ASSERT_TRUE(failed_output.Data().empty());
	}
	const KeyPair::RSA invalid_private(static_cast<std::string_view>(kp->PublicKey()),
		Safe::Optional<Secure::Password>(Secure::Password("malformed private key")));
	ASSERT_TRUE(invalid_private.HasPrivateKey());
	Signer::RSA invalid_signer(invalid_private);
	FIFO failed_output;
	ASSERT_FALSE(invalid_signer.Sign(message.span(), failed_output));
	ASSERT_TRUE(failed_output.Data().empty());
	ASSERT_TRUE(signer.Verify(message.span(), static_cast<std::string_view>(signature)));
	RETURN_TEST(0);
}

// -------------------
// Sign / verify
// -------------------

int test_rsa_sign_verify_byte_input_ranges() {
	const std::string_view message = "This is a range message to sign.";
	const Safe::Vector<std::uint8_t> bytes(message.begin(), message.end());
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(kp));
	Signer::RSA rsa(kp);
	FIFO signed_data;
	ASSERT_TRUE(rsa.Sign(message, signed_data));
	const Safe::String signature = DeserializeString(signed_data.Data());
	ASSERT_TRUE(rsa.Verify(bytes, static_cast<std::string_view>(signature)));
	ASSERT_TRUE(rsa.Verify(std::span<const std::uint8_t>(bytes.data(), bytes.size()), static_cast<std::string_view>(signature)));
	RETURN_TEST(0);
}

int test_rsa_sign_verify_embedded_nul_message() {
	const Safe::Binary message(std::string_view("before\0after", 12));
	const Safe::Binary prefix("before");
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(kp));
	Signer::RSA signer(kp);
	FIFO signed_data;
	ASSERT_TRUE(signer.Sign(message.span(), signed_data));
	const Safe::String signature = DeserializeString(signed_data.Data());
	ASSERT_FALSE(signature.empty());
	ASSERT_TRUE(signer.Verify(message.span(), static_cast<std::string_view>(signature)));
	ASSERT_FALSE(signer.Verify(prefix.span(), static_cast<std::string_view>(signature)));
	RETURN_TEST(0);
}

int test_rsa_sign_verify_empty_message() {
	const Safe::Binary message;
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(kp));
	Signer::RSA signer(kp);
	FIFO signed_data;
	ASSERT_TRUE(signer.Sign(message.span(), signed_data));
	const Safe::String signature = DeserializeString(signed_data.Data());
	ASSERT_FALSE(signature.empty());
	ASSERT_TRUE(signer.Verify(message.span(), static_cast<std::string_view>(signature)));
	RETURN_TEST(0);
}

int test_rsa_sign_verify_success() {
	const Safe::Binary message("This is a message to sign.");
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(kp));
	Signer::RSA rsa(kp);
	FIFO signed_data;
	ASSERT_TRUE(rsa.Sign(message.span(), signed_data));
	const Safe::String signature = DeserializeString(signed_data.Data());
	ASSERT_TRUE(rsa.Verify(message.span(), static_cast<std::string_view>(signature)));
	RETURN_TEST(0);
}

int test_rsa_verify_with_public_only_key() {
	auto kp = KeyPair::RSA::Generate(2048);
	ASSERT_TRUE(static_cast<bool>(kp));
	Signer::RSA signer(kp);
	const Safe::Binary message("Public-only verification");
	FIFO signed_data;
	ASSERT_TRUE(signer.Sign(message.span(), signed_data));
	const Safe::String signature = DeserializeString(signed_data.Data());
	const KeyPair::RSA public_key(static_cast<std::string_view>(kp->PublicKey()));
	ASSERT_FALSE(public_key.HasPrivateKey());
	Signer::RSA verifier(public_key);
	ASSERT_TRUE(verifier.Verify(message.span(), static_cast<std::string_view>(signature)));
	RETURN_TEST(0);
}

int main() {
	int result = 0;

	// -------------------
	// Class surface
	// -------------------
	result += test_rsa_copy_move_and_clone();

	// -------------------
	// Failure modes
	// -------------------
	result += test_rsa_sign_verify_with_corrupted_message();
	result += test_rsa_sign_verify_with_different_key_pair();
	result += test_rsa_sign_with_public_only_key();
	result += test_rsa_verify_with_invalid_signatures();
	result += test_rsa_verify_with_malformed_keys();

	// -------------------
	// Sign / verify
	// -------------------
	result += test_rsa_sign_verify_byte_input_ranges();
	result += test_rsa_sign_verify_embedded_nul_message();
	result += test_rsa_sign_verify_empty_message();
	result += test_rsa_sign_verify_success();
	result += test_rsa_verify_with_public_only_key();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
