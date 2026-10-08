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
#include <StormByte/crypto/signer/ecdsa.hxx>
#include <StormByte/safe/binary.hxx>
#include <StormByte/safe/string.hxx>
#include <StormByte/test_handlers.h>

#include <array>
#include <iostream>
#include <string_view>
#include <utility>

using StormByte::Buffer::FIFO;
using namespace StormByte;
using namespace StormByte::Crypto;

// -------------------
// Class surface
// -------------------

int test_ecdsa_copy_move_and_clone() {
	auto kp = KeyPair::ECDSA::Generate(256);
	ASSERT_TRUE(static_cast<bool>(kp));
	Signer::ECDSA original(kp);
	Signer::ECDSA copied(original);
	Signer::ECDSA copy_assigned(kp);
	copy_assigned = original;
	Signer::ECDSA moved(std::move(copied));
	Signer::ECDSA move_assigned(kp);
	move_assigned = std::move(copy_assigned);
	auto cloned = original.Clone();
	ASSERT_TRUE(static_cast<bool>(cloned));
	ASSERT_NOT_EQUAL(&original, cloned.get());
	Signer::ECDSA move_source(original);
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

int test_ecdsa_sign_with_public_only_key() {
	auto kp = KeyPair::ECDSA::Generate(256);
	ASSERT_TRUE(static_cast<bool>(kp));
	const KeyPair::ECDSA public_key(static_cast<std::string_view>(kp->PublicKey()));
	ASSERT_FALSE(public_key.HasPrivateKey());
	Signer::ECDSA signer(public_key);
	const Safe::Binary message("Public-only key");
	FIFO signed_data;
	ASSERT_FALSE(signer.Sign(message.span(), signed_data));
	ASSERT_TRUE(signed_data.Data().empty());
	RETURN_TEST(0);
}

int test_ecdsa_verify_with_corrupted_signature() {
	const Safe::Binary message("This is a test message.");
	auto kp = KeyPair::ECDSA::Generate(256);
	ASSERT_TRUE(static_cast<bool>(kp));
	Signer::ECDSA ecdsa(kp);
	FIFO signed_data;
	ASSERT_TRUE(ecdsa.Sign(message.span(), signed_data));
	Safe::String signature = DeserializeString(signed_data.Data());
	ASSERT_FALSE(signature.empty());
	signature.front() = static_cast<char>(~signature.front());
	ASSERT_FALSE(ecdsa.Verify(message.span(), static_cast<std::string_view>(signature)));
	RETURN_TEST(0);
}

int test_ecdsa_verify_with_invalid_signatures() {
	auto kp = KeyPair::ECDSA::Generate(256);
	ASSERT_TRUE(static_cast<bool>(kp));
	Signer::ECDSA signer(kp);
	const Safe::Binary message("Malformed signatures");
	FIFO signed_data;
	ASSERT_TRUE(signer.Sign(message.span(), signed_data));
	const Safe::String signature = DeserializeString(signed_data.Data());
	ASSERT_FALSE(signature.empty());
	ASSERT_TRUE(signer.Verify(message.span(), static_cast<std::string_view>(signature)));
	ASSERT_FALSE(signer.Verify(message.span(), std::string_view{}));
	const Safe::String malformed(signature.size(), '\0');
	ASSERT_FALSE(signer.Verify(message.span(), static_cast<std::string_view>(malformed)));
	Safe::String truncated = signature;
	truncated.pop_back();
	ASSERT_FALSE(signer.Verify(message.span(), static_cast<std::string_view>(truncated)));
	Safe::String extended = signature;
	extended.push_back('\0');
	ASSERT_FALSE(signer.Verify(message.span(), static_cast<std::string_view>(extended)));
	ASSERT_TRUE(signer.Verify(message.span(), static_cast<std::string_view>(signature)));
	RETURN_TEST(0);
}

int test_ecdsa_verify_with_malformed_keys() {
	auto kp = KeyPair::ECDSA::Generate(256);
	ASSERT_TRUE(static_cast<bool>(kp));
	Signer::ECDSA signer(kp);
	const Safe::Binary message("Malformed keys");
	FIFO signed_data;
	ASSERT_TRUE(signer.Sign(message.span(), signed_data));
	const Safe::String signature = DeserializeString(signed_data.Data());
	ASSERT_FALSE(signature.empty());
	const std::array<std::string_view, 3> materials {
		std::string_view{}, "not a key", std::string_view("bad\0key", 7)
	};
	for (const auto material: materials) {
		const KeyPair::ECDSA invalid_key(material);
		Signer::ECDSA invalid_signer(invalid_key);
		ASSERT_FALSE(invalid_signer.Verify(message.span(), static_cast<std::string_view>(signature)));
		FIFO failed_output;
		ASSERT_FALSE(invalid_signer.Sign(message.span(), failed_output));
		ASSERT_TRUE(failed_output.Data().empty());
	}
	const KeyPair::ECDSA invalid_private(static_cast<std::string_view>(kp->PublicKey()),
		Safe::Optional<Secure::Password>(Secure::Password("malformed private key")));
	ASSERT_TRUE(invalid_private.HasPrivateKey());
	Signer::ECDSA invalid_signer(invalid_private);
	FIFO failed_output;
	ASSERT_FALSE(invalid_signer.Sign(message.span(), failed_output));
	ASSERT_TRUE(failed_output.Data().empty());
	ASSERT_TRUE(signer.Verify(message.span(), static_cast<std::string_view>(signature)));
	RETURN_TEST(0);
}

int test_ecdsa_verify_with_mismatched_key() {
	const Safe::Binary message("This is a test message.");
	auto kp = KeyPair::ECDSA::Generate(256);
	ASSERT_TRUE(static_cast<bool>(kp));
	Signer::ECDSA ecdsa(kp);
	auto kp2 = KeyPair::ECDSA::Generate(256);
	ASSERT_TRUE(static_cast<bool>(kp2));
	Signer::ECDSA ecdsa2(kp2);
	FIFO signed_data;
	ASSERT_TRUE(ecdsa.Sign(message.span(), signed_data));
	const Safe::String signature = DeserializeString(signed_data.Data());
	ASSERT_FALSE(ecdsa2.Verify(message.span(), static_cast<std::string_view>(signature)));
	RETURN_TEST(0);
}

// -------------------
// Sign / verify
// -------------------

int test_ecdsa_sign_and_verify() {
	const Safe::Binary message("This is a test message.");
	auto kp = KeyPair::ECDSA::Generate(256);
	ASSERT_TRUE(static_cast<bool>(kp));
	Signer::ECDSA ecdsa(kp);
	FIFO signed_data;
	ASSERT_TRUE(ecdsa.Sign(message.span(), signed_data));
	const Safe::String signature = DeserializeString(signed_data.Data());
	ASSERT_TRUE(ecdsa.Verify(message.span(), static_cast<std::string_view>(signature)));
	RETURN_TEST(0);
}

int test_ecdsa_sign_and_verify_embedded_nul_message() {
	const Safe::Binary message(std::string_view("before\0after", 12));
	const Safe::Binary prefix("before");
	auto kp = KeyPair::ECDSA::Generate(256);
	ASSERT_TRUE(static_cast<bool>(kp));
	Signer::ECDSA signer(kp);
	FIFO signed_data;
	ASSERT_TRUE(signer.Sign(message.span(), signed_data));
	const Safe::String signature = DeserializeString(signed_data.Data());
	ASSERT_FALSE(signature.empty());
	ASSERT_TRUE(signer.Verify(message.span(), static_cast<std::string_view>(signature)));
	ASSERT_FALSE(signer.Verify(prefix.span(), static_cast<std::string_view>(signature)));
	RETURN_TEST(0);
}

int test_ecdsa_sign_and_verify_empty_message() {
	const Safe::Binary message;
	auto kp = KeyPair::ECDSA::Generate(256);
	ASSERT_TRUE(static_cast<bool>(kp));
	Signer::ECDSA signer(kp);
	FIFO signed_data;
	ASSERT_TRUE(signer.Sign(message.span(), signed_data));
	const Safe::String signature = DeserializeString(signed_data.Data());
	ASSERT_FALSE(signature.empty());
	ASSERT_TRUE(signer.Verify(message.span(), static_cast<std::string_view>(signature)));
	RETURN_TEST(0);
}

int test_ecdsa_verify_with_public_only_key() {
	auto kp = KeyPair::ECDSA::Generate(256);
	ASSERT_TRUE(static_cast<bool>(kp));
	Signer::ECDSA signer(kp);
	const Safe::Binary message("Public-only verification");
	FIFO signed_data;
	ASSERT_TRUE(signer.Sign(message.span(), signed_data));
	const Safe::String signature = DeserializeString(signed_data.Data());
	const KeyPair::ECDSA public_key(static_cast<std::string_view>(kp->PublicKey()));
	ASSERT_FALSE(public_key.HasPrivateKey());
	Signer::ECDSA verifier(public_key);
	ASSERT_TRUE(verifier.Verify(message.span(), static_cast<std::string_view>(signature)));
	RETURN_TEST(0);
}

int main() {
	int result = 0;

	// -------------------
	// Class surface
	// -------------------
	result += test_ecdsa_copy_move_and_clone();

	// -------------------
	// Failure modes
	// -------------------
	result += test_ecdsa_sign_with_public_only_key();
	result += test_ecdsa_verify_with_corrupted_signature();
	result += test_ecdsa_verify_with_invalid_signatures();
	result += test_ecdsa_verify_with_malformed_keys();
	result += test_ecdsa_verify_with_mismatched_key();

	// -------------------
	// Sign / verify
	// -------------------
	result += test_ecdsa_sign_and_verify();
	result += test_ecdsa_sign_and_verify_embedded_nul_message();
	result += test_ecdsa_sign_and_verify_empty_message();
	result += test_ecdsa_verify_with_public_only_key();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
