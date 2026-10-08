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

#include <StormByte/buffer/fifo.hxx>
#include <StormByte/crypto/crypter/symmetric/chachapoly.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/safe/binary.hxx>
#include <StormByte/test_handlers.h>

#include <iostream>
#include <utility>

using StormByte::Buffer::FIFO;
using StormByte::Safe::Binary;
using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;

// -------------------
// Authentication
// -------------------

int test_chacha_corrupted_ciphertext() {
	Password password("SecurePassword123!");
	const Binary original("Message to encrypt then corrupt a little.");
	Crypter::ChaChaPoly chacha(password);
	FIFO encrypted;
	ASSERT_TRUE(chacha.Encrypt(original.span(), encrypted));
	Binary corrupted = encrypted.Data();
	ASSERT_FALSE(corrupted.empty());
	corrupted[static_cast<std::size_t>(corrupted.size()) / 2] ^= std::byte{1};
	FIFO decrypted;
	ASSERT_FALSE(chacha.Decrypt(corrupted.span(), decrypted));
	ASSERT_TRUE(decrypted.Empty());
	RETURN_TEST(0);
}

int test_chacha_wrong_decryption_password() {
	Password password("SecurePassword123!");
	Password wrong_password("WrongPassword456!");
	const Binary original("This is sensitive data.");
	Crypter::ChaChaPoly chacha(password);
	Crypter::ChaChaPoly wrong_chacha(wrong_password);
	FIFO encrypted;
	ASSERT_TRUE(chacha.Encrypt(original.span(), encrypted));
	ASSERT_FALSE(encrypted.Empty());
	FIFO decrypted;
	ASSERT_FALSE(wrong_chacha.Decrypt(encrypted.Data().span(), decrypted));
	ASSERT_TRUE(decrypted.Empty());
	RETURN_TEST(0);
}

// -------------------
// Construct
// -------------------

int test_chacha_clone_and_move() {
	const Password password("ClonePassword");
	const Binary original("Clone and move retain the password");
	Crypter::ChaChaPoly chacha(password);
	auto clone = chacha.Clone();
	ASSERT_TRUE(clone);
	ASSERT_TRUE(clone.get() != &chacha);
	ASSERT_TRUE(clone->Type() == Crypter::Type::ChaChaPoly);
	auto moved = chacha.Move();
	ASSERT_TRUE(moved);
	ASSERT_TRUE(moved.get() != &chacha);
	ASSERT_TRUE(moved.get() != clone.get());
	ASSERT_TRUE(moved->Type() == Crypter::Type::ChaChaPoly);
	FIFO encrypted;
	ASSERT_TRUE(clone->Encrypt(original.span(), encrypted));
	FIFO decrypted;
	ASSERT_TRUE(moved->Decrypt(encrypted.Data().span(), decrypted));
	ASSERT_EQUAL(original, decrypted.Data());
	FIFO moved_encrypted;
	ASSERT_TRUE(moved->Encrypt(original.span(), moved_encrypted));
	FIFO clone_decrypted;
	ASSERT_TRUE(clone->Decrypt(moved_encrypted.Data().span(), clone_decrypted));
	ASSERT_EQUAL(original, clone_decrypted.Data());
	RETURN_TEST(0);
}

int test_chacha_copy_operations() {
	const Password password("CopyPassword");
	const Binary original("Copy constructors and assignments preserve keys");
	Crypter::ChaChaPoly source(password);
	Crypter::ChaChaPoly copied(source);
	Crypter::ChaChaPoly assigned(Password("ReplacedPassword"));
	ASSERT_TRUE(&(assigned = source) == &assigned);
	ASSERT_TRUE(copied.Type() == Crypter::Type::ChaChaPoly);
	ASSERT_TRUE(assigned.Type() == Crypter::Type::ChaChaPoly);
	ASSERT_TRUE(copied.Password() == password);
	ASSERT_TRUE(assigned.Password() == password);
	source = Crypter::ChaChaPoly(Password("DifferentPassword"));
	FIFO encrypted;
	ASSERT_TRUE(copied.Encrypt(original.span(), encrypted));
	FIFO decrypted;
	ASSERT_TRUE(assigned.Decrypt(encrypted.Data().span(), decrypted));
	ASSERT_EQUAL(original, decrypted.Data());
	RETURN_TEST(0);
}

int test_chacha_move_operations() {
	const Password password("MovePassword");
	const Binary original("Move constructors and assignments preserve keys");
	Crypter::ChaChaPoly source(password);
	Crypter::ChaChaPoly moved(std::move(source));
	ASSERT_TRUE(moved.Type() == Crypter::Type::ChaChaPoly);
	ASSERT_TRUE(moved.Password() == password);
	FIFO encrypted;
	ASSERT_TRUE(moved.Encrypt(original.span(), encrypted));
	Crypter::ChaChaPoly assigned(Password("ReplacedPassword"));
	ASSERT_TRUE(&(assigned = std::move(moved)) == &assigned);
	ASSERT_TRUE(assigned.Type() == Crypter::Type::ChaChaPoly);
	ASSERT_TRUE(assigned.Password() == password);
	FIFO decrypted;
	ASSERT_TRUE(assigned.Decrypt(encrypted.Data().span(), decrypted));
	ASSERT_EQUAL(original, decrypted.Data());
	RETURN_TEST(0);
}

// -------------------
// Edge cases
// -------------------

int test_chacha_embedded_nul() {
	const Binary original{std::byte{0}, std::byte{'A'}, std::byte{0}, std::byte{255}, std::byte{0}};
	Crypter::ChaChaPoly chacha(Password("BinaryPassword"));
	FIFO encrypted;
	ASSERT_TRUE(chacha.Encrypt(original.span(), encrypted));
	FIFO decrypted;
	ASSERT_TRUE(chacha.Decrypt(encrypted.Data().span(), decrypted));
	ASSERT_EQUAL(original.size(), decrypted.Data().size());
	ASSERT_EQUAL(original, decrypted.Data());
	RETURN_TEST(0);
}

int test_chacha_empty_ciphertext() {
	Crypter::ChaChaPoly chacha(Password("EmptyPassword"));
	const Binary empty;
	FIFO decrypted;
	ASSERT_FALSE(chacha.Decrypt(empty.span(), decrypted));
	ASSERT_TRUE(decrypted.Empty());
	RETURN_TEST(0);
}

int test_chacha_empty_round_trip() {
	Crypter::ChaChaPoly chacha(Password("EmptyPassword"));
	const Binary empty;
	FIFO encrypted;
	ASSERT_TRUE(chacha.Encrypt(empty.span(), encrypted));
	ASSERT_FALSE(encrypted.Empty());
	FIFO decrypted;
	ASSERT_TRUE(chacha.Decrypt(encrypted.Data().span(), decrypted));
	ASSERT_TRUE(decrypted.Empty());
	RETURN_TEST(0);
}

int test_chacha_truncated_header() {
	Crypter::ChaChaPoly chacha(Password("HeaderPassword"));
	const Binary truncated(StormByte::ByteSize{27}, std::byte{0});
	FIFO decrypted;
	ASSERT_FALSE(chacha.Decrypt(truncated.span(), decrypted));
	ASSERT_TRUE(decrypted.Empty());
	RETURN_TEST(0);
}

// -------------------
// Round trip
// -------------------

int test_chacha_encrypt_decrypt_consistency() {
	Password password("SecurePassword123!");
	const Binary original("Confidential information to encrypt and decrypt.");
	Crypter::ChaChaPoly chacha(password);
	FIFO encrypted;
	ASSERT_TRUE(chacha.Encrypt(original.span(), encrypted));
	ASSERT_FALSE(encrypted.Empty());
	FIFO decrypted;
	ASSERT_TRUE(chacha.Decrypt(encrypted.Data().span(), decrypted));
	ASSERT_EQUAL(original, decrypted.Data());
	RETURN_TEST(0);
}

int test_chacha_encryption_produces_different_content() {
	Password password("SecurePassword123!");
	const Binary original("Important data to encrypt");
	Crypter::ChaChaPoly chacha(password);
	FIFO encrypted;
	ASSERT_TRUE(chacha.Encrypt(original.span(), encrypted));
	ASSERT_FALSE(encrypted.Empty());
	ASSERT_NOT_EQUAL(original, encrypted.Data());
	FIFO second_encrypted;
	ASSERT_TRUE(chacha.Encrypt(original.span(), second_encrypted));
	ASSERT_NOT_EQUAL(encrypted.Data(), second_encrypted.Data());
	RETURN_TEST(0);
}

int main() {
	int result = 0;

	// -------------------
	// Authentication
	// -------------------
	result += test_chacha_corrupted_ciphertext();
	result += test_chacha_wrong_decryption_password();

	// -------------------
	// Construct
	// -------------------
	result += test_chacha_clone_and_move();
	result += test_chacha_copy_operations();
	result += test_chacha_move_operations();

	// -------------------
	// Edge cases
	// -------------------
	result += test_chacha_embedded_nul();
	result += test_chacha_empty_ciphertext();
	result += test_chacha_empty_round_trip();
	result += test_chacha_truncated_header();

	// -------------------
	// Round trip
	// -------------------
	result += test_chacha_encrypt_decrypt_consistency();
	result += test_chacha_encryption_produces_different_content();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
