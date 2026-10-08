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
#include <StormByte/crypto/crypter/symmetric/twofish.hxx>
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
// Construct
// -------------------

int test_twofish_clone_and_move() {
	const Password password("ClonePassword");
	const Binary original("Clone and move retain the password");
	Crypter::TwoFish twofish(password);
	auto clone = twofish.Clone();
	ASSERT_TRUE(clone);
	ASSERT_TRUE(clone.get() != &twofish);
	ASSERT_TRUE(clone->Type() == Crypter::Type::TwoFish);
	auto moved = twofish.Move();
	ASSERT_TRUE(moved);
	ASSERT_TRUE(moved.get() != &twofish);
	ASSERT_TRUE(moved.get() != clone.get());
	ASSERT_TRUE(moved->Type() == Crypter::Type::TwoFish);
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

int test_twofish_copy_operations() {
	const Password password("CopyPassword");
	const Binary original("Copy constructors and assignments preserve keys");
	Crypter::TwoFish source(password);
	Crypter::TwoFish copied(source);
	Crypter::TwoFish assigned(Password("ReplacedPassword"));
	ASSERT_TRUE(&(assigned = source) == &assigned);
	ASSERT_TRUE(copied.Type() == Crypter::Type::TwoFish);
	ASSERT_TRUE(assigned.Type() == Crypter::Type::TwoFish);
	ASSERT_TRUE(copied.Password() == password);
	ASSERT_TRUE(assigned.Password() == password);
	source = Crypter::TwoFish(Password("DifferentPassword"));
	FIFO encrypted;
	ASSERT_TRUE(copied.Encrypt(original.span(), encrypted));
	FIFO decrypted;
	ASSERT_TRUE(assigned.Decrypt(encrypted.Data().span(), decrypted));
	ASSERT_EQUAL(original, decrypted.Data());
	RETURN_TEST(0);
}

int test_twofish_move_operations() {
	const Password password("MovePassword");
	const Binary original("Move constructors and assignments preserve keys");
	Crypter::TwoFish source(password);
	Crypter::TwoFish moved(std::move(source));
	ASSERT_TRUE(moved.Type() == Crypter::Type::TwoFish);
	ASSERT_TRUE(moved.Password() == password);
	FIFO encrypted;
	ASSERT_TRUE(moved.Encrypt(original.span(), encrypted));
	Crypter::TwoFish assigned(Password("ReplacedPassword"));
	ASSERT_TRUE(&(assigned = std::move(moved)) == &assigned);
	ASSERT_TRUE(assigned.Type() == Crypter::Type::TwoFish);
	ASSERT_TRUE(assigned.Password() == password);
	FIFO decrypted;
	ASSERT_TRUE(assigned.Decrypt(encrypted.Data().span(), decrypted));
	ASSERT_EQUAL(original, decrypted.Data());
	RETURN_TEST(0);
}

// -------------------
// Edge cases
// -------------------

int test_twofish_embedded_nul() {
	const Binary original{std::byte{0}, std::byte{'A'}, std::byte{0}, std::byte{255}, std::byte{0}};
	Crypter::TwoFish twofish(Password("BinaryPassword"));
	FIFO encrypted;
	ASSERT_TRUE(twofish.Encrypt(original.span(), encrypted));
	FIFO decrypted;
	ASSERT_TRUE(twofish.Decrypt(encrypted.Data().span(), decrypted));
	ASSERT_EQUAL(original.size(), decrypted.Data().size());
	ASSERT_EQUAL(original, decrypted.Data());
	RETURN_TEST(0);
}

int test_twofish_empty_ciphertext() {
	Crypter::TwoFish twofish(Password("EmptyPassword"));
	const Binary empty;
	FIFO decrypted;
	ASSERT_FALSE(twofish.Decrypt(empty.span(), decrypted));
	ASSERT_TRUE(decrypted.Empty());
	RETURN_TEST(0);
}

int test_twofish_empty_round_trip() {
	Crypter::TwoFish twofish(Password("EmptyPassword"));
	const Binary empty;
	FIFO encrypted;
	ASSERT_TRUE(twofish.Encrypt(empty.span(), encrypted));
	ASSERT_FALSE(encrypted.Empty());
	FIFO decrypted;
	ASSERT_TRUE(twofish.Decrypt(encrypted.Data().span(), decrypted));
	ASSERT_TRUE(decrypted.Empty());
	RETURN_TEST(0);
}

int test_twofish_tampered_iv() {
	Crypter::TwoFish twofish(Password("TamperPassword"));
	const Binary original("CBC has no authentication; the IV controls the first block");
	FIFO encrypted;
	ASSERT_TRUE(twofish.Encrypt(original.span(), encrypted));
	Binary corrupted = encrypted.Data();
	ASSERT_TRUE(static_cast<std::size_t>(corrupted.size()) > 32);
	corrupted[16] ^= std::byte{1};
	FIFO decrypted;
	ASSERT_TRUE(twofish.Decrypt(corrupted.span(), decrypted));
	ASSERT_EQUAL(original.size(), decrypted.Data().size());
	ASSERT_NOT_EQUAL(original, decrypted.Data());
	Binary expected = original;
	expected[0] ^= std::byte{1};
	ASSERT_EQUAL(expected, decrypted.Data());
	RETURN_TEST(0);
}

int test_twofish_truncated_header() {
	Crypter::TwoFish twofish(Password("HeaderPassword"));
	const Binary truncated(StormByte::ByteSize{31}, std::byte{0});
	FIFO decrypted;
	ASSERT_FALSE(twofish.Decrypt(truncated.span(), decrypted));
	ASSERT_TRUE(decrypted.Empty());
	RETURN_TEST(0);
}

// -------------------
// Failure modes
// -------------------

int test_twofish_wrong_decryption_password() {
	const Binary original("Twofish by Bruce Schneier is an AES finalist");
	Password password("CorrectPassword");
	Password wrong_password("WrongPassword");
	Crypter::TwoFish twofish(password);
	Crypter::TwoFish wrong_twofish(wrong_password);
	FIFO encrypted;
	ASSERT_TRUE(twofish.Encrypt(original.span(), encrypted));
	ASSERT_FALSE(encrypted.Empty());
	FIFO decrypted;
	(void)wrong_twofish.Decrypt(encrypted.Data().span(), decrypted);
	ASSERT_NOT_EQUAL(original, decrypted.Data());
	RETURN_TEST(0);
}

// -------------------
// Round trip
// -------------------

int test_twofish_encrypt_decrypt_consistency() {
	const Binary original("The quick brown fox jumps over the lazy dog");
	Password password("SecurePassword123!");
	Crypter::TwoFish twofish(password);
	FIFO encrypted;
	ASSERT_TRUE(twofish.Encrypt(original.span(), encrypted));
	ASSERT_FALSE(encrypted.Empty());
	FIFO decrypted;
	ASSERT_TRUE(twofish.Decrypt(encrypted.Data().span(), decrypted));
	ASSERT_FALSE(decrypted.Empty());
	ASSERT_EQUAL(original, decrypted.Data());
	RETURN_TEST(0);
}

int test_twofish_encryption_produces_different_content() {
	Password password("SecurePassword123!");
	const Binary original("Important data to encrypt");
	Crypter::TwoFish twofish(password);
	FIFO encrypted;
	ASSERT_TRUE(twofish.Encrypt(original.span(), encrypted));
	ASSERT_FALSE(encrypted.Empty());
	ASSERT_NOT_EQUAL(original, encrypted.Data());
	FIFO second_encrypted;
	ASSERT_TRUE(twofish.Encrypt(original.span(), second_encrypted));
	ASSERT_NOT_EQUAL(encrypted.Data(), second_encrypted.Data());
	RETURN_TEST(0);
}

int main() {
	int result = 0;

	// -------------------
	// Construct
	// -------------------
	result += test_twofish_clone_and_move();
	result += test_twofish_copy_operations();
	result += test_twofish_move_operations();

	// -------------------
	// Edge cases
	// -------------------
	result += test_twofish_embedded_nul();
	result += test_twofish_empty_ciphertext();
	result += test_twofish_empty_round_trip();
	result += test_twofish_tampered_iv();
	result += test_twofish_truncated_header();

	// -------------------
	// Failure modes
	// -------------------
	result += test_twofish_wrong_decryption_password();

	// -------------------
	// Round trip
	// -------------------
	result += test_twofish_encrypt_decrypt_consistency();
	result += test_twofish_encryption_produces_different_content();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
