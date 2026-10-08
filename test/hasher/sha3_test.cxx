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
#include <StormByte/crypto/hasher/sha3_256.hxx>
#include <StormByte/crypto/hasher/sha3_512.hxx>
#include <StormByte/test_handlers.h>

#include <utility>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

// -------------------
// Assignment
// -------------------

template<typename HasherType>
int test_sha3_copy_assignment() {
	const HasherType source;
	HasherType assigned;
	ASSERT_TRUE(&(assigned = source) == &assigned);
	ASSERT_EQUAL(source.Type(), assigned.Type());
	FIFO hash;
	FIFO source_hash;
	ASSERT_TRUE(assigned.Hash(std::string_view("HashThisString"), hash));
	ASSERT_TRUE(source.Hash(std::string_view("HashThisString"), source_hash));
	ASSERT_EQUAL(source_hash.Data(), hash.Data());
	RETURN_TEST(0);
}

template<typename HasherType>
int test_sha3_move_assignment() {
	HasherType source;
	const auto expected_type = source.Type();
	FIFO source_hash;
	ASSERT_TRUE(source.Hash(std::string_view("HashThisString"), source_hash));
	HasherType assigned;
	ASSERT_TRUE(&(assigned = std::move(source)) == &assigned);
	ASSERT_EQUAL(expected_type, assigned.Type());
	FIFO hash;
	ASSERT_TRUE(assigned.Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(source_hash.Data(), hash.Data());
	RETURN_TEST(0);
}

// -------------------
// Construct
// -------------------

template<typename HasherType>
int test_sha3_copy_constructor() {
	const HasherType source;
	HasherType copied(source);
	ASSERT_EQUAL(source.Type(), copied.Type());
	FIFO hash;
	FIFO source_hash;
	ASSERT_TRUE(copied.Hash(std::string_view("HashThisString"), hash));
	ASSERT_TRUE(source.Hash(std::string_view("HashThisString"), source_hash));
	ASSERT_EQUAL(source_hash.Data(), hash.Data());
	RETURN_TEST(0);
}

template<typename HasherType>
int test_sha3_move_constructor() {
	HasherType source;
	const auto expected_type = source.Type();
	FIFO source_hash;
	ASSERT_TRUE(source.Hash(std::string_view("HashThisString"), source_hash));
	HasherType moved(std::move(source));
	ASSERT_EQUAL(expected_type, moved.Type());
	FIFO hash;
	ASSERT_TRUE(moved.Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(source_hash.Data(), hash.Data());
	RETURN_TEST(0);
}

// -------------------
// Correctness
// -------------------

int test_sha3_256_embedded_nul() {
	const StormByte::Safe::Binary input(std::string_view("a\0b", 3));
	Hasher::SHA3_256 hasher;
	FIFO result;
	ASSERT_EQUAL(std::size_t{3}, static_cast<std::size_t>(input.size()));
	ASSERT_TRUE(hasher.Hash(input.span(), result));
	ASSERT_EQUAL(StormByte::Safe::String("B476FD9CC202C304856E5B838839A737FBAAA96A2F44808F8C28C8CFF135DB22"), DeserializeString(result.Data()));
	RETURN_TEST(0);
}

int test_sha3_256_empty_input() {
	Hasher::SHA3_256 hasher;
	FIFO result;
	ASSERT_TRUE(hasher.Hash(std::span<const std::byte>{}, result));
	ASSERT_EQUAL(StormByte::Safe::String("A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A"), DeserializeString(result.Data()));
	RETURN_TEST(0);
}

int test_sha3_256_hash() {
	const StormByte::Safe::String input = "The quick brown fox jumps over the lazy dog";
	const StormByte::Safe::String expected = "69070DDA01975C8C120C3AADA1B282394E7F032FA9CF32F4CB2259A0897DFC04";
	Hasher::SHA3_256 hasher;
	FIFO result;
	ASSERT_TRUE(hasher.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input.data()), static_cast<std::size_t>(input.size())), result));
	ASSERT_EQUAL(expected, DeserializeString(result.Data()));
	RETURN_TEST(0);
}

int test_sha3_512_embedded_nul() {
	const StormByte::Safe::Binary input(std::string_view("a\0b", 3));
	Hasher::SHA3_512 hasher;
	FIFO result;
	ASSERT_EQUAL(std::size_t{3}, static_cast<std::size_t>(input.size()));
	ASSERT_TRUE(hasher.Hash(input.span(), result));
	ASSERT_EQUAL(StormByte::Safe::String(
		"7E8D19BEF3C71A02E24ECED970A8ED6D57FA3CE0DC6B00ED25F3EF47FDFAB00D"
		"5DD4A07180832E3E7CEBF4C5010216EE02C6FB6A6E24FA080A546D67C632DDD2"), DeserializeString(result.Data()));
	RETURN_TEST(0);
}

int test_sha3_512_empty_input() {
	Hasher::SHA3_512 hasher;
	FIFO result;
	ASSERT_TRUE(hasher.Hash(std::span<const std::byte>{}, result));
	ASSERT_EQUAL(StormByte::Safe::String(
		"A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A6"
		"15B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26"), DeserializeString(result.Data()));
	RETURN_TEST(0);
}

int test_sha3_512_hash() {
	const StormByte::Safe::String input = "The quick brown fox jumps over the lazy dog";
	const StormByte::Safe::String expected =
		"01DEDD5DE4EF14642445BA5F5B97C15E47B9AD931326E4B0727CD94CEFC44FFF"
		"23F07BF543139939B49128CAF436DC1BDEE54FCB24023A08D9403F9B4BF0D450";
	Hasher::SHA3_512 hasher;
	FIFO result;
	ASSERT_TRUE(hasher.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input.data()), static_cast<std::size_t>(input.size())), result));
	ASSERT_EQUAL(expected, DeserializeString(result.Data()));
	RETURN_TEST(0);
}

// -------------------
// Ownership
// -------------------

template<typename HasherType>
int test_sha3_clone() {
	const HasherType source;
	auto cloned = source.Clone();
	ASSERT_TRUE(cloned);
	ASSERT_TRUE(dynamic_cast<HasherType*>(cloned.get()) != nullptr);
	ASSERT_TRUE(cloned.get() != &source);
	ASSERT_EQUAL(source.Type(), cloned->Type());
	FIFO hash;
	FIFO source_hash;
	ASSERT_TRUE(cloned->Hash(std::string_view("HashThisString"), hash));
	ASSERT_TRUE(source.Hash(std::string_view("HashThisString"), source_hash));
	ASSERT_EQUAL(source_hash.Data(), hash.Data());
	RETURN_TEST(0);
}

template<typename HasherType>
int test_sha3_move() {
	HasherType source;
	const auto expected_type = source.Type();
	FIFO source_hash;
	ASSERT_TRUE(source.Hash(std::string_view("HashThisString"), source_hash));
	auto moved = source.Move();
	ASSERT_TRUE(moved);
	ASSERT_TRUE(dynamic_cast<HasherType*>(moved.get()) != nullptr);
	ASSERT_TRUE(moved.get() != &source);
	ASSERT_EQUAL(expected_type, moved->Type());
	FIFO hash;
	ASSERT_TRUE(moved->Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(source_hash.Data(), hash.Data());
	RETURN_TEST(0);
}

int main() {
	int result = 0;

	// -------------------
	// Assignment
	// -------------------
	result += test_sha3_copy_assignment<Hasher::SHA3_256>();
	result += test_sha3_copy_assignment<Hasher::SHA3_512>();
	result += test_sha3_move_assignment<Hasher::SHA3_256>();
	result += test_sha3_move_assignment<Hasher::SHA3_512>();

	// -------------------
	// Construct
	// -------------------
	result += test_sha3_copy_constructor<Hasher::SHA3_256>();
	result += test_sha3_copy_constructor<Hasher::SHA3_512>();
	result += test_sha3_move_constructor<Hasher::SHA3_256>();
	result += test_sha3_move_constructor<Hasher::SHA3_512>();

	// -------------------
	// Correctness
	// -------------------
	result += test_sha3_256_embedded_nul();
	result += test_sha3_256_empty_input();
	result += test_sha3_256_hash();
	result += test_sha3_512_embedded_nul();
	result += test_sha3_512_empty_input();
	result += test_sha3_512_hash();

	// -------------------
	// Ownership
	// -------------------
	result += test_sha3_clone<Hasher::SHA3_256>();
	result += test_sha3_clone<Hasher::SHA3_512>();
	result += test_sha3_move<Hasher::SHA3_256>();
	result += test_sha3_move<Hasher::SHA3_512>();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
