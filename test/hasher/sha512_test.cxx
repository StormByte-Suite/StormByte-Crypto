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
#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/hasher/sha512.hxx>
#include <StormByte/test_handlers.h>

#include <utility>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

namespace {
	const StormByte::Safe::String ExpectedHashThisString =
		"6D69A62B60C16398A2482B03FB56FB041E5014E3D8E1480833EB8427C3F45910"
		"B5B1ED812EC8C04087C92F47B50016C1495F358DD34E98723795E6E852B92875";
}

// -------------------
// Assignment
// -------------------

int test_sha512_copy_assignment() {
	const Hasher::SHA512 source;
	Hasher::SHA512 assigned;
	ASSERT_TRUE(&(assigned = source) == &assigned);
	ASSERT_EQUAL(Hasher::Type::SHA512, assigned.Type());
	FIFO hash;
	ASSERT_TRUE(assigned.Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	ASSERT_EQUAL(Hasher::Type::SHA512, source.Type());
	RETURN_TEST(0);
}

int test_sha512_move_assignment() {
	Hasher::SHA512 source;
	Hasher::SHA512 assigned;
	ASSERT_TRUE(&(assigned = std::move(source)) == &assigned);
	ASSERT_EQUAL(Hasher::Type::SHA512, assigned.Type());
	FIFO hash;
	ASSERT_TRUE(assigned.Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

// -------------------
// Construct
// -------------------

int test_sha512_copy_constructor() {
	const Hasher::SHA512 source;
	Hasher::SHA512 copied(source);
	ASSERT_EQUAL(Hasher::Type::SHA512, copied.Type());
	FIFO hash;
	ASSERT_TRUE(copied.Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	ASSERT_EQUAL(Hasher::Type::SHA512, source.Type());
	RETURN_TEST(0);
}

int test_sha512_move_constructor() {
	Hasher::SHA512 source;
	Hasher::SHA512 moved(std::move(source));
	ASSERT_EQUAL(Hasher::Type::SHA512, moved.Type());
	FIFO hash;
	ASSERT_TRUE(moved.Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

// -------------------
// Correctness
// -------------------

int test_sha512_embedded_nul() {
	const StormByte::Safe::Binary input(std::string_view("a\0b", 3));
	Hasher::SHA512 hasher;
	FIFO hash;
	ASSERT_EQUAL(std::size_t{3}, static_cast<std::size_t>(input.size()));
	ASSERT_TRUE(hasher.Hash(input.span(), hash));
	ASSERT_EQUAL(StormByte::Safe::String(
		"48DD66F05B49586E072C9F3485A10982231E246B46FD5EB1765721C855610C5A8"
		"1744D49B1CC7FFEEED783F6819FD3702D659CE14B5B9B4F5D14F2E05CC375B5"), DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

int test_sha512_empty_input() {
	Hasher::SHA512 hasher;
	FIFO hash;
	ASSERT_TRUE(hasher.Hash(std::span<const std::byte>{}, hash));
	ASSERT_EQUAL(StormByte::Safe::String(
		"CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE4"
		"7D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E"), DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

int test_sha512_hash_correctness() {
	const StormByte::Safe::String input_data = "HashThisString";
	Hasher::SHA512 sha512;
	FIFO hash_fifo;
	ASSERT_TRUE(sha512.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input_data.data()), static_cast<std::size_t>(input_data.size())), hash_fifo));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash_fifo.Data()));
	RETURN_TEST(0);
}

// -------------------
// Distinct inputs
// -------------------

int test_sha512_collision_resistance() {
	const StormByte::Safe::String input_data_1 = "Original Input Data";
	const StormByte::Safe::String input_data_2 = "Original Input Data!";
	Hasher::SHA512 sha512;
	FIFO hash_fifo_1;
	ASSERT_TRUE(sha512.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input_data_1.data()), static_cast<std::size_t>(input_data_1.size())), hash_fifo_1));
	FIFO hash_fifo_2;
	ASSERT_TRUE(sha512.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input_data_2.data()), static_cast<std::size_t>(input_data_2.size())), hash_fifo_2));
	ASSERT_NOT_EQUAL(DeserializeString(hash_fifo_1.Data()), DeserializeString(hash_fifo_2.Data()));
	RETURN_TEST(0);
}

int test_sha512_produces_different_content() {
	const StormByte::Safe::String original_data = "Data to hash";
	Hasher::SHA512 sha512;
	FIFO hash_fifo;
	ASSERT_TRUE(sha512.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(original_data.data()), static_cast<std::size_t>(original_data.size())), hash_fifo));
	ASSERT_NOT_EQUAL(original_data, DeserializeString(hash_fifo.Data()));
	RETURN_TEST(0);
}

// -------------------
// Ownership
// -------------------

int test_sha512_clone() {
	const Hasher::SHA512 source;
	auto cloned = source.Clone();
	ASSERT_TRUE(cloned);
	ASSERT_TRUE(dynamic_cast<Hasher::SHA512*>(cloned.get()) != nullptr);
	ASSERT_TRUE(cloned.get() != &source);
	ASSERT_EQUAL(Hasher::Type::SHA512, cloned->Type());
	FIFO hash;
	ASSERT_TRUE(cloned->Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

int test_sha512_move() {
	Hasher::SHA512 source;
	auto moved = source.Move();
	ASSERT_TRUE(moved);
	ASSERT_TRUE(dynamic_cast<Hasher::SHA512*>(moved.get()) != nullptr);
	ASSERT_TRUE(moved.get() != &source);
	ASSERT_EQUAL(Hasher::Type::SHA512, moved->Type());
	FIFO hash;
	ASSERT_TRUE(moved->Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

// -------------------
// Stream
// -------------------

int test_sha512_hash_using_consumer_producer() {
	const StormByte::Safe::String input_data = "HashThisString";
	Hasher::SHA512 sha512;
	StormByte::Buffer::Producer producer;
	ASSERT_TRUE(producer.Write(static_cast<std::string_view>(input_data)));
	producer.Close();
	auto hash_consumer = sha512.Hash(producer.Consumer());
	ASSERT_TRUE(hash_consumer.IsWritable() || !hash_consumer.Empty());
	auto hash_result = ReadAllFromConsumer(hash_consumer);
	ASSERT_FALSE(hash_result.Empty());
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash_result));
	RETURN_TEST(0);
}

int main() {
	int result = 0;

	// -------------------
	// Assignment
	// -------------------
	result += test_sha512_copy_assignment();
	result += test_sha512_move_assignment();

	// -------------------
	// Construct
	// -------------------
	result += test_sha512_copy_constructor();
	result += test_sha512_move_constructor();

	// -------------------
	// Correctness
	// -------------------
	result += test_sha512_embedded_nul();
	result += test_sha512_empty_input();
	result += test_sha512_hash_correctness();

	// -------------------
	// Distinct inputs
	// -------------------
	result += test_sha512_collision_resistance();
	result += test_sha512_produces_different_content();

	// -------------------
	// Ownership
	// -------------------
	result += test_sha512_clone();
	result += test_sha512_move();

	// -------------------
	// Stream
	// -------------------
	result += test_sha512_hash_using_consumer_producer();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
