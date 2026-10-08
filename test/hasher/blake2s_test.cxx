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
#include <StormByte/crypto/hasher/blake2s.hxx>
#include <StormByte/test_handlers.h>

#include <utility>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

namespace {
	const StormByte::Safe::String ExpectedHashThisString =
		"542412C16951C1538BDCB190255C363F7FA1986B500FFBAB8377EF5E67785F1D";
}

// -------------------
// Assignment
// -------------------

int test_blake2s_copy_assignment() {
	const Hasher::Blake2s source;
	Hasher::Blake2s assigned;
	ASSERT_TRUE(&(assigned = source) == &assigned);
	ASSERT_EQUAL(Hasher::Type::Blake2s, assigned.Type());
	FIFO hash;
	ASSERT_TRUE(assigned.Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	ASSERT_EQUAL(Hasher::Type::Blake2s, source.Type());
	RETURN_TEST(0);
}

int test_blake2s_move_assignment() {
	Hasher::Blake2s source;
	Hasher::Blake2s assigned;
	ASSERT_TRUE(&(assigned = std::move(source)) == &assigned);
	ASSERT_EQUAL(Hasher::Type::Blake2s, assigned.Type());
	FIFO hash;
	ASSERT_TRUE(assigned.Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

// -------------------
// Construct
// -------------------

int test_blake2s_copy_constructor() {
	const Hasher::Blake2s source;
	Hasher::Blake2s copied(source);
	ASSERT_EQUAL(Hasher::Type::Blake2s, copied.Type());
	FIFO hash;
	ASSERT_TRUE(copied.Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	ASSERT_EQUAL(Hasher::Type::Blake2s, source.Type());
	RETURN_TEST(0);
}

int test_blake2s_move_constructor() {
	Hasher::Blake2s source;
	Hasher::Blake2s moved(std::move(source));
	ASSERT_EQUAL(Hasher::Type::Blake2s, moved.Type());
	FIFO hash;
	ASSERT_TRUE(moved.Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

// -------------------
// Correctness
// -------------------

int test_blake2s_embedded_nul() {
	const StormByte::Safe::Binary input(std::string_view("a\0b", 3));
	Hasher::Blake2s hasher;
	FIFO hash;
	ASSERT_EQUAL(std::size_t{3}, static_cast<std::size_t>(input.size()));
	ASSERT_TRUE(hasher.Hash(input.span(), hash));
	ASSERT_EQUAL(StormByte::Safe::String("F3E12C25611E6F1EE6BD153D04BED2D276E1E83B95C66EBFC034C0FBB04247C7"), DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

int test_blake2s_empty_input() {
	Hasher::Blake2s hasher;
	FIFO hash;
	ASSERT_TRUE(hasher.Hash(std::span<const std::byte>{}, hash));
	ASSERT_EQUAL(StormByte::Safe::String("69217A3079908094E11121D042354A7C1F55B6482CA1A51E1B250DFD1ED0EEF9"), DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

int test_blake2s_hash_correctness() {
	const StormByte::Safe::String input_data = "HashThisString";
	Hasher::Blake2s blake2s;
	FIFO hash;
	ASSERT_TRUE(blake2s.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input_data.data()), static_cast<std::size_t>(input_data.size())), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

// -------------------
// Distinct inputs
// -------------------

int test_blake2s_collision_resistance() {
	Hasher::Blake2s blake2s;
	FIFO hash_1_fifo;
	ASSERT_TRUE(blake2s.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>("Original Input Data"), 19), hash_1_fifo));
	FIFO hash_2_fifo;
	ASSERT_TRUE(blake2s.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>("Original Input Data!"), 20), hash_2_fifo));
	ASSERT_NOT_EQUAL(DeserializeString(hash_1_fifo.Data()), DeserializeString(hash_2_fifo.Data()));
	RETURN_TEST(0);
}

int test_blake2s_produces_different_content() {
	const StormByte::Safe::String original_data = "Data to hash";
	Hasher::Blake2s blake2s;
	FIFO hash;
	ASSERT_TRUE(blake2s.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(original_data.data()), static_cast<std::size_t>(original_data.size())), hash));
	ASSERT_NOT_EQUAL(original_data, DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

// -------------------
// Ownership
// -------------------

int test_blake2s_clone() {
	const Hasher::Blake2s source;
	auto cloned = source.Clone();
	ASSERT_TRUE(cloned);
	ASSERT_TRUE(dynamic_cast<Hasher::Blake2s*>(cloned.get()) != nullptr);
	ASSERT_TRUE(cloned.get() != &source);
	ASSERT_EQUAL(Hasher::Type::Blake2s, cloned->Type());
	FIFO hash;
	ASSERT_TRUE(cloned->Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

int test_blake2s_move() {
	Hasher::Blake2s source;
	auto moved = source.Move();
	ASSERT_TRUE(moved);
	ASSERT_TRUE(dynamic_cast<Hasher::Blake2s*>(moved.get()) != nullptr);
	ASSERT_TRUE(moved.get() != &source);
	ASSERT_EQUAL(Hasher::Type::Blake2s, moved->Type());
	FIFO hash;
	ASSERT_TRUE(moved->Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

// -------------------
// Stream
// -------------------

int test_blake2s_hash_using_consumer_producer() {
	Hasher::Blake2s blake2s;
	StormByte::Buffer::Producer producer;
	ASSERT_TRUE(producer.Write(std::string_view("HashThisString")));
	producer.Close();
	auto hash_consumer = blake2s.Hash(producer.Consumer());
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
	result += test_blake2s_copy_assignment();
	result += test_blake2s_move_assignment();

	// -------------------
	// Construct
	// -------------------
	result += test_blake2s_copy_constructor();
	result += test_blake2s_move_constructor();

	// -------------------
	// Correctness
	// -------------------
	result += test_blake2s_embedded_nul();
	result += test_blake2s_empty_input();
	result += test_blake2s_hash_correctness();

	// -------------------
	// Distinct inputs
	// -------------------
	result += test_blake2s_collision_resistance();
	result += test_blake2s_produces_different_content();

	// -------------------
	// Ownership
	// -------------------
	result += test_blake2s_clone();
	result += test_blake2s_move();

	// -------------------
	// Stream
	// -------------------
	result += test_blake2s_hash_using_consumer_producer();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
