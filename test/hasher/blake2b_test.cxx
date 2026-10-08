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
#include <StormByte/crypto/hasher/blake2b.hxx>
#include <StormByte/test_handlers.h>

#include <utility>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

namespace {
	const StormByte::Safe::String ExpectedHashThisString =
		"66CCD3A78741E16F894F2FB20045A8678D12B73D9CBA95D3473B1029781D6587"
		"648E839960BDA14F0FF075C0EC9E7ED1AA13197BEED8B027EEA32800453CC7F8";
}

// -------------------
// Assignment
// -------------------

int test_blake2b_copy_assignment() {
	const Hasher::Blake2b source;
	Hasher::Blake2b assigned;
	ASSERT_TRUE(&(assigned = source) == &assigned);
	ASSERT_EQUAL(Hasher::Type::Blake2b, assigned.Type());
	FIFO hash;
	ASSERT_TRUE(assigned.Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	ASSERT_EQUAL(Hasher::Type::Blake2b, source.Type());
	RETURN_TEST(0);
}

int test_blake2b_move_assignment() {
	Hasher::Blake2b source;
	Hasher::Blake2b assigned;
	ASSERT_TRUE(&(assigned = std::move(source)) == &assigned);
	ASSERT_EQUAL(Hasher::Type::Blake2b, assigned.Type());
	FIFO hash;
	ASSERT_TRUE(assigned.Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

// -------------------
// Construct
// -------------------

int test_blake2b_copy_constructor() {
	const Hasher::Blake2b source;
	Hasher::Blake2b copied(source);
	ASSERT_EQUAL(Hasher::Type::Blake2b, copied.Type());
	FIFO hash;
	ASSERT_TRUE(copied.Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	ASSERT_EQUAL(Hasher::Type::Blake2b, source.Type());
	RETURN_TEST(0);
}

int test_blake2b_move_constructor() {
	Hasher::Blake2b source;
	Hasher::Blake2b moved(std::move(source));
	ASSERT_EQUAL(Hasher::Type::Blake2b, moved.Type());
	FIFO hash;
	ASSERT_TRUE(moved.Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

// -------------------
// Correctness
// -------------------

int test_blake2b_embedded_nul() {
	const StormByte::Safe::Binary input(std::string_view("a\0b", 3));
	Hasher::Blake2b hasher;
	FIFO hash;
	ASSERT_EQUAL(std::size_t{3}, static_cast<std::size_t>(input.size()));
	ASSERT_TRUE(hasher.Hash(input.span(), hash));
	ASSERT_EQUAL(StormByte::Safe::String(
		"07EEC4716391A892EA0225564EC9C0ED550C9272692DEDDB5BA1E375AA7756859"
		"B00EBF25DE872ACADA3705F1343B13EFCCB59E5A1CBA077EF9D718D7056DF2D"), DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

int test_blake2b_empty_input() {
	Hasher::Blake2b blake2b;
	FIFO hash;
	ASSERT_TRUE(blake2b.Hash(std::span<const std::byte>{}, hash));
	ASSERT_EQUAL(StormByte::Safe::String(
		"786A02F742015903C6C6FD852552D272912F4740E15847618A86E217F71F5419"
		"D25E1031AFEE585313896444934EB04B903A685B1448B755D56F701AFE9BE2CE"),
		DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

int test_blake2b_hash_correctness() {
	const StormByte::Safe::String input_data = "HashThisString";
	Hasher::Blake2b blake2b;
	FIFO hash;
	ASSERT_TRUE(blake2b.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input_data.data()), static_cast<std::size_t>(input_data.size())), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

// -------------------
// Distinct inputs
// -------------------

int test_blake2b_collision_resistance() {
	Hasher::Blake2b blake2b;
	FIFO hash_1_fifo;
	ASSERT_TRUE(blake2b.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>("Original Input Data"), 19), hash_1_fifo));
	FIFO hash_2_fifo;
	ASSERT_TRUE(blake2b.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>("Original Input Data!"), 20), hash_2_fifo));
	ASSERT_NOT_EQUAL(DeserializeString(hash_1_fifo.Data()), DeserializeString(hash_2_fifo.Data()));
	RETURN_TEST(0);
}

int test_blake2b_produces_different_content() {
	const StormByte::Safe::String original_data = "Data to hash";
	Hasher::Blake2b blake2b;
	FIFO hash;
	ASSERT_TRUE(blake2b.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(original_data.data()), static_cast<std::size_t>(original_data.size())), hash));
	ASSERT_NOT_EQUAL(original_data, DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

// -------------------
// Ownership
// -------------------

int test_blake2b_clone() {
	const Hasher::Blake2b source;
	auto cloned = source.Clone();
	ASSERT_TRUE(cloned);
	ASSERT_TRUE(dynamic_cast<Hasher::Blake2b*>(cloned.get()) != nullptr);
	ASSERT_TRUE(cloned.get() != &source);
	ASSERT_EQUAL(Hasher::Type::Blake2b, cloned->Type());
	FIFO hash;
	ASSERT_TRUE(cloned->Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

int test_blake2b_move() {
	Hasher::Blake2b source;
	auto moved = source.Move();
	ASSERT_TRUE(moved);
	ASSERT_TRUE(dynamic_cast<Hasher::Blake2b*>(moved.get()) != nullptr);
	ASSERT_TRUE(moved.get() != &source);
	ASSERT_EQUAL(Hasher::Type::Blake2b, moved->Type());
	FIFO hash;
	ASSERT_TRUE(moved->Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

// -------------------
// Stream
// -------------------

int test_blake2b_hash_using_consumer_producer() {
	Hasher::Blake2b blake2b;
	StormByte::Buffer::Producer producer;
	ASSERT_TRUE(producer.Write(std::string_view("HashThisString")));
	producer.Close();
	auto hash_consumer = blake2b.Hash(producer.Consumer());
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
	result += test_blake2b_copy_assignment();
	result += test_blake2b_move_assignment();

	// -------------------
	// Construct
	// -------------------
	result += test_blake2b_copy_constructor();
	result += test_blake2b_move_constructor();

	// -------------------
	// Correctness
	// -------------------
	result += test_blake2b_embedded_nul();
	result += test_blake2b_empty_input();
	result += test_blake2b_hash_correctness();

	// -------------------
	// Distinct inputs
	// -------------------
	result += test_blake2b_collision_resistance();
	result += test_blake2b_produces_different_content();

	// -------------------
	// Ownership
	// -------------------
	result += test_blake2b_clone();
	result += test_blake2b_move();

	// -------------------
	// Stream
	// -------------------
	result += test_blake2b_hash_using_consumer_producer();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
