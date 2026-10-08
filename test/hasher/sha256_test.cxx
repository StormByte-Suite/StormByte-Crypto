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
#include <StormByte/crypto/hasher/sha256.hxx>
#include <StormByte/safe/binary.hxx>
#include <StormByte/safe/string.hxx>
#include <StormByte/safe/vector.hxx>
#include <StormByte/test_handlers.h>

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

namespace {
	const StormByte::Safe::String ExpectedHashThisString = "BE767EABA134CB2F01E8D1755A8DD3B18BC8B063049CFF5E6228F5F7143FF777";
}

// -------------------
// Assignment
// -------------------

int test_sha256_copy_assignment() {
	const Hasher::SHA256 source;
	Hasher::SHA256 assigned;
	ASSERT_TRUE(&(assigned = source) == &assigned);
	ASSERT_EQUAL(Hasher::Type::SHA256, assigned.Type());
	FIFO hash;
	ASSERT_TRUE(assigned.Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	ASSERT_EQUAL(Hasher::Type::SHA256, source.Type());
	RETURN_TEST(0);
}

int test_sha256_move_assignment() {
	Hasher::SHA256 source;
	Hasher::SHA256 assigned;
	ASSERT_TRUE(&(assigned = std::move(source)) == &assigned);
	ASSERT_EQUAL(Hasher::Type::SHA256, assigned.Type());
	FIFO hash;
	ASSERT_TRUE(assigned.Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

// -------------------
// Construct
// -------------------

int test_sha256_copy_constructor() {
	const Hasher::SHA256 source;
	Hasher::SHA256 copied(source);
	ASSERT_EQUAL(Hasher::Type::SHA256, copied.Type());
	FIFO hash;
	ASSERT_TRUE(copied.Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	ASSERT_EQUAL(Hasher::Type::SHA256, source.Type());
	RETURN_TEST(0);
}

int test_sha256_move_constructor() {
	Hasher::SHA256 source;
	Hasher::SHA256 moved(std::move(source));
	ASSERT_EQUAL(Hasher::Type::SHA256, moved.Type());
	FIFO hash;
	ASSERT_TRUE(moved.Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

// -------------------
// Correctness
// -------------------

int test_sha256_embedded_nul() {
	const StormByte::Safe::Binary input(std::string_view("a\0b", 3));
	Hasher::SHA256 hasher;
	FIFO hash;
	ASSERT_EQUAL(std::size_t{3}, static_cast<std::size_t>(input.size()));
	ASSERT_TRUE(hasher.Hash(input.span(), hash));
	ASSERT_EQUAL(StormByte::Safe::String("59B271AE1BBCB1D31D41929817F4B16FB439EB4F31520B5AD1D5CE98920A7138"), DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

int test_sha256_empty_input() {
	Hasher::SHA256 hasher;
	FIFO hash;
	ASSERT_TRUE(hasher.Hash(std::span<const std::byte>{}, hash));
	ASSERT_EQUAL(StormByte::Safe::String("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"), DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

int test_sha256_hash_byte_input_ranges() {
	const std::string_view string_input = "HashThisString";
	const StormByte::Safe::Vector<std::uint8_t> vector_input(string_input.begin(), string_input.end());
	const std::array<std::byte, 14> array_input {
		std::byte{'H'}, std::byte{'a'}, std::byte{'s'}, std::byte{'h'},
		std::byte{'T'}, std::byte{'h'}, std::byte{'i'}, std::byte{'s'},
		std::byte{'S'}, std::byte{'t'}, std::byte{'r'}, std::byte{'i'},
		std::byte{'n'}, std::byte{'g'}
	};
	Hasher::SHA256 sha256;

	FIFO string_hash;
	ASSERT_TRUE(sha256.Hash(string_input, string_hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(string_hash.Data()));

	FIFO vector_hash;
	ASSERT_TRUE(sha256.Hash(vector_input, vector_hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(vector_hash.Data()));

	FIFO span_hash;
	ASSERT_TRUE(sha256.Hash(std::span<const std::uint8_t>(vector_input.data(), vector_input.size()), span_hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(span_hash.Data()));

	FIFO byte_span_hash;
	ASSERT_TRUE(sha256.Hash(std::span<const std::byte>(array_input), byte_span_hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(byte_span_hash.Data()));
	RETURN_TEST(0);
}

int test_sha256_hash_correctness() {
	const StormByte::Safe::String input_data = "HashThisString";
	Hasher::SHA256 sha256;
	FIFO hash;
	ASSERT_TRUE(sha256.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input_data.data()), static_cast<std::size_t>(input_data.size())), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

int test_sha256_hash_mutable_byte_span() {
	StormByte::Safe::Binary input(std::string_view("a\0b", 3));
	const std::span<std::byte> mutable_input = input.span();
	Hasher::SHA256 hasher;
	FIFO hash;
	ASSERT_TRUE(hasher.Hash(mutable_input, hash));
	ASSERT_FALSE(hash.Empty());
	ASSERT_EQUAL(StormByte::Safe::String("59B271AE1BBCB1D31D41929817F4B16FB439EB4F31520B5AD1D5CE98920A7138"), DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

// -------------------
// Distinct inputs
// -------------------

int test_sha256_collision_resistance() {
	const StormByte::Safe::String input_data_1 = "Original Input Data";
	const StormByte::Safe::String input_data_2 = "Original Input Data!";
	Hasher::SHA256 sha256;
	FIFO hash_1_fifo;
	ASSERT_TRUE(sha256.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input_data_1.data()), static_cast<std::size_t>(input_data_1.size())), hash_1_fifo));
	FIFO hash_2_fifo;
	ASSERT_TRUE(sha256.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input_data_2.data()), static_cast<std::size_t>(input_data_2.size())), hash_2_fifo));
	ASSERT_NOT_EQUAL(DeserializeString(hash_1_fifo.Data()), DeserializeString(hash_2_fifo.Data()));
	RETURN_TEST(0);
}

int test_sha256_produces_different_content() {
	const StormByte::Safe::String original_data = "Data to hash";
	Hasher::SHA256 sha256;
	FIFO hash_fifo;
	ASSERT_TRUE(sha256.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(original_data.data()), static_cast<std::size_t>(original_data.size())), hash_fifo));
	ASSERT_NOT_EQUAL(original_data, DeserializeString(hash_fifo.Data()));
	RETURN_TEST(0);
}

// -------------------
// Ownership
// -------------------

int test_sha256_clone() {
	const Hasher::SHA256 source;
	auto cloned = source.Clone();
	ASSERT_TRUE(cloned);
	ASSERT_TRUE(dynamic_cast<Hasher::SHA256*>(cloned.get()) != nullptr);
	ASSERT_TRUE(cloned.get() != &source);
	ASSERT_EQUAL(Hasher::Type::SHA256, cloned->Type());
	FIFO hash;
	ASSERT_TRUE(cloned->Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

int test_sha256_move() {
	Hasher::SHA256 source;
	auto moved = source.Move();
	ASSERT_TRUE(moved);
	ASSERT_TRUE(dynamic_cast<Hasher::SHA256*>(moved.get()) != nullptr);
	ASSERT_TRUE(moved.get() != &source);
	ASSERT_EQUAL(Hasher::Type::SHA256, moved->Type());
	FIFO hash;
	ASSERT_TRUE(moved->Hash(std::string_view("HashThisString"), hash));
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash.Data()));
	RETURN_TEST(0);
}

// -------------------
// Stream
// -------------------

int test_sha256_hash_using_consumer_producer() {
	const StormByte::Safe::String input_data = "HashThisString";
	Hasher::SHA256 sha256;
	StormByte::Buffer::Producer producer;
	ASSERT_TRUE(producer.Write(static_cast<std::string_view>(input_data)));
	producer.Close();
	auto hash_consumer = sha256.Hash(producer.Consumer());
	ASSERT_TRUE(hash_consumer.IsWritable() || !hash_consumer.Empty());
	auto hash_result = ReadAllFromConsumer(hash_consumer);
	ASSERT_FALSE(hash_result.Empty());
	ASSERT_EQUAL(ExpectedHashThisString, DeserializeString(hash_result));
	RETURN_TEST(0);
}

int test_sha256_stream_and_block_equality() {
	const StormByte::Safe::String input_data = "Data to hash for stream and block equality test";
	Hasher::SHA256 sha256;
	FIFO block_hash_fifo;
	ASSERT_TRUE(sha256.Hash(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input_data.data()), static_cast<std::size_t>(input_data.size())), block_hash_fifo));
	const StormByte::Safe::String block_hash = DeserializeString(block_hash_fifo.Data());
	StormByte::Buffer::Producer producer;
	ASSERT_TRUE(producer.Write(static_cast<std::string_view>(input_data)));
	producer.Close();
	auto stream_hash_consumer = sha256.Hash(producer.Consumer());
	ASSERT_TRUE(stream_hash_consumer.IsWritable() || !stream_hash_consumer.Empty());
	auto stream_hash_result = ReadAllFromConsumer(stream_hash_consumer);
	ASSERT_FALSE(stream_hash_result.Empty());
	ASSERT_EQUAL(block_hash, DeserializeString(stream_hash_result));
	RETURN_TEST(0);
}

int main() {
	int result = 0;

	// -------------------
	// Assignment
	// -------------------
	result += test_sha256_copy_assignment();
	result += test_sha256_move_assignment();

	// -------------------
	// Construct
	// -------------------
	result += test_sha256_copy_constructor();
	result += test_sha256_move_constructor();

	// -------------------
	// Correctness
	// -------------------
	result += test_sha256_embedded_nul();
	result += test_sha256_empty_input();
	result += test_sha256_hash_byte_input_ranges();
	result += test_sha256_hash_correctness();
	result += test_sha256_hash_mutable_byte_span();

	// -------------------
	// Distinct inputs
	// -------------------
	result += test_sha256_collision_resistance();
	result += test_sha256_produces_different_content();

	// -------------------
	// Ownership
	// -------------------
	result += test_sha256_clone();
	result += test_sha256_move();

	// -------------------
	// Stream
	// -------------------
	result += test_sha256_hash_using_consumer_producer();
	result += test_sha256_stream_and_block_equality();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
