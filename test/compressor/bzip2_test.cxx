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
#include <StormByte/crypto/compressor/bzip2.hxx>
#include <StormByte/safe/binary.hxx>
#include <StormByte/safe/string.hxx>
#include <StormByte/test_handlers.h>

#include <algorithm>
#include <string_view>
#include <utility>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

// -------------------
// Class
// -------------------

int test_bzip2_clone() {
	const Compressor::Bzip2 original(9);
	auto clone = original.Clone();
	ASSERT_NOT_NULL(clone);
	ASSERT_EQUAL(clone->Type(), Compressor::Type::Bzip2);
	ASSERT_EQUAL(clone->Level(), original.Level());
	const StormByte::Safe::Binary input(std::string_view("clone payload"));
	FIFO expected;
	FIFO actual;
	ASSERT_TRUE(original.Compress(input.span(), expected));
	ASSERT_TRUE(clone->Compress(input.span(), actual));
	ASSERT_EQUAL(actual.Data(), expected.Data());
	FIFO restored;
	ASSERT_TRUE(clone->Decompress(actual, restored));
	ASSERT_EQUAL(restored.Data(), input);
	RETURN_TEST(0);
}

int test_bzip2_copy_assignment() {
	const Compressor::Bzip2 original(9);
	Compressor::Bzip2 copied(1);
	copied = original;
	ASSERT_EQUAL(copied.Type(), original.Type());
	ASSERT_EQUAL(copied.Level(), original.Level());
	const StormByte::Safe::Binary input(std::string_view("copy assignment payload"));
	FIFO expected;
	FIFO actual;
	ASSERT_TRUE(original.Compress(input.span(), expected));
	ASSERT_TRUE(copied.Compress(input.span(), actual));
	ASSERT_EQUAL(actual.Data(), expected.Data());
	FIFO restored;
	ASSERT_TRUE(copied.Decompress(actual, restored));
	ASSERT_EQUAL(restored.Data(), input);
	RETURN_TEST(0);
}

int test_bzip2_copy_constructor() {
	const Compressor::Bzip2 original(1);
	Compressor::Bzip2 copied(original);
	ASSERT_EQUAL(copied.Type(), original.Type());
	ASSERT_EQUAL(copied.Level(), original.Level());
	const StormByte::Safe::Binary input(std::string_view("copy constructor payload"));
	FIFO expected;
	FIFO actual;
	ASSERT_TRUE(original.Compress(input.span(), expected));
	ASSERT_TRUE(copied.Compress(input.span(), actual));
	ASSERT_EQUAL(actual.Data(), expected.Data());
	FIFO restored;
	ASSERT_TRUE(copied.Decompress(actual, restored));
	ASSERT_EQUAL(restored.Data(), input);
	RETURN_TEST(0);
}

int test_bzip2_move_assignment() {
	Compressor::Bzip2 original(9);
	const StormByte::Safe::Binary input(std::string_view("move assignment payload"));
	FIFO expected;
	ASSERT_TRUE(original.Compress(input.span(), expected));
	Compressor::Bzip2 moved(1);
	moved = std::move(original);
	ASSERT_EQUAL(moved.Type(), Compressor::Type::Bzip2);
	ASSERT_EQUAL(moved.Level(), 9);
	FIFO actual;
	ASSERT_TRUE(moved.Compress(input.span(), actual));
	ASSERT_EQUAL(actual.Data(), expected.Data());
	FIFO restored;
	ASSERT_TRUE(moved.Decompress(actual, restored));
	ASSERT_EQUAL(restored.Data(), input);
	RETURN_TEST(0);
}

int test_bzip2_move_constructor() {
	Compressor::Bzip2 original(1);
	const StormByte::Safe::Binary input(std::string_view("move constructor payload"));
	FIFO expected;
	ASSERT_TRUE(original.Compress(input.span(), expected));
	Compressor::Bzip2 moved(std::move(original));
	ASSERT_EQUAL(moved.Type(), Compressor::Type::Bzip2);
	ASSERT_EQUAL(moved.Level(), 1);
	FIFO actual;
	ASSERT_TRUE(moved.Compress(input.span(), actual));
	ASSERT_EQUAL(actual.Data(), expected.Data());
	FIFO restored;
	ASSERT_TRUE(moved.Decompress(actual, restored));
	ASSERT_EQUAL(restored.Data(), input);
	RETURN_TEST(0);
}

// -------------------
// Corruption
// -------------------

int test_bzip2_decompress_corrupted_data() {
	const StormByte::Safe::String original_data = "This is some valid data to compress and corrupt.";
	Compressor::Bzip2 bzip2;
	FIFO compressed_data;
	ASSERT_TRUE(bzip2.Compress(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(original_data.data()), static_cast<size_t>(original_data.size())), compressed_data));
	ASSERT_FALSE(compressed_data.Empty());
	StormByte::Safe::String corrupted_string = DeserializeString(compressed_data.Data());
	ASSERT_FALSE(corrupted_string.empty());
	const size_t size = static_cast<size_t>(corrupted_string.size());
	if (size > 10) {
		corrupted_string[4] ^= static_cast<char>(0xFF);
		corrupted_string[size / 2] ^= static_cast<char>(0xFF);
		corrupted_string[size - 3] ^= static_cast<char>(0xFF);
	}
	else if (!corrupted_string.empty())
		corrupted_string[0] ^= static_cast<char>(0xFF);
	FIFO bad_decompress;
	const bool ok = bzip2.Decompress(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(corrupted_string.data()), size), bad_decompress);
	if (ok)
		ASSERT_NOT_EQUAL(DeserializeString(bad_decompress.Data()), original_data);
	RETURN_TEST(0);
}

// -------------------
// Round trip
// -------------------

int test_bzip2_buffer_path() {
	StormByte::Safe::String src(1024, 'B');
	FIFO input;
	StormByte::Safe::Binary bytes(StormByte::ByteSize{static_cast<size_t>(src.size())});
	std::transform(src.begin(), src.end(), bytes.begin(),
		[](char character) { return static_cast<std::byte>(character); });
	input.Write(bytes);
	Compressor::Bzip2 bzip2;
	FIFO compressed;
	ASSERT_TRUE(bzip2.Compress(input, compressed));
	FIFO decompressed;
	ASSERT_TRUE(bzip2.Decompress(compressed, decompressed));
	ASSERT_EQUAL(DeserializeString(decompressed.Data()), src);
	RETURN_TEST(0);
}

int test_bzip2_compress_level_bounds() {
	const StormByte::Safe::String input = "level-bounds-test-payload";
	for (unsigned short level : {1, 5, 9}) {
		Compressor::Bzip2 bzip2(level);
		FIFO compressed;
		ASSERT_TRUE(bzip2.Compress(std::span<const std::byte>(
			reinterpret_cast<const std::byte*>(input.data()), static_cast<size_t>(input.size())), compressed));
		FIFO decompressed;
		ASSERT_TRUE(bzip2.Decompress(compressed, decompressed));
		ASSERT_EQUAL(DeserializeString(decompressed.Data()), input);
	}
	RETURN_TEST(0);
}

int test_bzip2_compression_decompression_integrity() {
	const StormByte::Safe::String input_data = "OriginalDataForIntegrityCheck";
	Compressor::Bzip2 bzip2;
	FIFO compressed_data;
	ASSERT_TRUE(bzip2.Compress(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input_data.data()), static_cast<size_t>(input_data.size())), compressed_data));
	ASSERT_FALSE(compressed_data.Empty());
	FIFO decompressed_data;
	ASSERT_TRUE(bzip2.Decompress(compressed_data, decompressed_data));
	ASSERT_FALSE(decompressed_data.Empty());
	ASSERT_EQUAL(DeserializeString(decompressed_data.Data()), input_data);
	RETURN_TEST(0);
}

int test_bzip2_compression_produces_different_content() {
	const StormByte::Safe::String original_data = "Compress this data";
	Compressor::Bzip2 bzip2;
	FIFO compressed_data;
	ASSERT_TRUE(bzip2.Compress(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(original_data.data()), static_cast<size_t>(original_data.size())), compressed_data));
	ASSERT_FALSE(compressed_data.Empty());
	const StormByte::Safe::String compressed_string = DeserializeString(compressed_data.Data());
	ASSERT_FALSE(compressed_string.empty());
	ASSERT_NOT_EQUAL(compressed_string, original_data);
	RETURN_TEST(0);
}

int test_bzip2_embedded_nul() {
	const StormByte::Safe::Binary input{std::byte{0}, std::byte{'A'}, std::byte{0}, std::byte{0xFF}, std::byte{0}};
	Compressor::Bzip2 bzip2;
	FIFO compressed;
	ASSERT_TRUE(bzip2.Compress(input.span(), compressed));
	ASSERT_FALSE(compressed.Empty());
	FIFO decompressed;
	ASSERT_TRUE(bzip2.Decompress(compressed, decompressed));
	ASSERT_EQUAL(decompressed.Data().size(), input.size());
	ASSERT_EQUAL(decompressed.Data(), input);
	const StormByte::Safe::String restored = DeserializeString(decompressed.Data());
	ASSERT_EQUAL(static_cast<size_t>(restored.size()), static_cast<size_t>(input.size()));
	ASSERT_EQUAL(restored[0], '\0');
	ASSERT_EQUAL(restored[2], '\0');
	ASSERT_EQUAL(restored[4], '\0');
	RETURN_TEST(0);
}

int test_bzip2_empty_input() {
	Compressor::Bzip2 bzip2;
	FIFO compressed;
	ASSERT_TRUE(bzip2.Compress(std::span<const std::byte>(), compressed));
	ASSERT_TRUE(compressed.Empty());
	FIFO decompressed;
	ASSERT_TRUE(bzip2.Decompress(std::span<const std::byte>(), decompressed));
	ASSERT_TRUE(decompressed.Empty());
	RETURN_TEST(0);
}

// -------------------
// Stream
// -------------------

int test_bzip2_compress_decompress_using_consumer_producer() {
	const StormByte::Safe::String input_data = "This is some data to compress using the Consumer/Producer model.";
	Compressor::Bzip2 bzip2;
	StormByte::Buffer::Producer producer;
	producer.Write(input_data);
	producer.Close();
	auto compressed_consumer = bzip2.Compress(producer.Consumer());
	ASSERT_TRUE(compressed_consumer.IsWritable() || !compressed_consumer.Empty());
	auto decompressed_consumer = bzip2.Decompress(compressed_consumer);
	ASSERT_TRUE(decompressed_consumer.IsWritable() || !decompressed_consumer.Empty());
	FIFO decompressed_data = ReadAllFromConsumer(decompressed_consumer);
	ASSERT_FALSE(decompressed_data.Empty());
	ASSERT_EQUAL(input_data, DeserializeString(decompressed_data));
	RETURN_TEST(0);
}

int test_bzip2_streaming_decompress() {
	StormByte::Safe::String big(128 * 1024, '\0');
	for (size_t i = 0; i < big.size(); ++i)
		big[i] = static_cast<char>('A' + (i % 26));
	Compressor::Bzip2 bzip2;
	FIFO compressedFifo;
	ASSERT_TRUE(bzip2.Compress(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(big.data()), static_cast<size_t>(big.size())), compressedFifo));
	ASSERT_FALSE(compressedFifo.Empty());
	StormByte::Buffer::Producer producer;
	auto consumerIn = producer.Consumer();
	const auto& raw = compressedFifo.Data();
	const size_t rawSize = static_cast<size_t>(raw.size());
	const size_t chunk = 4096;
	for (size_t off = 0; off < rawSize; off += chunk) {
		const size_t count = std::min(chunk, rawSize - off);
		StormByte::Safe::Binary bytes(std::span<const std::byte>(raw.data() + off, count));
		(void)producer.Write(bytes);
	}
	producer.Close();
	auto decompressedFifo = ReadAllFromConsumer(bzip2.Decompress(consumerIn));
	ASSERT_EQUAL(DeserializeString(decompressedFifo.Data()), big);
	RETURN_TEST(0);
}

int test_bzip2_streaming_round_trip() {
	StormByte::Safe::String big(64 * 1024, '\0');
	for (size_t i = 0; i < big.size(); ++i)
		big[i] = static_cast<char>('a' + (i % 26));
	StormByte::Buffer::Producer producer;
	auto consumerIn = producer.Consumer();
	const size_t chunk = 2048;
	for (size_t off = 0; off < big.size(); off += chunk) {
		const size_t count = std::min(chunk, static_cast<size_t>(big.size()) - off);
		StormByte::Safe::Binary bytes(StormByte::ByteSize{count});
		std::transform(big.begin() + static_cast<std::ptrdiff_t>(off),
			big.begin() + static_cast<std::ptrdiff_t>(off + count),
			bytes.begin(),
			[](char character) { return static_cast<std::byte>(character); });
		(void)producer.Write(bytes);
	}
	producer.Close();
	Compressor::Bzip2 bzip2;
	auto outFifo = ReadAllFromConsumer(bzip2.Decompress(bzip2.Compress(consumerIn)));
	ASSERT_EQUAL(DeserializeString(outFifo.Data()), big);
	RETURN_TEST(0);
}

int main() {
	int result = 0;

	// -------------------
	// Class
	// -------------------
	result += test_bzip2_clone();
	result += test_bzip2_copy_assignment();
	result += test_bzip2_copy_constructor();
	result += test_bzip2_move_assignment();
	result += test_bzip2_move_constructor();

	// -------------------
	// Corruption
	// -------------------
	result += test_bzip2_decompress_corrupted_data();

	// -------------------
	// Round trip
	// -------------------
	result += test_bzip2_buffer_path();
	result += test_bzip2_compress_level_bounds();
	result += test_bzip2_compression_decompression_integrity();
	result += test_bzip2_compression_produces_different_content();
	result += test_bzip2_embedded_nul();
	result += test_bzip2_empty_input();

	// -------------------
	// Stream
	// -------------------
	result += test_bzip2_compress_decompress_using_consumer_producer();
	result += test_bzip2_streaming_decompress();
	result += test_bzip2_streaming_round_trip();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
