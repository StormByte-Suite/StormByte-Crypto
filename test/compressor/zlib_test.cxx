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
#include <StormByte/crypto/compressor/zlib.hxx>
#include <StormByte/safe/binary.hxx>
#include <StormByte/safe/string.hxx>
#include <StormByte/safe/vector.hxx>
#include <StormByte/test_handlers.h>

#include <algorithm>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>

using StormByte::Buffer::FIFO;
using namespace StormByte::Crypto;

// -------------------
// Class
// -------------------

int test_zlib_clone() {
	const Compressor::Zlib original(9);
	auto clone = original.Clone();
	ASSERT_NOT_NULL(clone);
	ASSERT_EQUAL(clone->Type(), Compressor::Type::Zlib);
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

int test_zlib_copy_assignment() {
	const Compressor::Zlib original(9);
	Compressor::Zlib copied(1);
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

int test_zlib_copy_constructor() {
	const Compressor::Zlib original(1);
	Compressor::Zlib copied(original);
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

int test_zlib_move_assignment() {
	Compressor::Zlib original(9);
	const StormByte::Safe::Binary input(std::string_view("move assignment payload"));
	FIFO expected;
	ASSERT_TRUE(original.Compress(input.span(), expected));
	Compressor::Zlib moved(1);
	moved = std::move(original);
	ASSERT_EQUAL(moved.Type(), Compressor::Type::Zlib);
	ASSERT_EQUAL(moved.Level(), 9);
	FIFO actual;
	ASSERT_TRUE(moved.Compress(input.span(), actual));
	ASSERT_EQUAL(actual.Data(), expected.Data());
	FIFO restored;
	ASSERT_TRUE(moved.Decompress(actual, restored));
	ASSERT_EQUAL(restored.Data(), input);
	RETURN_TEST(0);
}

int test_zlib_move_constructor() {
	Compressor::Zlib original(1);
	const StormByte::Safe::Binary input(std::string_view("move constructor payload"));
	FIFO expected;
	ASSERT_TRUE(original.Compress(input.span(), expected));
	Compressor::Zlib moved(std::move(original));
	ASSERT_EQUAL(moved.Type(), Compressor::Type::Zlib);
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
// Round trip
// -------------------

int test_zlib_byte_input_ranges() {
	const std::string_view input = "Byte input range compression";
	const StormByte::Safe::String expected(input);
	const StormByte::Safe::Vector<std::uint8_t> bytes(input.begin(), input.end());
	Compressor::Zlib compressor;
	FIFO compressed;
	ASSERT_TRUE(compressor.Compress(input, compressed));
	FIFO decompressed;
	ASSERT_TRUE(compressor.Decompress(compressed.Data(), decompressed));
	ASSERT_EQUAL(DeserializeString(decompressed.Data()), expected);
	FIFO span_compressed;
	ASSERT_TRUE(compressor.Compress(std::span<const std::uint8_t>(bytes.data(), bytes.size()), span_compressed));
	FIFO span_decompressed;
	ASSERT_TRUE(compressor.Decompress(span_compressed.Data().span(), span_decompressed));
	ASSERT_EQUAL(DeserializeString(span_decompressed.Data()), expected);
	RETURN_TEST(0);
}

int test_zlib_compress_decompress_buffer() {
	StormByte::Safe::String src(1024, 'A');
	FIFO input;
	StormByte::Safe::Binary bytes(StormByte::ByteSize{static_cast<size_t>(src.size())});
	std::transform(src.begin(), src.end(), bytes.begin(), [](char character) { return static_cast<std::byte>(character); });
	input.Write(bytes);
	Compressor::Zlib compressor;
	FIFO compressed_data;
	ASSERT_TRUE(compressor.Compress(input, compressed_data));
	FIFO decompressed_data;
	ASSERT_TRUE(compressor.Decompress(compressed_data, decompressed_data));
	ASSERT_EQUAL(DeserializeString(decompressed_data.Data()), src);
	RETURN_TEST(0);
}

int test_zlib_compress_decompress_mutable_byte_span() {
	const StormByte::Safe::String expected(std::string_view("a\0b\0", 4));
	StormByte::Safe::Binary input(static_cast<std::string_view>(expected));
	const std::span<std::byte> mutable_input = input.span();
	Compressor::Zlib compressor;
	FIFO compressed;
	ASSERT_TRUE(compressor.Compress(mutable_input, compressed));
	ASSERT_FALSE(compressed.Empty());
	FIFO const_compressed;
	ASSERT_TRUE(compressor.Compress(std::span<const std::byte>{mutable_input}, const_compressed));
	ASSERT_EQUAL(compressed.Data(), const_compressed.Data());
	StormByte::Safe::Binary compressed_bytes(compressed.Data());
	const std::span<std::byte> mutable_compressed = compressed_bytes.span();
	FIFO decompressed;
	ASSERT_TRUE(compressor.Decompress(mutable_compressed, decompressed));
	ASSERT_FALSE(decompressed.Empty());
	ASSERT_EQUAL(decompressed.Data().size(), input.size());
	ASSERT_EQUAL(decompressed.Data(), input);
	ASSERT_EQUAL(DeserializeString(decompressed.Data()), expected);
	RETURN_TEST(0);
}

int test_zlib_compress_decompress_string() {
	const StormByte::Safe::String input = "The quick brown fox jumps over the lazy dog.\n";
	Compressor::Zlib compressor;
	FIFO compressed_data;
	ASSERT_TRUE(compressor.Compress(std::span<const std::byte>(
		reinterpret_cast<const std::byte*>(input.data()), static_cast<size_t>(input.size())), compressed_data));
	ASSERT_FALSE(compressed_data.Empty());
	FIFO decompressed_data;
	ASSERT_TRUE(compressor.Decompress(compressed_data, decompressed_data));
	ASSERT_EQUAL(DeserializeString(decompressed_data.Data()), input);
	RETURN_TEST(0);
}

int test_zlib_compress_level_bounds() {
	const StormByte::Safe::String input = "level-bounds-test-payload";
	for (unsigned short level : {1, 5, 9}) {
		Compressor::Zlib zlib(level);
		FIFO compressed;
		ASSERT_TRUE(zlib.Compress(std::span<const std::byte>(
			reinterpret_cast<const std::byte*>(input.data()), static_cast<size_t>(input.size())), compressed));
		FIFO decompressed;
		ASSERT_TRUE(zlib.Decompress(compressed, decompressed));
		ASSERT_EQUAL(DeserializeString(decompressed.Data()), input);
	}
	RETURN_TEST(0);
}

int test_zlib_embedded_nul() {
	const StormByte::Safe::Binary input{std::byte{0}, std::byte{'A'}, std::byte{0}, std::byte{0xFF}, std::byte{0}};
	Compressor::Zlib zlib;
	FIFO compressed;
	ASSERT_TRUE(zlib.Compress(input.span(), compressed));
	ASSERT_FALSE(compressed.Empty());
	FIFO decompressed;
	ASSERT_TRUE(zlib.Decompress(compressed, decompressed));
	ASSERT_EQUAL(decompressed.Data().size(), input.size());
	ASSERT_EQUAL(decompressed.Data(), input);
	const StormByte::Safe::String restored = DeserializeString(decompressed.Data());
	ASSERT_EQUAL(static_cast<size_t>(restored.size()), static_cast<size_t>(input.size()));
	ASSERT_EQUAL(restored[0], '\0');
	ASSERT_EQUAL(restored[2], '\0');
	ASSERT_EQUAL(restored[4], '\0');
	RETURN_TEST(0);
}

int test_zlib_empty_input() {
	Compressor::Zlib zlib;
	FIFO compressed;
	ASSERT_TRUE(zlib.Compress(std::span<const std::byte>(), compressed));
	FIFO decompressed;
	ASSERT_TRUE(zlib.Decompress(compressed, decompressed));
	ASSERT_TRUE(decompressed.Empty() || DeserializeString(decompressed.Data()).empty());
	RETURN_TEST(0);
}

// -------------------
// Stream
// -------------------

int test_zlib_streaming() {
	StormByte::Safe::String big(256 * 1024, '\0');
	for (size_t i = 0; i < big.size(); ++i)
		big[i] = static_cast<char>('A' + (i % 26));
	StormByte::Buffer::Producer producer;
	auto consumerIn = producer.Consumer();
	const size_t chunk = 8192;
	for (size_t off = 0; off < big.size(); off += chunk) {
		const size_t count = std::min(chunk, static_cast<size_t>(big.size()) - off);
		StormByte::Safe::Binary bytes(StormByte::ByteSize{count});
		std::transform(big.begin() + off, big.begin() + off + count, bytes.begin(),
			[](char character) { return static_cast<std::byte>(character); });
		(void)producer.Write(bytes);
	}
	producer.Close();
	Compressor::Zlib comp;
	auto compressedFifo = ReadAllFromConsumer(comp.Compress(consumerIn));
	Compressor::Zlib decomp;
	FIFO decompressedFifo;
	ASSERT_TRUE(decomp.Decompress(compressedFifo, decompressedFifo));
	ASSERT_EQUAL(DeserializeString(decompressedFifo.Data()), big);
	RETURN_TEST(0);
}

int test_zlib_streaming_decompress() {
	StormByte::Safe::String big(128 * 1024, '\0');
	for (size_t i = 0; i < big.size(); ++i)
		big[i] = static_cast<char>('A' + (i % 26));
	Compressor::Zlib comp;
	FIFO compressedFifo;
	ASSERT_TRUE(comp.Compress(std::span<const std::byte>(
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
	Compressor::Zlib decomp;
	auto decompressedFifo = ReadAllFromConsumer(decomp.Decompress(consumerIn));
	ASSERT_EQUAL(DeserializeString(decompressedFifo.Data()), big);
	RETURN_TEST(0);
}

int test_zlib_streaming_round_trip() {
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
	Compressor::Zlib zlib;
	auto outFifo = ReadAllFromConsumer(zlib.Decompress(zlib.Compress(consumerIn)));
	ASSERT_EQUAL(DeserializeString(outFifo.Data()), big);
	RETURN_TEST(0);
}

int main() {
	int result = 0;

	// -------------------
	// Class
	// -------------------
	result += test_zlib_clone();
	result += test_zlib_copy_assignment();
	result += test_zlib_copy_constructor();
	result += test_zlib_move_assignment();
	result += test_zlib_move_constructor();

	// -------------------
	// Round trip
	// -------------------
	result += test_zlib_byte_input_ranges();
	result += test_zlib_compress_decompress_buffer();
	result += test_zlib_compress_decompress_mutable_byte_span();
	result += test_zlib_compress_decompress_string();
	result += test_zlib_compress_level_bounds();
	result += test_zlib_embedded_nul();
	result += test_zlib_empty_input();

	// -------------------
	// Stream
	// -------------------
	result += test_zlib_streaming();
	result += test_zlib_streaming_decompress();
	result += test_zlib_streaming_round_trip();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
