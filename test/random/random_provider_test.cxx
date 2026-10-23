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

#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/rng.hxx>
#include <StormByte/test_handlers.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <string_view>

using namespace StormByte;
using namespace StormByte::Crypto;

namespace {
	/**
	 * @brief Provider responses selected only by this isolated test executable.
	 */
	enum class Mode {
		Bytes,
		FailGeneration,
		FailInitialization,
		Text
	};

	Mode Response = Mode::Bytes;	///< Current deterministic provider response.
	std::size_t Calls = 0;	///< Number of block generation requests.
	std::size_t Requests = 0;	///< Number of RNG accesses, including failed initialization.

	/**
	 * @brief Deterministic provider replacing RNG only in this executable.
	 */
	class Provider final: public CryptoPP::AutoSeededRandomPool {
		public:
			/**
			 * @brief Construct the test provider.
			 */
			Provider() = default;

			Provider(const Provider& other) = delete;

			Provider(Provider&& other) = delete;

			/**
			 * @brief Release provider storage.
			 */
			~Provider() override = default;

			Provider& operator=(const Provider& other) = delete;

			Provider& operator=(Provider&& other) = delete;

			/**
			 * @brief Write predictable bytes or fail after writing partial output.
			 * @param output Provider destination.
			 * @param count Requested byte count.
			 */
			void GenerateBlock(CryptoPP::byte* output, std::size_t count) override {
				++Calls;
				if (Response == Mode::FailGeneration) {
					if (count == sizeof(CryptoPP::word32) && Calls < 3) {
						std::fill_n(output, count, CryptoPP::byte{0});
						return;
					}
					std::fill_n(output, count / 2, CryptoPP::byte{0xAA});
					throw CryptoPP::Exception(CryptoPP::Exception::OTHER_ERROR, "forced generation failure");
				}
				if (Response == Mode::Text) {
					const CryptoPP::word32 value = Calls == 1 ? 127 : (Calls % 2 == 0 ? 0 : 93);
					if (count != sizeof(value))
						throw CryptoPP::Exception(CryptoPP::Exception::OTHER_ERROR, "unexpected sample size");
					std::memcpy(output, &value, count);
					return;
				}
				for (std::size_t index = 0; index < count; ++index)
					output[index] = static_cast<CryptoPP::byte>(index % 251);
			}
	};
}

CryptoPP::AutoSeededRandomPool& StormByte::Crypto::RNG() {
	++Requests;
	if (Response == Mode::FailInitialization)
		throw CryptoPP::Exception(CryptoPP::Exception::OTHER_ERROR, "forced initialization failure");
	static Provider provider;
	return provider;
}

// -------------------
// Generation
// -------------------

int test_bytes_complete_output() {
	Response = Mode::Bytes;
	Calls = 0;
	const auto bytes = Random::Bytes(ByteSize{4096});
	ASSERT_EQUAL(ByteSize{4096}, bytes.size());
	ASSERT_EQUAL(std::size_t{1}, Calls);
	for (std::size_t index = 0; index < 4096; ++index)
		ASSERT_EQUAL(static_cast<std::byte>(index % 251), bytes[ByteSize{index}]);
	RETURN_TEST(0);
}

int test_text_rejection_and_endpoints() {
	Response = Mode::Text;
	Calls = 0;
	const auto text = Random::Text(Size{4});
	ASSERT_EQUAL(Safe::String("!~!~"), text);
	ASSERT_EQUAL(std::size_t{5}, Calls);
	RETURN_TEST(0);
}

// -------------------
// Provider failures
// -------------------

int test_provider_failures() {
	for (const auto mode : {Mode::FailGeneration, Mode::FailInitialization}) {
		Response = mode;
		Calls = 0;
		Safe::SecureBinary bytes("unchanged");
		try {
			bytes = Random::Bytes(ByteSize{32});
			RETURN_TEST(1);
		} catch (const Random::Exception& error) {
			ASSERT_TRUE(std::string_view(error.what()).starts_with("StormByte.Crypto.Random: "));
			ASSERT_TRUE(std::string_view(error.what()).find("forced") != std::string_view::npos);
		}
		ASSERT_EQUAL(Safe::SecureBinary("unchanged"), bytes);
		Calls = 0;
		Safe::String text("unchanged");
		try {
			text = Random::Text(Size{32});
			RETURN_TEST(1);
		} catch (const Random::Exception& error) {
			ASSERT_TRUE(std::string_view(error.what()).starts_with("StormByte.Crypto.Random: "));
			ASSERT_TRUE(std::string_view(error.what()).find("forced") != std::string_view::npos);
		}
		ASSERT_EQUAL(Safe::String("unchanged"), text);
		if (mode == Mode::FailGeneration)
			ASSERT_EQUAL(std::size_t{3}, Calls);
	}
	RETURN_TEST(0);
}

int test_zero_without_provider() {
	Response = Mode::FailInitialization;
	Calls = 0;
	Requests = 0;
	ASSERT_THROWS(Random::Bytes(ByteSize{0}), Random::Exception);
	ASSERT_THROWS(Random::Text(Size{0}), Random::Exception);
	ASSERT_EQUAL(std::size_t{0}, Calls);
	ASSERT_EQUAL(std::size_t{0}, Requests);
	RETURN_TEST(0);
}

int main() {
	int result = 0;

	// -------------------
	// Generation
	// -------------------
	result += test_bytes_complete_output();
	result += test_text_rejection_and_endpoints();

	// -------------------
	// Provider failures
	// -------------------
	result += test_provider_failures();
	result += test_zero_without_provider();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
