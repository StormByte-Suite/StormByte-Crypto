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

#include <StormByte/crypto/crypter/symmetric/generic.hxx>
#include <StormByte/crypto/random.hxx>
#include <StormByte/test_handlers.h>

#include <cstddef>
#include <string_view>
#include <type_traits>
#include <utility>

using namespace StormByte;
using namespace StormByte::Crypto;

static_assert(std::is_same_v<decltype(Random::Bytes(ByteSize{1})), Safe::SecureBinary>);

// -------------------
// Bytes
// -------------------

int test_bytes_independent_storage() {
	auto first = Random::Bytes(ByteSize{256});
	const Safe::SecureBinary snapshot(first);
	auto second = Random::Bytes(ByteSize{256});
	ASSERT_TRUE(first.data() != second.data());
	ASSERT_EQUAL(snapshot, first);
	for (auto& byte : second)
		byte = std::byte{0};
	ASSERT_EQUAL(snapshot, first);
	first.front() ^= std::byte{0xFF};
	ASSERT_EQUAL(std::byte{0}, second.front());
	RETURN_TEST(0);
}

int test_bytes_secure_ownership() {
	auto source = Random::Bytes(ByteSize{32});
	const Safe::SecureBinary snapshot(source);
	Safe::SecureBinary moved(std::move(source));
	ASSERT_TRUE(source.empty());
	ASSERT_EQUAL(snapshot, moved);
	auto destination = Random::Bytes(ByteSize{16});
	destination = std::move(moved);
	ASSERT_TRUE(moved.empty());
	ASSERT_EQUAL(snapshot, destination);
	destination.clear();
	ASSERT_TRUE(destination.empty());
	ASSERT_EQUAL(ByteSize{32}, snapshot.size());
	RETURN_TEST(0);
}

int test_bytes_sizes() {
	for (const std::size_t count : {1, 16, 32, 4096, 65536}) {
		const auto bytes = Random::Bytes(ByteSize{count});
		ASSERT_EQUAL(ByteSize{count}, bytes.size());
		ASSERT_EQUAL(count, bytes.span().size_bytes());
		ASSERT_TRUE(bytes.data() != nullptr);
	}
	RETURN_TEST(0);
}

int test_bytes_zero() {
	Safe::SecureBinary output("unchanged");
	try {
		output = Random::Bytes(ByteSize{0});
		RETURN_TEST(1);
	} catch (const Random::Exception& error) {
		ASSERT_TRUE(std::string_view(error.what()).starts_with("StormByte.Crypto.Random: "));
	}
	ASSERT_EQUAL(Safe::SecureBinary("unchanged"), output);
	ASSERT_NO_THROW(Random::Bytes(ByteSize{1}));
	RETURN_TEST(0);
}

// -------------------
// Exception
// -------------------

int test_exception_value_semantics() {
	Random::Exception source("Provider failed: {}", "test");
	Random::Exception copy(source);
	Random::Exception moved(std::move(copy));
	Random::Exception assigned("old");
	assigned = source;
	Random::Exception move_assigned("old");
	move_assigned = std::move(assigned);
	const std::string_view expected("StormByte.Crypto.Random: Provider failed: test");
	ASSERT_EQUAL(expected, std::string_view(source.what()));
	ASSERT_EQUAL(expected, std::string_view(moved.what()));
	ASSERT_EQUAL(expected, std::string_view(move_assigned.what()));
	ASSERT_THROWS(Random::Bytes(ByteSize{0}), Crypto::Exception);
	ASSERT_THROWS(Random::Text(Size{0}), StormByte::Exception);
	RETURN_TEST(0);
}

// -------------------
// Password regression
// -------------------

int test_random_password_sizes() {
	ASSERT_EQUAL(ByteSize{32}, Crypter::Symmetric::RandomPassword().Size());
	ASSERT_TRUE(Crypter::Symmetric::RandomPassword(0).Empty());
	for (const std::size_t count : {1, 16, 32, 256}) {
		const auto password = Crypter::Symmetric::RandomPassword(count);
		ASSERT_FALSE(password.Empty());
		ASSERT_EQUAL(ByteSize{count}, password.Size());
	}
	RETURN_TEST(0);
}

// -------------------
// Text
// -------------------

int test_text_independent_storage() {
	auto first = Random::Text(Size{256});
	const Safe::String snapshot(first);
	auto second = Random::Text(Size{256});
	ASSERT_TRUE(first.data() != second.data());
	ASSERT_EQUAL(snapshot, first);
	for (auto& character : second)
		character = '\0';
	ASSERT_EQUAL(snapshot, first);
	first[Size{0}] = '!';
	ASSERT_EQUAL('\0', second[Size{0}]);
	RETURN_TEST(0);
}

int test_text_sizes_and_alphabet() {
	for (const std::size_t count : {1, 16, 32, 4096}) {
		const auto text = Random::Text(Size{count});
		ASSERT_EQUAL(Size{count}, text.size());
		for (const unsigned char character : text) {
			ASSERT_TRUE(character >= 33);
			ASSERT_TRUE(character <= 126);
		}
		ASSERT_EQUAL('\0', text.data()[count]);
	}
	RETURN_TEST(0);
}

int test_text_zero() {
	Safe::String output("unchanged");
	try {
		output = Random::Text(Size{0});
		RETURN_TEST(1);
	} catch (const Random::Exception& error) {
		ASSERT_TRUE(std::string_view(error.what()).starts_with("StormByte.Crypto.Random: "));
	}
	ASSERT_EQUAL(Safe::String("unchanged"), output);
	ASSERT_NO_THROW(Random::Text(Size{1}));
	RETURN_TEST(0);
}

int main() {
	int result = 0;

	// -------------------
	// Bytes
	// -------------------
	result += test_bytes_independent_storage();
	result += test_bytes_secure_ownership();
	result += test_bytes_sizes();
	result += test_bytes_zero();

	// -------------------
	// Exception
	// -------------------
	result += test_exception_value_semantics();

	// -------------------
	// Password regression
	// -------------------
	result += test_random_password_sizes();

	// -------------------
	// Text
	// -------------------
	result += test_text_independent_storage();
	result += test_text_sizes_and_alphabet();
	result += test_text_zero();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
