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

#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/safe/binary.hxx>
#include <StormByte/safe/optional.hxx>
#include <StormByte/safe/queue.hxx>
#include <StormByte/safe/string.hxx>
#include <StormByte/safe/vector.hxx>
#include <StormByte/test_handlers.h>

#include <string_view>
#include <utility>

using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;

static_assert(StormByte::Type::MaybeSafe<Password>);
static_assert(StormByte::Type::SafeValue<Password>);
static_assert(sizeof(StormByte::Safe::Vector<Password>) > 0);
static_assert(sizeof(StormByte::Safe::Optional<Password>) > 0);
static_assert(sizeof(StormByte::Safe::Queue<Password>) > 0);

// -------------------
// Assignment
// -------------------

int test_password_copy_assignment() {
	Password source("shared-bytes");
	Password destination("old");
	Password retained(destination);
	ASSERT_TRUE(&(destination = source) == &destination);
	ASSERT_TRUE(destination == source);
	ASSERT_TRUE(retained == Password("old"));
	source = Password();
	ASSERT_TRUE(destination == Password("shared-bytes"));
	destination = source;
	ASSERT_TRUE(destination.Empty());
	RETURN_TEST(0);
}

int test_password_move_assignment() {
	Password source("move-me");
	Password destination("old");
	Password retained(destination);
	ASSERT_TRUE(&(destination = std::move(source)) == &destination);
	ASSERT_TRUE(destination == Password("move-me"));
	ASSERT_TRUE(retained == Password("old"));
	ASSERT_TRUE(source.Empty());
	ASSERT_EQUAL(StormByte::ByteSize{0}, source.Size());
	ASSERT_FALSE(static_cast<bool>(source));
	source = Password("reused");
	ASSERT_TRUE(source == Password("reused"));
	ASSERT_TRUE(destination == Password("move-me"));
	Password empty;
	destination = std::move(empty);
	ASSERT_TRUE(destination.Empty());
	ASSERT_TRUE(empty.Empty());
	RETURN_TEST(0);
}

int test_password_self_assignment() {
	Password password("self");
	Password retained(password);
	Password& alias = password;
	ASSERT_TRUE(&(password = alias) == &password);
	ASSERT_TRUE(password == retained);
	ASSERT_TRUE(&(password = std::move(alias)) == &password);
	ASSERT_TRUE(password == retained);
	Password empty;
	Password& empty_alias = empty;
	empty = empty_alias;
	empty = std::move(empty_alias);
	ASSERT_TRUE(empty.Empty());
	RETURN_TEST(0);
}

// -------------------
// Construction
// -------------------

int test_password_construct_default() {
	Password password;
	ASSERT_TRUE(password.Empty());
	ASSERT_EQUAL(StormByte::ByteSize{0}, password.Size());
	ASSERT_FALSE(static_cast<bool>(password));
	ASSERT_TRUE(password == Password(""));
	password = Password("reused");
	ASSERT_TRUE(password == Password("reused"));
	RETURN_TEST(0);
}

int test_password_construct_from_bytes() {
	const StormByte::Safe::Binary bytes{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}, std::byte{0xff}};
	Password password(bytes.data(), bytes.size());
	ASSERT_FALSE(password.Empty());
	ASSERT_EQUAL(StormByte::ByteSize{5}, password.Size());
	ASSERT_TRUE(password == Password(bytes.data(), bytes.size()));
	ASSERT_EQUAL(std::byte{0xff}, bytes.back());
	RETURN_TEST(0);
}

int test_password_construct_from_c_string() {
	const char raw[] = "secret-value\0ignored";
	Password password(raw);
	ASSERT_FALSE(password.Empty());
	ASSERT_EQUAL(StormByte::ByteSize{12}, password.Size());
	ASSERT_TRUE(static_cast<bool>(password));
	ASSERT_TRUE(password == Password("secret-value"));
	ASSERT_EQUAL('s', raw[0]);
	RETURN_TEST(0);
}

int test_password_construct_from_embedded_nuls() {
	const StormByte::Safe::Binary bytes{std::byte{0}, std::byte{'a'}, std::byte{0}, std::byte{'b'}, std::byte{0}};
	Password password(bytes.data(), bytes.size());
	ASSERT_EQUAL(StormByte::ByteSize{5}, password.Size());
	ASSERT_FALSE(password.Empty());
	ASSERT_TRUE(password == Password(bytes.data(), bytes.size()));
	ASSERT_FALSE(password == Password(""));
	ASSERT_FALSE(password == Password(bytes.data(), StormByte::ByteSize{4}));
	RETURN_TEST(0);
}

int test_password_construct_from_long_string() {
	StormByte::Safe::String raw(StormByte::Size{4096}, 's');
	raw.front() = '\0';
	raw[1024] = '\0';
	raw.back() = '\0';
	Password expected(raw.data(), StormByte::ByteSize{static_cast<std::size_t>(raw.size())});
	Password password{std::string_view{raw}};
	ASSERT_EQUAL(StormByte::Size{4096}, raw.size());
	ASSERT_EQUAL(StormByte::ByteSize{4096}, password.Size());
	ASSERT_TRUE(password == expected);
	raw = std::string_view{"reused"};
	ASSERT_TRUE(password == expected);
	RETURN_TEST(0);
}

int test_password_construct_from_null() {
	Password null_string(static_cast<const char*>(nullptr));
	Password null_bytes(nullptr, StormByte::ByteSize{0});
	Password zero_bytes("ignored", StormByte::ByteSize{0});
	ASSERT_TRUE(null_string.Empty());
	ASSERT_TRUE(null_bytes.Empty());
	ASSERT_TRUE(zero_bytes.Empty());
	ASSERT_TRUE(null_string == Password());
	ASSERT_TRUE(null_bytes == zero_bytes);
	ASSERT_EQUAL(StormByte::ByteSize{0}, null_string.Size());
	ASSERT_EQUAL(StormByte::ByteSize{0}, null_bytes.Size());
	ASSERT_FALSE(static_cast<bool>(zero_bytes));
	RETURN_TEST(0);
}

int test_password_construct_from_safe_string() {
	StormByte::Safe::String bytes(StormByte::Size{4096}, 'x');
	bytes.append("tail");
	StormByte::Safe::String raw(bytes);
	Password password(raw);
	ASSERT_TRUE(raw.empty());
	ASSERT_EQUAL(StormByte::ByteSize{static_cast<std::size_t>(bytes.size())}, password.Size());
	ASSERT_TRUE(password == Password(bytes.data(), StormByte::ByteSize{static_cast<std::size_t>(bytes.size())}));
	raw = StormByte::Safe::String("reused");
	Password reused(raw);
	ASSERT_TRUE(raw.empty());
	ASSERT_TRUE(reused == Password("reused"));
	StormByte::Safe::String short_raw("short");
	Password short_password(short_raw);
	ASSERT_TRUE(short_raw.empty());
	ASSERT_TRUE(short_password == Password("short"));
	StormByte::Safe::String empty;
	Password empty_password(empty);
	ASSERT_TRUE(empty.empty());
	ASSERT_TRUE(empty_password.Empty());
	RETURN_TEST(0);
}

int test_password_construct_from_string_view() {
	StormByte::Safe::String raw = "from-view";
	Password password{std::string_view{raw}};
	ASSERT_TRUE(raw == "from-view");
	ASSERT_FALSE(password.Empty());
	ASSERT_EQUAL(StormByte::ByteSize{9}, password.Size());
	ASSERT_TRUE(password == Password("from-view"));
	raw = std::string_view{"reused"};
	Password reused{std::string_view{raw}};
	ASSERT_TRUE(raw == "reused");
	ASSERT_TRUE(reused == Password("reused"));
	ASSERT_TRUE(password == Password("from-view"));
	Password empty_password{std::string_view{}};
	ASSERT_TRUE(empty_password.Empty());
	const char embedded[] = "\0a\0b\0";
	Password expected(embedded, StormByte::ByteSize{5});
	Password embedded_password{std::string_view{embedded, 5}};
	ASSERT_EQUAL('a', embedded[1]);
	ASSERT_EQUAL(StormByte::ByteSize{5}, embedded_password.Size());
	ASSERT_TRUE(embedded_password == expected);
	Password partial{std::string_view{embedded + 1, 3}};
	ASSERT_EQUAL(StormByte::ByteSize{3}, partial.Size());
	ASSERT_TRUE(partial == Password(embedded + 1, StormByte::ByteSize{3}));
	RETURN_TEST(0);
}

int test_password_empty() {
	Password empty(nullptr, StormByte::ByteSize{0});
	ASSERT_TRUE(empty.Empty());
	ASSERT_EQUAL(StormByte::ByteSize{0}, empty.Size());
	ASSERT_FALSE(static_cast<bool>(empty));
	Password nonempty("x");
	ASSERT_FALSE(nonempty.Empty());
	ASSERT_TRUE(static_cast<bool>(nonempty));
	RETURN_TEST(0);
}

int test_password_safe_string_preserves_embedded_nuls() {
	for (const StormByte::Size length : {StormByte::Size{5}, StormByte::Size{4100}}) {
		StormByte::Safe::String bytes(length, 'x');
		bytes.front() = '\0';
		bytes[length / StormByte::Size{2}] = '\0';
		bytes.back() = '\0';
		StormByte::Safe::String raw(bytes);
		ASSERT_EQUAL(length, raw.size());
		Password expected(bytes.data(), StormByte::ByteSize{static_cast<std::size_t>(length)});
		Password password(raw);
		ASSERT_TRUE(raw.empty());
		ASSERT_EQUAL(StormByte::ByteSize{static_cast<std::size_t>(length)}, password.Size());
		ASSERT_TRUE(password == expected);
		raw = StormByte::Safe::String("replacement");
		ASSERT_TRUE(password == expected);
	}
	RETURN_TEST(0);
}

// -------------------
// Copy
// -------------------

int test_password_copy_empty() {
	Password original;
	Password copy(original);
	ASSERT_TRUE(original.Empty());
	ASSERT_TRUE(copy.Empty());
	ASSERT_TRUE(original == copy);
	copy = Password("replacement");
	ASSERT_TRUE(original.Empty());
	RETURN_TEST(0);
}

int test_password_copy_shares_content() {
	Password original("shared-bytes");
	Password copy(original);
	ASSERT_TRUE(original == copy);
	ASSERT_EQUAL(original.Size(), copy.Size());
	ASSERT_FALSE(original.Empty());
	ASSERT_FALSE(copy.Empty());
	original = Password("replacement");
	ASSERT_TRUE(copy == Password("shared-bytes"));
	RETURN_TEST(0);
}

// -------------------
// Equality
// -------------------

int test_password_binary_not_equal_to_text_of_same_length() {
	const StormByte::Safe::Binary bytes{std::byte{'a'}, std::byte{0}, std::byte{'b'}, std::byte{'c'}};
	Password from_bytes(bytes.data(), bytes.size());
	Password from_text("aabc");
	ASSERT_EQUAL(from_bytes.Size(), from_text.Size());
	ASSERT_FALSE(from_bytes == from_text);
	RETURN_TEST(0);
}

int test_password_equality_different_content() {
	Password first("alpha");
	Password second("beta");
	ASSERT_FALSE(first == second);
	ASSERT_TRUE(first != second);
	ASSERT_FALSE(second == first);
	ASSERT_TRUE(second != first);
	Password same_length("alphb");
	ASSERT_FALSE(first == same_length);
	ASSERT_FALSE(first == Password());
	ASSERT_FALSE(Password() == first);
	RETURN_TEST(0);
}

int test_password_equality_same_content() {
	Password first("same-secret");
	Password second("same-secret");
	ASSERT_TRUE(first == second);
	ASSERT_TRUE(second == first);
	ASSERT_FALSE(first != second);
	ASSERT_TRUE(Password() == Password(""));
	RETURN_TEST(0);
}

int test_password_self_equality() {
	Password password("self");
	ASSERT_TRUE(password == password);
	ASSERT_FALSE(password != password);
	RETURN_TEST(0);
}

// -------------------
// Move
// -------------------

int test_password_move_empty() {
	Password source;
	Password destination(std::move(source));
	ASSERT_TRUE(source.Empty());
	ASSERT_TRUE(destination.Empty());
	source = Password("reused");
	ASSERT_TRUE(source == Password("reused"));
	ASSERT_TRUE(destination.Empty());
	RETURN_TEST(0);
}

int test_password_move_leaves_usable_source() {
	Password source("move-me");
	Password destination(std::move(source));
	ASSERT_FALSE(destination.Empty());
	ASSERT_TRUE(destination == Password("move-me"));
	ASSERT_TRUE(destination.Size() > StormByte::ByteSize{0});
	ASSERT_TRUE(source.Empty());
	ASSERT_EQUAL(StormByte::ByteSize{0}, source.Size());
	ASSERT_FALSE(static_cast<bool>(source));
	source = Password("reused");
	ASSERT_TRUE(source == Password("reused"));
	ASSERT_TRUE(destination == Password("move-me"));
	RETURN_TEST(0);
}

// -------------------
// Ownership
// -------------------

int test_password_shared_owner_survives_scope() {
	Password survivor("");
	{
		StormByte::Safe::String raw("shared secret");
		Password original(raw);
		survivor = original;
	}
	ASSERT_TRUE(survivor == Password("shared secret"));
	Password moved(std::move(survivor));
	ASSERT_TRUE(survivor.Empty());
	ASSERT_TRUE(moved == Password("shared secret"));
	RETURN_TEST(0);
}

int main() {
	int result = 0;

	// -------------------
	// Assignment
	// -------------------
	result += test_password_copy_assignment();
	result += test_password_move_assignment();
	result += test_password_self_assignment();

	// -------------------
	// Construction
	// -------------------
	result += test_password_construct_default();
	result += test_password_construct_from_bytes();
	result += test_password_construct_from_c_string();
	result += test_password_construct_from_embedded_nuls();
	result += test_password_construct_from_long_string();
	result += test_password_construct_from_null();
	result += test_password_construct_from_safe_string();
	result += test_password_construct_from_string_view();
	result += test_password_empty();
	result += test_password_safe_string_preserves_embedded_nuls();

	// -------------------
	// Copy
	// -------------------
	result += test_password_copy_empty();
	result += test_password_copy_shares_content();

	// -------------------
	// Equality
	// -------------------
	result += test_password_binary_not_equal_to_text_of_same_length();
	result += test_password_equality_different_content();
	result += test_password_equality_same_content();
	result += test_password_self_equality();

	// -------------------
	// Move
	// -------------------
	result += test_password_move_empty();
	result += test_password_move_leaves_usable_source();

	// -------------------
	// Ownership
	// -------------------
	result += test_password_shared_owner_survives_scope();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
