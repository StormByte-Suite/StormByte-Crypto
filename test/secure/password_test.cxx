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
#include <StormByte/safe/optional.hxx>
#include <StormByte/safe/queue.hxx>
#include <StormByte/safe/vector.hxx>
#include <StormByte/test_handlers.h>

#include <string>
#include <utility>

using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;

static_assert(StormByte::Type::MaybeSafe<Password>);
static_assert(StormByte::Type::SafeValue<Password>);
static_assert(sizeof(StormByte::Safe::Vector<Password>) > 0);
static_assert(sizeof(StormByte::Safe::Optional<Password>) > 0);
static_assert(sizeof(StormByte::Safe::Queue<Password>) > 0);

// -------------------
// Construction
// -------------------

int test_password_construct_default() {
	const std::string fn_name = "test_password_construct_default";
	Password password;
	ASSERT_TRUE(fn_name, password.Empty());
	ASSERT_EQUAL(fn_name, password.Size(), StormByte::ByteSize{0});
	ASSERT_FALSE(fn_name, static_cast<bool>(password));
	ASSERT_TRUE(fn_name, password == Password(""));
	password = Password("reused");
	ASSERT_TRUE(fn_name, password == Password("reused"));
	RETURN_TEST(fn_name, 0);
}

int test_password_construct_from_c_string() {
	const std::string fn_name = "test_password_construct_from_c_string";
	Password p("secret-value");
	ASSERT_FALSE(fn_name, p.Empty());
	ASSERT_TRUE(fn_name, p.Size() > StormByte::ByteSize{0});
	ASSERT_TRUE(fn_name, static_cast<bool>(p));
	RETURN_TEST(fn_name, 0);
}

int test_password_construct_from_string() {
	const std::string fn_name = "test_password_construct_from_string";
	std::string raw = "from-std-string";
	Password p(raw);
	ASSERT_TRUE(fn_name, raw.empty());
	ASSERT_FALSE(fn_name, p.Empty());
	ASSERT_EQUAL(fn_name, p.Size(), StormByte::ByteSize{std::string("from-std-string").size()});
	RETURN_TEST(fn_name, 0);
}

int test_password_construct_from_safe_string() {
	const std::string fn_name = "test_password_construct_from_safe_string";
	const std::string bytes = std::string(4096, 'x') + "tail";
	StormByte::Safe::String raw{std::string_view{bytes}};
	Password password(raw);
	ASSERT_TRUE(fn_name, raw.empty());
	ASSERT_EQUAL(fn_name, bytes.size(), static_cast<std::size_t>(password.Size()));
	ASSERT_TRUE(fn_name, password == Password(bytes.data(), StormByte::ByteSize{bytes.size()}));
	raw = StormByte::Safe::String("reused");
	Password reused(raw);
	ASSERT_TRUE(fn_name, raw.empty());
	ASSERT_TRUE(fn_name, reused == Password("reused"));
	StormByte::Safe::String empty;
	Password empty_password(empty);
	ASSERT_TRUE(fn_name, empty.empty());
	ASSERT_TRUE(fn_name, empty_password.Empty());
	RETURN_TEST(fn_name, 0);
}

int test_password_construct_from_long_string() {
	const std::string fn_name = "test_password_construct_from_long_string";
	std::string raw(4096, 's');
	raw[1024] = '\0';
	Password expected(raw.data(), StormByte::ByteSize{raw.size()});
	Password password(raw);
	ASSERT_TRUE(fn_name, raw.empty());
	ASSERT_TRUE(fn_name, password == expected);
	RETURN_TEST(fn_name, 0);
}

int test_password_construct_from_bytes() {
	const std::string fn_name = "test_password_construct_from_bytes";
	const unsigned char bytes[] = { 0x01, 0x02, 0x03, 0x04, 0xff };
	Password p(bytes, sizeof(bytes));
	ASSERT_FALSE(fn_name, p.Empty());
	ASSERT_EQUAL(fn_name, p.Size(), StormByte::ByteSize{sizeof(bytes)});
	RETURN_TEST(fn_name, 0);
}

int test_password_empty() {
	const std::string fn_name = "test_password_empty";
	Password empty(static_cast<const void*>(nullptr), 0);
	ASSERT_TRUE(fn_name, empty.Empty());
	ASSERT_EQUAL(fn_name, empty.Size(), StormByte::ByteSize{0});
	ASSERT_FALSE(fn_name, static_cast<bool>(empty));
	Password nonempty("x");
	ASSERT_FALSE(fn_name, nonempty.Empty());
	ASSERT_TRUE(fn_name, static_cast<bool>(nonempty));
	RETURN_TEST(fn_name, 0);
}

// -------------------
// Equality
// -------------------

int test_password_equality_same_content() {
	const std::string fn_name = "test_password_equality_same_content";
	Password a("same-secret");
	Password b("same-secret");
	ASSERT_TRUE(fn_name, a == b);
	ASSERT_FALSE(fn_name, a != b);
	RETURN_TEST(fn_name, 0);
}

int test_password_equality_different_content() {
	const std::string fn_name = "test_password_equality_different_content";
	Password a("alpha");
	Password b("beta");
	ASSERT_FALSE(fn_name, a == b);
	ASSERT_TRUE(fn_name, a != b);
	RETURN_TEST(fn_name, 0);
}

int test_password_self_equality() {
	const std::string fn_name = "test_password_self_equality";
	Password p("self");
	ASSERT_TRUE(fn_name, p == p);
	ASSERT_FALSE(fn_name, p != p);
	RETURN_TEST(fn_name, 0);
}

int test_password_binary_not_equal_to_text_of_same_length() {
	const std::string fn_name = "test_password_binary_not_equal_to_text_of_same_length";
	const unsigned char bin[] = { 'a', 'b', 'c', 0x00 };
	Password fromBytes(bin, sizeof(bin));
	Password fromText("abc");
	ASSERT_FALSE(fn_name, fromBytes == fromText);
	RETURN_TEST(fn_name, 0);
}

// -------------------
// Copy / move
// -------------------

int test_password_copy_shares_content() {
	const std::string fn_name = "test_password_copy_shares_content";
	Password original("shared-bytes");
	Password copy(original);
	ASSERT_TRUE(fn_name, original == copy);
	ASSERT_EQUAL(fn_name, original.Size(), copy.Size());
	ASSERT_FALSE(fn_name, original.Empty());
	ASSERT_FALSE(fn_name, copy.Empty());
	RETURN_TEST(fn_name, 0);
}

int test_password_move_leaves_usable_source() {
	const std::string fn_name = "test_password_move_leaves_usable_source";
	Password source("move-me");
	Password dest(std::move(source));
	ASSERT_FALSE(fn_name, dest.Empty());
	ASSERT_TRUE(fn_name, dest.Size() > StormByte::ByteSize{0});
	(void)source.Empty();
	(void)source.Size();
	RETURN_TEST(fn_name, 0);
}

int test_password_shared_owner_survives_scope() {
	const std::string fn_name = "test_password_shared_owner_survives_scope";
	Password survivor("");
	{
		StormByte::Safe::String raw("shared secret");
		Password original(raw);
		survivor = original;
	}
	ASSERT_TRUE(fn_name, survivor == Password("shared secret"));
	Password moved(std::move(survivor));
	ASSERT_TRUE(fn_name, survivor.Empty());
	ASSERT_TRUE(fn_name, moved == Password("shared secret"));
	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	// -------------------
	// Construction
	// -------------------
	result += test_password_construct_default();
	result += test_password_construct_from_c_string();
	result += test_password_construct_from_string();
	result += test_password_construct_from_safe_string();
	result += test_password_construct_from_long_string();
	result += test_password_construct_from_bytes();
	result += test_password_empty();

	// -------------------
	// Equality
	// -------------------
	result += test_password_equality_same_content();
	result += test_password_equality_different_content();
	result += test_password_self_equality();
	result += test_password_binary_not_equal_to_text_of_same_length();

	// -------------------
	// Copy / move
	// -------------------
	result += test_password_copy_shares_content();
	result += test_password_move_leaves_usable_source();
	result += test_password_shared_owner_survives_scope();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
