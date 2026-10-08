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

#include <StormByte/crypto/crypter/exception.hxx>
#include <StormByte/crypto/exception.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/crypto/secure/vault.hxx>
#include <StormByte/safe/string.hxx>
#include <StormByte/test_handlers.h>

#include <string_view>
#include <utility>

using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;
using StormByte::Crypto::Secure::Vault;
using StormByte::Safe::String;

static_assert(StormByte::Type::MaybeSafe<Exception>);
static_assert(StormByte::Type::MaybeSafe<Crypter::Exception>);
static_assert(StormByte::Type::MaybeSafe<Secure::Exception>);
static_assert(StormByte::Type::MaybeSafe<Secure::VaultException>);
static_assert(StormByte::Type::MaybeSafe<Vault>);
static_assert(StormByte::Type::MaybeSafe<StormByte::Crypto::Secure::ExpectedPassword>);
static_assert(!StormByte::Type::SafeValue<Vault>);

// -------------------
// Exceptions
// -------------------

int test_exception_string_view_and_dll_boundary() {
	const String message = "plain message";
	Exception root{std::string_view{message}};
	ASSERT_EQUAL("StormByte.Crypto: plain message", std::string_view(root.what()));

	String owned_message{"owned message"};
	Crypter::Exception component{owned_message};
	ASSERT_EQUAL("StormByte.Crypto.Crypter: owned message", std::string_view(component.what()));

	Crypter::Exception formatted{"failure {}", 42};
	ASSERT_EQUAL("StormByte.Crypto.Crypter: failure 42", std::string_view(formatted.what()));

	Crypter::Exception copied{component};
	Crypter::Exception assigned{"before"};
	assigned = copied;
	Crypter::Exception moved{std::move(copied)};
	ASSERT_EQUAL("StormByte.Crypto.Crypter: owned message", std::string_view(assigned.what()));
	ASSERT_EQUAL("StormByte.Crypto.Crypter: owned message", std::string_view(moved.what()));
	RETURN_TEST(0);
}

// -------------------
// Move
// -------------------

int test_vault_move_assign() {
	Vault source;
	source.Store("alpha", Password("111"));
	source.Store("beta", Password("222"));
	Vault destination;
	destination.Store("old", Password("should-be-wiped"));
	destination = std::move(source);
	ASSERT_TRUE(source.Empty());
	ASSERT_EQUAL(StormByte::Size{2}, destination.Size());
	ASSERT_TRUE(destination.Contains("alpha"));
	ASSERT_TRUE(destination.Contains("beta"));
	ASSERT_FALSE(destination.Contains("old"));
	auto alpha = destination.Get("alpha");
	ASSERT_TRUE(static_cast<bool>(alpha));
	ASSERT_TRUE(*alpha == Password("111"));
	source.Store("reused", Password("333"));
	ASSERT_TRUE(source.Contains("reused"));
	ASSERT_FALSE(destination.Contains("reused"));
	const auto retained = destination.Get("beta");
	ASSERT_TRUE(static_cast<bool>(retained));
	destination.Clear();
	ASSERT_TRUE(*retained == Password("222"));
	destination = std::move(source);
	ASSERT_TRUE(source.Empty());
	ASSERT_TRUE(destination.Contains("reused"));
	RETURN_TEST(0);
}

int test_vault_move_construct() {
	Vault original;
	original.Store("moved", Password("payload"));
	Vault moved(std::move(original));
	ASSERT_TRUE(original.Empty());
	ASSERT_EQUAL(StormByte::Size{0}, original.Size());
	ASSERT_FALSE(moved.Empty());
	ASSERT_TRUE(moved.Contains("moved"));
	auto password = moved.Get("moved");
	ASSERT_TRUE(static_cast<bool>(password));
	ASSERT_TRUE(*password == Password("payload"));
	ASSERT_FALSE(original.Contains("moved"));
	ASSERT_FALSE(static_cast<bool>(original.Get("moved")));
	original.Remove("moved");
	original.Clear();
	original.Store("reused", Password("new payload"));
	ASSERT_TRUE(original.Contains("reused"));
	ASSERT_FALSE(moved.Contains("reused"));
	RETURN_TEST(0);
}

// -------------------
// Password via vault
// -------------------

int test_vault_password_bool_conversion() {
	Password password("non-empty");
	ASSERT_TRUE(static_cast<bool>(password));
	ASSERT_FALSE(password.Empty());
	RETURN_TEST(0);
}

int test_vault_password_operator_equal() {
	Password first("same");
	Password second("same");
	Password different("other");
	ASSERT_TRUE(first == second);
	ASSERT_FALSE(first != second);
	ASSERT_FALSE(first == different);
	ASSERT_TRUE(first != different);
	RETURN_TEST(0);
}

int test_vault_password_retained_after_clear() {
	Vault vault;
	vault.Store("retained", Password("clear-secret"));
	const auto retained = vault.Get("retained");
	ASSERT_TRUE(static_cast<bool>(retained));
	vault.Clear();
	ASSERT_TRUE(vault.Empty());
	ASSERT_FALSE(static_cast<bool>(vault.Get("retained")));
	ASSERT_TRUE(*retained == Password("clear-secret"));
	RETURN_TEST(0);
}

int test_vault_password_retained_after_overwrite() {
	Vault vault;
	vault.Store("retained", Password("original-secret"));
	const auto retained = vault.Get("retained");
	ASSERT_TRUE(static_cast<bool>(retained));
	vault.Store("retained", Password("replacement-secret"));
	const auto replacement = vault.Get("retained");
	ASSERT_TRUE(static_cast<bool>(replacement));
	ASSERT_EQUAL(StormByte::Size{1}, vault.Size());
	ASSERT_TRUE(*replacement == Password("replacement-secret"));
	ASSERT_TRUE(*retained == Password("original-secret"));
	RETURN_TEST(0);
}

int test_vault_password_retained_after_remove() {
	Vault vault;
	vault.Store("retained", Password("remove-secret"));
	const auto retained = vault.Get("retained");
	ASSERT_TRUE(static_cast<bool>(retained));
	vault.Remove("retained");
	ASSERT_TRUE(vault.Empty());
	ASSERT_FALSE(static_cast<bool>(vault.Get("retained")));
	ASSERT_TRUE(*retained == Password("remove-secret"));
	RETURN_TEST(0);
}

int test_vault_password_shared_ownership() {
	Password shared("shared-secret");
	Vault vault;
	vault.Store("ref1", shared);
	vault.Store("ref2", shared);
	auto first = vault.Get("ref1");
	auto second = vault.Get("ref2");
	ASSERT_TRUE(static_cast<bool>(first));
	ASSERT_TRUE(static_cast<bool>(second));
	ASSERT_TRUE(*first == Password("shared-secret"));
	ASSERT_TRUE(*second == Password("shared-secret"));
	ASSERT_TRUE(*first == *second);
	ASSERT_TRUE(shared == Password("shared-secret"));
	RETURN_TEST(0);
}

// -------------------
// Store / get
// -------------------

int test_vault_clear() {
	Vault vault;
	vault.Store("x", Password("aaa"));
	vault.Store("y", Password("bbb"));
	vault.Store("z", Password("ccc"));
	vault.Clear();
	ASSERT_TRUE(vault.Empty());
	ASSERT_EQUAL(StormByte::Size{0}, vault.Size());
	ASSERT_FALSE(vault.Contains("x"));
	ASSERT_FALSE(static_cast<bool>(vault.Get("y")));
	RETURN_TEST(0);
}

int test_vault_empty_on_construct() {
	Vault vault;
	ASSERT_TRUE(vault.Empty());
	ASSERT_EQUAL(StormByte::Size{0}, vault.Size());
	ASSERT_FALSE(vault.Contains("anything"));
	RETURN_TEST(0);
}

int test_vault_get_missing() {
	Vault vault;
	const String missing_name{"nope"};
	const auto empty_missing = vault.Get(missing_name);
	ASSERT_FALSE(static_cast<bool>(empty_missing));
	vault.Store("only", Password("present"));
	const auto missing = vault.Get(missing_name);
	ASSERT_FALSE(static_cast<bool>(missing));
	const std::string_view message = missing.error()->what();
	ASSERT_TRUE(message.find("StormByte.Crypto.Secure.Vault") != std::string_view::npos);
	ASSERT_EQUAL(StormByte::Size{1}, vault.Size());
	ASSERT_FALSE(vault.Contains(missing_name));
	RETURN_TEST(0);
}

int test_vault_overwrite() {
	Vault vault;
	vault.Store("key", Password("first"));
	vault.Store("key", Password("second"));
	ASSERT_EQUAL(StormByte::Size{1}, vault.Size());
	auto password = vault.Get("key");
	ASSERT_TRUE(static_cast<bool>(password));
	ASSERT_TRUE(*password == Password("second"));
	RETURN_TEST(0);
}

int test_vault_remove() {
	Vault vault;
	vault.Store("a", Password("one"));
	vault.Store("b", Password("two"));
	vault.Remove("a");
	ASSERT_FALSE(vault.Contains("a"));
	ASSERT_TRUE(vault.Contains("b"));
	ASSERT_EQUAL(StormByte::Size{1}, vault.Size());
	vault.Remove("does-not-exist");
	ASSERT_EQUAL(StormByte::Size{1}, vault.Size());
	RETURN_TEST(0);
}

int test_vault_restore_after_clear() {
	Vault vault;
	vault.Store("tmp", Password("gone"));
	vault.Clear();
	vault.Store("tmp", Password("back"));
	auto password = vault.Get("tmp");
	ASSERT_TRUE(static_cast<bool>(password));
	ASSERT_TRUE(*password == Password("back"));
	ASSERT_EQUAL(StormByte::Size{1}, vault.Size());
	RETURN_TEST(0);
}

int test_vault_store_and_get() {
	Vault vault;
	vault.Store("db", Password("s3cret"));
	vault.Store("api", Password("token-xyz"));
	ASSERT_FALSE(vault.Empty());
	ASSERT_EQUAL(StormByte::Size{2}, vault.Size());
	ASSERT_TRUE(vault.Contains("db"));
	ASSERT_TRUE(vault.Contains("api"));
	auto database_password = vault.Get("db");
	ASSERT_TRUE(static_cast<bool>(database_password));
	ASSERT_TRUE(*database_password == Password("s3cret"));
	auto api_password = vault.Get("api");
	ASSERT_TRUE(static_cast<bool>(api_password));
	ASSERT_TRUE(*api_password == Password("token-xyz"));
	RETURN_TEST(0);
}

int test_vault_store_copies_safe_names() {
	Vault vault;
	String short_name{"short-name"};
	String long_name(4096, 'B');
	const String original_long_name = long_name;
	vault.Store(short_name, Password("short-secret"));
	vault.Store(long_name, Password("long-secret"));
	short_name[0] = 'X';
	long_name[0] = 'X';
	ASSERT_FALSE(vault.Contains(short_name));
	ASSERT_FALSE(vault.Contains(long_name));
	ASSERT_TRUE(vault.Contains("short-name"));
	ASSERT_TRUE(vault.Contains(original_long_name));
	const auto short_password = vault.Get("short-name");
	const auto long_password = vault.Get(original_long_name);
	ASSERT_TRUE(static_cast<bool>(short_password));
	ASSERT_TRUE(static_cast<bool>(long_password));
	ASSERT_TRUE(*short_password == Password("short-secret"));
	ASSERT_TRUE(*long_password == Password("long-secret"));
	ASSERT_EQUAL(StormByte::Size{2}, vault.Size());
	RETURN_TEST(0);
}

int test_vault_store_from_const_char() {
	Vault vault;
	vault.Store("implicit", Password("from-literal"));
	auto password = vault.Get("implicit");
	ASSERT_TRUE(static_cast<bool>(password));
	ASSERT_FALSE(password->Empty());
	ASSERT_TRUE(*password == Password("from-literal"));
	ASSERT_EQUAL(StormByte::ByteSize{12}, password->Size());
	RETURN_TEST(0);
}

int main() {
	int result = 0;

	// -------------------
	// Exceptions
	// -------------------
	result += test_exception_string_view_and_dll_boundary();

	// -------------------
	// Move
	// -------------------
	result += test_vault_move_assign();
	result += test_vault_move_construct();

	// -------------------
	// Password via vault
	// -------------------
	result += test_vault_password_bool_conversion();
	result += test_vault_password_operator_equal();
	result += test_vault_password_retained_after_clear();
	result += test_vault_password_retained_after_overwrite();
	result += test_vault_password_retained_after_remove();
	result += test_vault_password_shared_ownership();

	// -------------------
	// Store / get
	// -------------------
	result += test_vault_clear();
	result += test_vault_empty_on_construct();
	result += test_vault_get_missing();
	result += test_vault_overwrite();
	result += test_vault_remove();
	result += test_vault_restore_after_clear();
	result += test_vault_store_and_get();
	result += test_vault_store_copies_safe_names();
	result += test_vault_store_from_const_char();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;

	return result;
}
