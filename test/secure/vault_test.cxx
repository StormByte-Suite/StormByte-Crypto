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

// -------------------
// Store / get
// -------------------

int test_vault_empty_on_construct() {
	const std::string fn_name = "test_vault_empty_on_construct";
	Vault vault;
	ASSERT_TRUE(fn_name, vault.Empty());
	ASSERT_EQUAL(fn_name, vault.Size(), StormByte::Size{0});
	ASSERT_FALSE(fn_name, vault.Contains("anything"));
	RETURN_TEST(fn_name, 0);
}

int test_vault_store_and_get() {
	const std::string fn_name = "test_vault_store_and_get";
	Vault vault;
	vault.Store("db", Password("s3cret"));
	vault.Store("api", Password("token-xyz"));
	ASSERT_FALSE(fn_name, vault.Empty());
	ASSERT_EQUAL(fn_name, vault.Size(), StormByte::Size{2});
	ASSERT_TRUE(fn_name, vault.Contains("db"));
	ASSERT_TRUE(fn_name, vault.Contains("api"));
	auto db = vault.Get("db");
	ASSERT_TRUE(fn_name, static_cast<bool>(db));
	ASSERT_TRUE(fn_name, *db == Password("s3cret"));
	auto api = vault.Get("api");
	ASSERT_TRUE(fn_name, static_cast<bool>(api));
	ASSERT_TRUE(fn_name, *api == Password("token-xyz"));
	RETURN_TEST(fn_name, 0);
}

int test_vault_get_missing() {
	const std::string fn_name = "test_vault_get_missing";
	Vault vault;
	vault.Store("only", Password("present"));
	auto missing = vault.Get("nope");
	ASSERT_FALSE(fn_name, static_cast<bool>(missing));
	const std::string message = missing.error()->what();
	ASSERT_TRUE(fn_name, message.find("StormByte.Crypto.Secure.Vault") != std::string::npos);
	RETURN_TEST(fn_name, 0);
}

int test_exception_string_view_and_dll_boundary() {
	const std::string fn_name = "test_exception_string_view_and_dll_boundary";
	const std::string message = "plain message";
	Exception root{std::string_view{message}};
	ASSERT_EQUAL(fn_name, std::string(root.what()), "StormByte.Crypto: plain message");

	StormByte::Safe::String owned_message{std::string_view{"owned message"}};
	Crypter::Exception component{owned_message};
	ASSERT_EQUAL(fn_name, std::string(component.what()), "StormByte.Crypto.Crypter: owned message");

	Crypter::Exception formatted{"failure {}", 42};
	ASSERT_EQUAL(fn_name, std::string(formatted.what()), "StormByte.Crypto.Crypter: failure 42");

	Crypter::Exception copied{component};
	Crypter::Exception assigned{"before"};
	assigned = copied;
	Crypter::Exception moved{std::move(copied)};
	ASSERT_EQUAL(fn_name, std::string(assigned.what()), "StormByte.Crypto.Crypter: owned message");
	ASSERT_EQUAL(fn_name, std::string(moved.what()), "StormByte.Crypto.Crypter: owned message");
	RETURN_TEST(fn_name, 0);
}

int test_vault_overwrite() {
	const std::string fn_name = "test_vault_overwrite";
	Vault vault;
	vault.Store("key", Password("first"));
	vault.Store("key", Password("second"));
	ASSERT_EQUAL(fn_name, vault.Size(), StormByte::Size{1});
	auto pwd = vault.Get("key");
	ASSERT_TRUE(fn_name, static_cast<bool>(pwd));
	ASSERT_TRUE(fn_name, *pwd == Password("second"));
	RETURN_TEST(fn_name, 0);
}

int test_vault_remove() {
	const std::string fn_name = "test_vault_remove";
	Vault vault;
	vault.Store("a", Password("one"));
	vault.Store("b", Password("two"));
	vault.Remove("a");
	ASSERT_FALSE(fn_name, vault.Contains("a"));
	ASSERT_TRUE(fn_name, vault.Contains("b"));
	ASSERT_EQUAL(fn_name, vault.Size(), StormByte::Size{1});
	vault.Remove("does-not-exist");
	ASSERT_EQUAL(fn_name, vault.Size(), StormByte::Size{1});
	RETURN_TEST(fn_name, 0);
}

int test_vault_clear() {
	const std::string fn_name = "test_vault_clear";
	Vault vault;
	vault.Store("x", Password("aaa"));
	vault.Store("y", Password("bbb"));
	vault.Store("z", Password("ccc"));
	vault.Clear();
	ASSERT_TRUE(fn_name, vault.Empty());
	ASSERT_EQUAL(fn_name, vault.Size(), StormByte::Size{0});
	ASSERT_FALSE(fn_name, vault.Contains("x"));
	ASSERT_FALSE(fn_name, static_cast<bool>(vault.Get("y")));
	RETURN_TEST(fn_name, 0);
}

int test_vault_restore_after_clear() {
	const std::string fn_name = "test_vault_restore_after_clear";
	Vault vault;
	vault.Store("tmp", Password("gone"));
	vault.Clear();
	vault.Store("tmp", Password("back"));
	auto pwd = vault.Get("tmp");
	ASSERT_TRUE(fn_name, static_cast<bool>(pwd));
	ASSERT_TRUE(fn_name, *pwd == Password("back"));
	ASSERT_EQUAL(fn_name, vault.Size(), StormByte::Size{1});
	RETURN_TEST(fn_name, 0);
}

int test_vault_store_from_const_char() {
	const std::string fn_name = "test_vault_store_from_const_char";
	Vault vault;
	vault.Store("implicit", Password("from-literal"));
	auto pwd = vault.Get("implicit");
	ASSERT_TRUE(fn_name, static_cast<bool>(pwd));
	ASSERT_FALSE(fn_name, pwd->Empty());
	ASSERT_TRUE(fn_name, *pwd == Password("from-literal"));
	ASSERT_EQUAL(fn_name, pwd->Size(), StormByte::ByteSize{12});
	RETURN_TEST(fn_name, 0);
}

// -------------------
// Move
// -------------------

int test_vault_move_construct() {
	const std::string fn_name = "test_vault_move_construct";
	Vault original;
	original.Store("moved", Password("payload"));
	Vault moved(std::move(original));
	ASSERT_TRUE(fn_name, original.Empty());
	ASSERT_EQUAL(fn_name, original.Size(), StormByte::Size{0});
	ASSERT_FALSE(fn_name, moved.Empty());
	ASSERT_TRUE(fn_name, moved.Contains("moved"));
	auto pwd = moved.Get("moved");
	ASSERT_TRUE(fn_name, static_cast<bool>(pwd));
	ASSERT_TRUE(fn_name, *pwd == Password("payload"));
	RETURN_TEST(fn_name, 0);
}

int test_vault_move_assign() {
	const std::string fn_name = "test_vault_move_assign";
	Vault src;
	src.Store("alpha", Password("111"));
	src.Store("beta", Password("222"));
	Vault dst;
	dst.Store("old", Password("should-be-wiped"));
	dst = std::move(src);
	ASSERT_TRUE(fn_name, src.Empty());
	ASSERT_EQUAL(fn_name, dst.Size(), StormByte::Size{2});
	ASSERT_TRUE(fn_name, dst.Contains("alpha"));
	ASSERT_TRUE(fn_name, dst.Contains("beta"));
	ASSERT_FALSE(fn_name, dst.Contains("old"));
	auto alpha = dst.Get("alpha");
	ASSERT_TRUE(fn_name, static_cast<bool>(alpha));
	ASSERT_TRUE(fn_name, *alpha == Password("111"));
	RETURN_TEST(fn_name, 0);
}

// -------------------
// Password via vault
// -------------------

int test_vault_password_shared_ownership() {
	const std::string fn_name = "test_vault_password_shared_ownership";
	Password shared("shared-secret");
	Vault vault;
	vault.Store("ref1", shared);
	vault.Store("ref2", shared);
	auto a = vault.Get("ref1");
	auto b = vault.Get("ref2");
	ASSERT_TRUE(fn_name, static_cast<bool>(a));
	ASSERT_TRUE(fn_name, static_cast<bool>(b));
	ASSERT_TRUE(fn_name, *a == Password("shared-secret"));
	ASSERT_TRUE(fn_name, *b == Password("shared-secret"));
	ASSERT_TRUE(fn_name, *a == *b);
	ASSERT_TRUE(fn_name, shared == Password("shared-secret"));
	RETURN_TEST(fn_name, 0);
}

int test_vault_password_bool_conversion() {
	const std::string fn_name = "test_vault_password_bool_conversion";
	Password p("non-empty");
	ASSERT_TRUE(fn_name, static_cast<bool>(p));
	ASSERT_FALSE(fn_name, p.Empty());
	RETURN_TEST(fn_name, 0);
}

int test_vault_password_operator_equal() {
	const std::string fn_name = "test_vault_password_operator_equal";
	Password a("same");
	Password b("same");
	Password c("other");
	ASSERT_TRUE(fn_name, a == b);
	ASSERT_FALSE(fn_name, a != b);
	ASSERT_FALSE(fn_name, a == c);
	ASSERT_TRUE(fn_name, a != c);
	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	// -------------------
	// Store / get
	// -------------------
	result += test_vault_empty_on_construct();
	result += test_vault_store_and_get();
	result += test_vault_get_missing();
	result += test_exception_string_view_and_dll_boundary();
	result += test_vault_overwrite();
	result += test_vault_remove();
	result += test_vault_clear();
	result += test_vault_restore_after_clear();
	result += test_vault_store_from_const_char();

	// -------------------
	// Move
	// -------------------
	result += test_vault_move_construct();
	result += test_vault_move_assign();

	// -------------------
	// Password via vault
	// -------------------
	result += test_vault_password_shared_ownership();
	result += test_vault_password_bool_conversion();
	result += test_vault_password_operator_equal();

	if (result == 0) {
		std::cout << "All tests passed!" << std::endl;
	} else {
		std::cout << result << " tests failed." << std::endl;
	}

	return result;
}
