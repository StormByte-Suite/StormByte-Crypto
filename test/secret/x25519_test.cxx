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

#include <StormByte/crypto/secret/x25519.hxx>
#include <StormByte/test_handlers.h>

using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;

// -------------------
// Generate
// -------------------

int test_x25519_generate_key_pair() {
	const std::string fn_name = "test_x25519_generate_key_pair";
	auto kp = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(fn_name, static_cast<bool>(kp));
	ASSERT_TRUE(fn_name, kp->HasPrivateKey());
	ASSERT_TRUE(fn_name, !kp->PublicKey().empty());
	RETURN_TEST(fn_name, 0);
}

// -------------------
// Share
// -------------------

int test_x25519_derive_shared_secret_valid_keys() {
	const std::string fn_name = "test_x25519_derive_shared_secret_valid_keys";
	auto kp1 = KeyPair::X25519::Generate(256);
	auto kp2 = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(fn_name, static_cast<bool>(kp1));
	ASSERT_TRUE(fn_name, static_cast<bool>(kp2));
	Secret::X25519 a(kp1);
	Secret::X25519 b(kp2);
	auto s1 = a.Share(kp2->PublicKey());
	auto s2 = b.Share(kp1->PublicKey());
	ASSERT_TRUE(fn_name, s1.has_value());
	ASSERT_TRUE(fn_name, s2.has_value());
	ASSERT_TRUE(fn_name, s1.value() == s2.value());
	RETURN_TEST(fn_name, 0);
}

int test_x25519_server_client_shared_secret() {
	const std::string fn_name = "test_x25519_server_client_shared_secret";
	auto server = KeyPair::X25519::Generate(256);
	auto client = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(fn_name, static_cast<bool>(server));
	ASSERT_TRUE(fn_name, static_cast<bool>(client));
	Secret::X25519 xs(server);
	Secret::X25519 xc(client);
	auto s1 = xs.Share(client->PublicKey());
	auto s2 = xc.Share(server->PublicKey());
	ASSERT_TRUE(fn_name, s1.has_value());
	ASSERT_TRUE(fn_name, s2.has_value());
	ASSERT_TRUE(fn_name, s1.value() == s2.value());
	RETURN_TEST(fn_name, 0);
}

int test_x25519_derive_shared_secret_static() {
	const std::string fn_name = "test_x25519_derive_shared_secret_static";
	auto a = KeyPair::X25519::Generate(256);
	auto b = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(fn_name, static_cast<bool>(a));
	ASSERT_TRUE(fn_name, static_cast<bool>(b));
	auto s1 = Secret::X25519::DeriveSharedSecret(a, b->PublicKey());
	auto s2 = Secret::X25519::DeriveSharedSecret(b, a->PublicKey());
	ASSERT_TRUE(fn_name, s1.has_value());
	ASSERT_TRUE(fn_name, s2.has_value());
	ASSERT_TRUE(fn_name, s1.value() == s2.value());
	RETURN_TEST(fn_name, 0);
}

int test_x25519_share_idempotent() {
	const std::string fn_name = "test_x25519_share_idempotent";
	auto a = KeyPair::X25519::Generate(256);
	auto b = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(fn_name, static_cast<bool>(a));
	ASSERT_TRUE(fn_name, static_cast<bool>(b));
	Secret::X25519 x(a);
	auto s1 = x.Share(b->PublicKey());
	auto s2 = x.Share(b->PublicKey());
	ASSERT_TRUE(fn_name, s1.has_value());
	ASSERT_TRUE(fn_name, s2.has_value());
	ASSERT_TRUE(fn_name, s1.value() == s2.value());
	RETURN_TEST(fn_name, 0);
}

// -------------------
// Failure modes
// -------------------

int test_x25519_derive_shared_secret_invalid_key() {
	const std::string fn_name = "test_x25519_derive_shared_secret_invalid_key";
	auto kp = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(fn_name, static_cast<bool>(kp));
	Secret::X25519 x(kp);
	ASSERT_FALSE(fn_name, x.Share("InvalidPublicKey").has_value());
	RETURN_TEST(fn_name, 0);
}

int test_x25519_shared_secret_corrupted_keys() {
	const std::string fn_name = "test_x25519_shared_secret_corrupted_keys";
	auto kp = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(fn_name, static_cast<bool>(kp));
	ASSERT_TRUE(fn_name, kp->HasPrivateKey());
	std::string corrupted { std::string_view{kp->PublicKey()} };
	if (corrupted.size() > 1)
		corrupted = corrupted.substr(0, corrupted.size() / 2);
	auto badKp = KeyPair::X25519::MakePointer<KeyPair::X25519>(
		std::move(corrupted),
		Password("not-a-valid-x25519-private-key")
	);
	Secret::X25519 x(badKp);
	ASSERT_FALSE(fn_name, x.Share(kp->PublicKey()).has_value());
	RETURN_TEST(fn_name, 0);
}

int test_x25519_malicious_third_party_key() {
	const std::string fn_name = "test_x25519_malicious_third_party_key";
	auto alice = KeyPair::X25519::Generate(256);
	auto bob = KeyPair::X25519::Generate(256);
	auto mallory = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(fn_name, static_cast<bool>(alice));
	ASSERT_TRUE(fn_name, static_cast<bool>(bob));
	ASSERT_TRUE(fn_name, static_cast<bool>(mallory));
	Secret::X25519 xa(alice);
	Secret::X25519 xb(bob);
	Secret::X25519 xm(mallory);
	auto ab = xa.Share(bob->PublicKey());
	auto ba = xb.Share(alice->PublicKey());
	auto ma = xm.Share(alice->PublicKey());
	ASSERT_TRUE(fn_name, ab.has_value());
	ASSERT_TRUE(fn_name, ba.has_value());
	ASSERT_TRUE(fn_name, ma.has_value());
	ASSERT_TRUE(fn_name, ab.value() == ba.value());
	ASSERT_FALSE(fn_name, ma.value() == ab.value());
	RETURN_TEST(fn_name, 0);
}

int test_x25519_share_without_private_key() {
	const std::string fn_name = "test_x25519_share_without_private_key";
	auto full = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(fn_name, static_cast<bool>(full));
	auto pubOnly = KeyPair::X25519::MakePointer<KeyPair::X25519>(full->PublicKey());
	Secret::X25519 x(pubOnly);
	auto peer = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(fn_name, static_cast<bool>(peer));
	ASSERT_FALSE(fn_name, x.Share(peer->PublicKey()).has_value());
	RETURN_TEST(fn_name, 0);
}

int test_x25519_shared_secret_snapshot_survives_reset() {
	const std::string fn_name = "test_x25519_shared_secret_snapshot_survives_reset";
	auto alice = KeyPair::X25519::Generate(256);
	auto bob = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(fn_name, static_cast<bool>(alice));
	ASSERT_TRUE(fn_name, static_cast<bool>(bob));
	Secret::X25519 agreement(alice);
	auto result = agreement.Share(bob->PublicKey());
	ASSERT_TRUE(fn_name, result.has_value());
	const Password snapshot = result.value();
	result.reset();
	ASSERT_FALSE(fn_name, result.has_value());
	ASSERT_FALSE(fn_name, snapshot.Empty());
	const auto repeated = agreement.Share(bob->PublicKey());
	ASSERT_TRUE(fn_name, repeated.has_value());
	ASSERT_TRUE(fn_name, snapshot == repeated.value());
	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	// -------------------
	// Generate
	// -------------------
	result += test_x25519_generate_key_pair();

	// -------------------
	// Share
	// -------------------
	result += test_x25519_derive_shared_secret_valid_keys();
	result += test_x25519_server_client_shared_secret();
	result += test_x25519_derive_shared_secret_static();
	result += test_x25519_share_idempotent();
	result += test_x25519_shared_secret_snapshot_survives_reset();

	// -------------------
	// Failure modes
	// -------------------
	result += test_x25519_derive_shared_secret_invalid_key();
	result += test_x25519_shared_secret_corrupted_keys();
	result += test_x25519_malicious_third_party_key();
	result += test_x25519_share_without_private_key();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
