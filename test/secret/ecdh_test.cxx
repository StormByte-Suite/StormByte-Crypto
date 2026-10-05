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

#include <StormByte/crypto/secret/ecdh.hxx>
#include <StormByte/test_handlers.h>

using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;

// -------------------
// Generate
// -------------------

int test_ecdh_generate_key_pair_valid_curve() {
	const std::string fn_name = "test_ecdh_generate_key_pair_valid_curve";
	auto kp = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(fn_name, static_cast<bool>(kp));
	Secret::ECDH ecdh(kp);
	RETURN_TEST(fn_name, 0);
}

int test_ecdh_generate_key_pair_invalid_curve() {
	const std::string fn_name = "test_ecdh_generate_key_pair_invalid_curve";
	ASSERT_FALSE(fn_name, static_cast<bool>(KeyPair::ECDH::Generate(9999)));
	RETURN_TEST(fn_name, 0);
}

int test_ecdh_generate_key_pair_different_curves() {
	const std::string fn_name = "test_ecdh_generate_key_pair_different_curves";
	auto kp256 = KeyPair::ECDH::Generate(256);
	auto kp384 = KeyPair::ECDH::Generate(384);
	auto kp521 = KeyPair::ECDH::Generate(521);
	ASSERT_TRUE(fn_name, static_cast<bool>(kp256));
	ASSERT_TRUE(fn_name, static_cast<bool>(kp384));
	ASSERT_TRUE(fn_name, static_cast<bool>(kp521));
	ASSERT_TRUE(fn_name, kp256->HasPrivateKey() && kp384->HasPrivateKey() && kp521->HasPrivateKey());
	ASSERT_FALSE(fn_name, kp256->PrivateKey()->Empty());
	ASSERT_FALSE(fn_name, kp384->PrivateKey()->Empty());
	ASSERT_FALSE(fn_name, kp521->PrivateKey()->Empty());
	ASSERT_FALSE(fn_name, kp256->PublicKey().empty());
	ASSERT_FALSE(fn_name, kp384->PublicKey().empty());
	ASSERT_FALSE(fn_name, kp521->PublicKey().empty());
	RETURN_TEST(fn_name, 0);
}

// -------------------
// Share
// -------------------

int test_ecdh_derive_shared_secret_valid_keys() {
	const std::string fn_name = "test_ecdh_derive_shared_secret_valid_keys";
	auto kp1 = KeyPair::ECDH::Generate(256);
	auto kp2 = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(fn_name, static_cast<bool>(kp1));
	ASSERT_TRUE(fn_name, static_cast<bool>(kp2));
	Secret::ECDH ecdh1(kp1);
	Secret::ECDH ecdh2(kp2);
	auto s1 = ecdh1.Share(kp2->PublicKey());
	auto s2 = ecdh2.Share(kp1->PublicKey());
	ASSERT_TRUE(fn_name, s1.has_value());
	ASSERT_TRUE(fn_name, s2.has_value());
	ASSERT_TRUE(fn_name, s1.value() == s2.value());
	RETURN_TEST(fn_name, 0);
}

int test_ecdh_server_client_shared_secret() {
	const std::string fn_name = "test_ecdh_server_client_shared_secret";
	auto server = KeyPair::ECDH::Generate(256);
	auto client = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(fn_name, static_cast<bool>(server));
	ASSERT_TRUE(fn_name, static_cast<bool>(client));
	Secret::ECDH ecdh_server(server);
	Secret::ECDH ecdh_client(client);
	auto s1 = ecdh_server.Share(client->PublicKey());
	auto s2 = ecdh_client.Share(server->PublicKey());
	ASSERT_TRUE(fn_name, s1.has_value());
	ASSERT_TRUE(fn_name, s2.has_value());
	ASSERT_TRUE(fn_name, s1.value() == s2.value());
	RETURN_TEST(fn_name, 0);
}

int test_ecdh_share_all_curves() {
	const std::string fn_name = "test_ecdh_share_all_curves";
	for (unsigned short bits : {256, 384, 521}) {
		auto a = KeyPair::ECDH::Generate(bits);
		auto b = KeyPair::ECDH::Generate(bits);
		ASSERT_TRUE(fn_name, static_cast<bool>(a));
		ASSERT_TRUE(fn_name, static_cast<bool>(b));
		Secret::ECDH ea(a, bits);
		Secret::ECDH eb(b, bits);
		auto s1 = ea.Share(b->PublicKey());
		auto s2 = eb.Share(a->PublicKey());
		ASSERT_TRUE(fn_name, s1.has_value());
		ASSERT_TRUE(fn_name, s2.has_value());
		ASSERT_TRUE(fn_name, s1.value() == s2.value());
	}
	RETURN_TEST(fn_name, 0);
}

int test_ecdh_share_idempotent() {
	const std::string fn_name = "test_ecdh_share_idempotent";
	auto a = KeyPair::ECDH::Generate(256);
	auto b = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(fn_name, static_cast<bool>(a));
	ASSERT_TRUE(fn_name, static_cast<bool>(b));
	Secret::ECDH ecdh(a, 256);
	auto s1 = ecdh.Share(b->PublicKey());
	auto s2 = ecdh.Share(b->PublicKey());
	ASSERT_TRUE(fn_name, s1.has_value());
	ASSERT_TRUE(fn_name, s2.has_value());
	ASSERT_TRUE(fn_name, s1.value() == s2.value());
	RETURN_TEST(fn_name, 0);
}

// -------------------
// Failure modes
// -------------------

int test_ecdh_derive_shared_secret_invalid_key() {
	const std::string fn_name = "test_ecdh_derive_shared_secret_invalid_key";
	auto kp = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(fn_name, static_cast<bool>(kp));
	Secret::ECDH ecdh(kp);
	ASSERT_FALSE(fn_name, ecdh.Share("InvalidPublicKey").has_value());
	RETURN_TEST(fn_name, 0);
}

int test_ecdh_shared_secret_different_curves() {
	const std::string fn_name = "test_ecdh_shared_secret_different_curves";
	auto kp1 = KeyPair::ECDH::Generate(256);
	auto kp2 = KeyPair::ECDH::Generate(384);
	ASSERT_TRUE(fn_name, static_cast<bool>(kp1));
	ASSERT_TRUE(fn_name, static_cast<bool>(kp2));
	Secret::ECDH ecdh1(kp1, 256);
	ASSERT_FALSE(fn_name, ecdh1.Share(kp2->PublicKey()).has_value());
	RETURN_TEST(fn_name, 0);
}

int test_ecdh_shared_secret_corrupted_keys() {
	const std::string fn_name = "test_ecdh_shared_secret_corrupted_keys";
	auto kp = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(fn_name, static_cast<bool>(kp));
	ASSERT_TRUE(fn_name, kp->HasPrivateKey());
	std::string corrupted { std::string_view{kp->PublicKey()} };
	if (corrupted.size() > 1)
		corrupted = corrupted.substr(0, corrupted.size() / 2);
	auto badKp = KeyPair::ECDH::MakePointer<KeyPair::ECDH>(
		std::move(corrupted),
		Password("not-a-valid-ecdh-private-key")
	);
	Secret::ECDH ecdh(badKp, 256);
	ASSERT_FALSE(fn_name, ecdh.Share(kp->PublicKey()).has_value());
	RETURN_TEST(fn_name, 0);
}

int test_ecdh_malicious_third_party_key() {
	const std::string fn_name = "test_ecdh_malicious_third_party_key";
	auto alice = KeyPair::ECDH::Generate(256);
	auto bob = KeyPair::ECDH::Generate(256);
	auto mallory = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(fn_name, static_cast<bool>(alice));
	ASSERT_TRUE(fn_name, static_cast<bool>(bob));
	ASSERT_TRUE(fn_name, static_cast<bool>(mallory));
	Secret::ECDH ecdh_alice(alice);
	Secret::ECDH ecdh_bob(bob);
	Secret::ECDH ecdh_mallory(mallory);
	auto ab = ecdh_alice.Share(bob->PublicKey());
	auto ba = ecdh_bob.Share(alice->PublicKey());
	auto ma = ecdh_mallory.Share(alice->PublicKey());
	ASSERT_TRUE(fn_name, ab.has_value());
	ASSERT_TRUE(fn_name, ba.has_value());
	ASSERT_TRUE(fn_name, ma.has_value());
	ASSERT_TRUE(fn_name, ab.value() == ba.value());
	ASSERT_FALSE(fn_name, ma.value() == ab.value());
	RETURN_TEST(fn_name, 0);
}

int test_ecdh_share_without_private_key() {
	const std::string fn_name = "test_ecdh_share_without_private_key";
	auto full = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(fn_name, static_cast<bool>(full));
	auto pubOnly = KeyPair::ECDH::MakePointer<KeyPair::ECDH>(full->PublicKey());
	Secret::ECDH ecdh(pubOnly, 256);
	auto peer = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(fn_name, static_cast<bool>(peer));
	ASSERT_FALSE(fn_name, ecdh.Share(peer->PublicKey()).has_value());
	RETURN_TEST(fn_name, 0);
}

int main() {
	int result = 0;

	// -------------------
	// Generate
	// -------------------
	result += test_ecdh_generate_key_pair_valid_curve();
	result += test_ecdh_generate_key_pair_invalid_curve();
	result += test_ecdh_generate_key_pair_different_curves();

	// -------------------
	// Share
	// -------------------
	result += test_ecdh_derive_shared_secret_valid_keys();
	result += test_ecdh_server_client_shared_secret();
	result += test_ecdh_share_all_curves();
	result += test_ecdh_share_idempotent();

	// -------------------
	// Failure modes
	// -------------------
	result += test_ecdh_derive_shared_secret_invalid_key();
	result += test_ecdh_shared_secret_different_curves();
	result += test_ecdh_shared_secret_corrupted_keys();
	result += test_ecdh_malicious_third_party_key();
	result += test_ecdh_share_without_private_key();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
