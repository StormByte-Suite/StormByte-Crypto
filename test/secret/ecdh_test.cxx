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

#include <StormByte/crypto/keypair/x25519.hxx>
#include <StormByte/crypto/secret/ecdh.hxx>
#include <StormByte/safe/string.hxx>
#include <StormByte/test_handlers.h>

#include <string_view>
#include <utility>

using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;

// -------------------
// Construct
// -------------------

int test_ecdh_copy_move_clone() {
	auto local = KeyPair::ECDH::Generate(384);
	auto peer = KeyPair::ECDH::Generate(384);
	ASSERT_TRUE(static_cast<bool>(local));
	ASSERT_TRUE(static_cast<bool>(peer));
	Secret::ECDH original(local, 384);
	const auto expected = original.Share(peer->PublicKey());
	ASSERT_TRUE(expected.has_value());
	ASSERT_FALSE(expected.value().Empty());
	ASSERT_EQUAL(static_cast<std::size_t>(expected.value().Size()), std::size_t{48});
	Secret::ECDH copied(original);
	Secret::ECDH assigned(peer, 256);
	assigned = original;
	Secret::ECDH moved(std::move(copied));
	Secret::ECDH move_assigned(peer, 256);
	move_assigned = std::move(assigned);
	auto clone = original.Clone();
	auto relocated = moved.Move();
	ASSERT_TRUE(static_cast<bool>(clone));
	ASSERT_TRUE(static_cast<bool>(relocated));
	const Secret::Generic* agreements[] = {&original, &move_assigned, clone.get(), relocated.get()};
	for (const Secret::Generic* agreement : agreements) {
		ASSERT_TRUE(agreement->Type() == Secret::Type::ECDH);
		const auto actual = agreement->Share(peer->PublicKey());
		ASSERT_TRUE(actual.has_value());
		ASSERT_TRUE(actual.value() == expected.value());
	}
	RETURN_TEST(0);
}

int test_ecdh_create() {
	auto local = KeyPair::ECDH::Generate(256);
	auto peer = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(static_cast<bool>(local));
	ASSERT_TRUE(static_cast<bool>(peer));
	auto agreement = Secret::Create(Secret::Type::ECDH, local);
	ASSERT_TRUE(static_cast<bool>(agreement));
	ASSERT_TRUE(agreement->Type() == Secret::Type::ECDH);
	Secret::ECDH reciprocal(peer);
	const auto actual = agreement->Share(peer->PublicKey());
	const auto expected = reciprocal.Share(local->PublicKey());
	ASSERT_TRUE(actual.has_value());
	ASSERT_TRUE(expected.has_value());
	ASSERT_TRUE(actual.value() == expected.value());
	RETURN_TEST(0);
}

int test_ecdh_keypair_constructors() {
	auto local = KeyPair::ECDH::Generate(384);
	auto peer = KeyPair::ECDH::Generate(384);
	ASSERT_TRUE(static_cast<bool>(local));
	ASSERT_TRUE(static_cast<bool>(peer));
	KeyPair::ECDH keypair(local->PublicKey(), local->PrivateKey());
	Secret::ECDH copied(keypair, 384);
	Secret::ECDH moved(std::move(keypair), 384);
	Secret::ECDH reciprocal(peer, 384);
	const auto expected = reciprocal.Share(local->PublicKey());
	const auto copied_secret = copied.Share(peer->PublicKey());
	const auto moved_secret = moved.Share(peer->PublicKey());
	ASSERT_TRUE(expected.has_value());
	ASSERT_TRUE(copied_secret.has_value());
	ASSERT_TRUE(moved_secret.has_value());
	ASSERT_TRUE(copied_secret.value() == expected.value());
	ASSERT_TRUE(moved_secret.value() == expected.value());
	RETURN_TEST(0);
}

// -------------------
// Failure modes
// -------------------

int test_ecdh_create_invalid_keys() {
	ASSERT_FALSE(static_cast<bool>(Secret::Create(Secret::Type::ECDH, nullptr)));
	auto mismatched = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(static_cast<bool>(mismatched));
	ASSERT_FALSE(static_cast<bool>(Secret::Create(Secret::Type::ECDH, mismatched)));
	RETURN_TEST(0);
}

int test_ecdh_derive_shared_secret_invalid_key() {
	auto kp = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(static_cast<bool>(kp));
	Secret::ECDH ecdh(kp);
	ASSERT_FALSE(ecdh.Share("InvalidPublicKey").has_value());
	RETURN_TEST(0);
}

int test_ecdh_derive_shared_secret_null_key() {
	Secret::ECDH agreement(nullptr);
	ASSERT_FALSE(agreement.Share("InvalidPublicKey").has_value());
	RETURN_TEST(0);
}

int test_ecdh_malicious_third_party_key() {
	auto alice = KeyPair::ECDH::Generate(256);
	auto bob = KeyPair::ECDH::Generate(256);
	auto mallory = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(static_cast<bool>(alice));
	ASSERT_TRUE(static_cast<bool>(bob));
	ASSERT_TRUE(static_cast<bool>(mallory));
	Secret::ECDH ecdh_alice(alice);
	Secret::ECDH ecdh_bob(bob);
	Secret::ECDH ecdh_mallory(mallory);
	auto ab = ecdh_alice.Share(bob->PublicKey());
	auto ba = ecdh_bob.Share(alice->PublicKey());
	auto ma = ecdh_mallory.Share(alice->PublicKey());
	ASSERT_TRUE(ab.has_value());
	ASSERT_TRUE(ba.has_value());
	ASSERT_TRUE(ma.has_value());
	ASSERT_TRUE(ab.value() == ba.value());
	ASSERT_FALSE(ma.value() == ab.value());
	RETURN_TEST(0);
}

int test_ecdh_share_empty_private_key() {
	auto peer = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(static_cast<bool>(peer));
	auto local = KeyPair::ECDH::MakePointer<KeyPair::ECDH>(peer->PublicKey(), Password());
	ASSERT_TRUE(local->HasPrivateKey());
	ASSERT_TRUE(local->PrivateKey()->Empty());
	Secret::ECDH agreement(local);
	ASSERT_FALSE(agreement.Share(peer->PublicKey()).has_value());
	RETURN_TEST(0);
}

int test_ecdh_share_invalid_curve() {
	auto local = KeyPair::ECDH::Generate(256);
	auto peer = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(static_cast<bool>(local));
	ASSERT_TRUE(static_cast<bool>(peer));
	Secret::ECDH agreement(local, 9999);
	ASSERT_FALSE(agreement.Share(peer->PublicKey()).has_value());
	RETURN_TEST(0);
}

int test_ecdh_share_malformed_peer_keys() {
	auto local = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(static_cast<bool>(local));
	Secret::ECDH agreement(local);
	const StormByte::Safe::String nul_peer(std::string_view{"AA\0AA", 5});
	for (const StormByte::Safe::String& peer : {StormByte::Safe::String(), StormByte::Safe::String("%%%"), StormByte::Safe::String("AQ=="), nul_peer})
		ASSERT_FALSE(agreement.Share(peer).has_value());
	RETURN_TEST(0);
}

int test_ecdh_share_without_private_key() {
	auto full = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(static_cast<bool>(full));
	auto pubOnly = KeyPair::ECDH::MakePointer<KeyPair::ECDH>(full->PublicKey());
	ASSERT_FALSE(pubOnly->HasPrivateKey());
	Secret::ECDH ecdh(pubOnly, 256);
	auto peer = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(static_cast<bool>(peer));
	ASSERT_FALSE(ecdh.Share(peer->PublicKey()).has_value());
	RETURN_TEST(0);
}

int test_ecdh_shared_secret_corrupted_keys() {
	auto kp = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(static_cast<bool>(kp));
	ASSERT_TRUE(kp->HasPrivateKey());
	const std::string_view public_key = kp->PublicKey();
	ASSERT_TRUE(public_key.size() > 1);
	StormByte::Safe::String corrupted(public_key.substr(0, public_key.size() / 2));
	auto badKp = KeyPair::ECDH::MakePointer<KeyPair::ECDH>(
		std::move(corrupted),
		Password("not-a-valid-ecdh-private-key")
	);
	Secret::ECDH ecdh(badKp, 256);
	ASSERT_FALSE(ecdh.Share(kp->PublicKey()).has_value());
	RETURN_TEST(0);
}

int test_ecdh_shared_secret_different_curves() {
	auto kp1 = KeyPair::ECDH::Generate(256);
	auto kp2 = KeyPair::ECDH::Generate(384);
	ASSERT_TRUE(static_cast<bool>(kp1));
	ASSERT_TRUE(static_cast<bool>(kp2));
	Secret::ECDH ecdh1(kp1, 256);
	ASSERT_FALSE(ecdh1.Share(kp2->PublicKey()).has_value());
	RETURN_TEST(0);
}

// -------------------
// Generate
// -------------------

int test_ecdh_generate_key_pair_different_curves() {
	auto kp256 = KeyPair::ECDH::Generate(256);
	auto kp384 = KeyPair::ECDH::Generate(384);
	auto kp521 = KeyPair::ECDH::Generate(521);
	ASSERT_TRUE(static_cast<bool>(kp256));
	ASSERT_TRUE(static_cast<bool>(kp384));
	ASSERT_TRUE(static_cast<bool>(kp521));
	ASSERT_TRUE(kp256->HasPrivateKey() && kp384->HasPrivateKey() && kp521->HasPrivateKey());
	ASSERT_FALSE(kp256->PrivateKey()->Empty());
	ASSERT_FALSE(kp384->PrivateKey()->Empty());
	ASSERT_FALSE(kp521->PrivateKey()->Empty());
	ASSERT_FALSE(kp256->PublicKey().empty());
	ASSERT_FALSE(kp384->PublicKey().empty());
	ASSERT_FALSE(kp521->PublicKey().empty());
	RETURN_TEST(0);
}

int test_ecdh_generate_key_pair_invalid_curve() {
	ASSERT_FALSE(static_cast<bool>(KeyPair::ECDH::Generate(9999)));
	RETURN_TEST(0);
}

int test_ecdh_generate_key_pair_valid_curve() {
	auto kp = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(static_cast<bool>(kp));
	Secret::ECDH ecdh(kp);
	RETURN_TEST(0);
}

// -------------------
// Share
// -------------------

int test_ecdh_derive_shared_secret_valid_keys() {
	auto kp1 = KeyPair::ECDH::Generate(256);
	auto kp2 = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(static_cast<bool>(kp1));
	ASSERT_TRUE(static_cast<bool>(kp2));
	Secret::ECDH ecdh1(kp1);
	Secret::ECDH ecdh2(kp2);
	auto s1 = ecdh1.Share(kp2->PublicKey());
	auto s2 = ecdh2.Share(kp1->PublicKey());
	ASSERT_TRUE(s1.has_value());
	ASSERT_TRUE(s2.has_value());
	ASSERT_TRUE(s1.value() == s2.value());
	RETURN_TEST(0);
}

int test_ecdh_server_client_shared_secret() {
	auto server = KeyPair::ECDH::Generate(256);
	auto client = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(static_cast<bool>(server));
	ASSERT_TRUE(static_cast<bool>(client));
	Secret::ECDH ecdh_server(server);
	Secret::ECDH ecdh_client(client);
	auto s1 = ecdh_server.Share(client->PublicKey());
	auto s2 = ecdh_client.Share(server->PublicKey());
	ASSERT_TRUE(s1.has_value());
	ASSERT_TRUE(s2.has_value());
	ASSERT_TRUE(s1.value() == s2.value());
	RETURN_TEST(0);
}

int test_ecdh_share_all_curves() {
	for (unsigned short bits : {256, 384, 521}) {
		auto a = KeyPair::ECDH::Generate(bits);
		auto b = KeyPair::ECDH::Generate(bits);
		ASSERT_TRUE(static_cast<bool>(a));
		ASSERT_TRUE(static_cast<bool>(b));
		Secret::ECDH ea(a, bits);
		Secret::ECDH eb(b, bits);
		auto s1 = ea.Share(b->PublicKey());
		auto s2 = eb.Share(a->PublicKey());
		ASSERT_TRUE(s1.has_value());
		ASSERT_TRUE(s2.has_value());
		ASSERT_TRUE(s1.value() == s2.value());
	}
	RETURN_TEST(0);
}

int test_ecdh_share_idempotent() {
	auto a = KeyPair::ECDH::Generate(256);
	auto b = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(static_cast<bool>(a));
	ASSERT_TRUE(static_cast<bool>(b));
	Secret::ECDH ecdh(a, 256);
	auto s1 = ecdh.Share(b->PublicKey());
	auto s2 = ecdh.Share(b->PublicKey());
	ASSERT_TRUE(s1.has_value());
	ASSERT_TRUE(s2.has_value());
	ASSERT_TRUE(s1.value() == s2.value());
	RETURN_TEST(0);
}

int main() {
	int result = 0;

	// -------------------
	// Construct
	// -------------------
	result += test_ecdh_copy_move_clone();
	result += test_ecdh_create();
	result += test_ecdh_keypair_constructors();

	// -------------------
	// Failure modes
	// -------------------
	result += test_ecdh_create_invalid_keys();
	result += test_ecdh_derive_shared_secret_invalid_key();
	result += test_ecdh_derive_shared_secret_null_key();
	result += test_ecdh_malicious_third_party_key();
	result += test_ecdh_share_empty_private_key();
	result += test_ecdh_share_invalid_curve();
	result += test_ecdh_share_malformed_peer_keys();
	result += test_ecdh_share_without_private_key();
	result += test_ecdh_shared_secret_corrupted_keys();
	result += test_ecdh_shared_secret_different_curves();

	// -------------------
	// Generate
	// -------------------
	result += test_ecdh_generate_key_pair_different_curves();
	result += test_ecdh_generate_key_pair_invalid_curve();
	result += test_ecdh_generate_key_pair_valid_curve();

	// -------------------
	// Share
	// -------------------
	result += test_ecdh_derive_shared_secret_valid_keys();
	result += test_ecdh_server_client_shared_secret();
	result += test_ecdh_share_all_curves();
	result += test_ecdh_share_idempotent();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
