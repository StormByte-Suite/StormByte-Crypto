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

#include <StormByte/crypto/keypair/ecdh.hxx>
#include <StormByte/crypto/secret/x25519.hxx>
#include <StormByte/safe/string.hxx>
#include <StormByte/test_handlers.h>

#include <string_view>
#include <utility>

using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;

// -------------------
// Construct
// -------------------

int test_x25519_copy_move_clone() {
	auto local = KeyPair::X25519::Generate(256);
	auto peer = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(static_cast<bool>(local));
	ASSERT_TRUE(static_cast<bool>(peer));
	Secret::X25519 original(local);
	const auto expected = original.Share(peer->PublicKey());
	ASSERT_TRUE(expected.has_value());
	ASSERT_FALSE(expected.value().Empty());
	ASSERT_EQUAL(static_cast<std::size_t>(expected.value().Size()), std::size_t{32});
	Secret::X25519 copied(original);
	Secret::X25519 assigned(peer);
	assigned = original;
	Secret::X25519 moved(std::move(copied));
	Secret::X25519 move_assigned(peer);
	move_assigned = std::move(assigned);
	auto clone = original.Clone();
	auto relocated = moved.Move();
	ASSERT_TRUE(static_cast<bool>(clone));
	ASSERT_TRUE(static_cast<bool>(relocated));
	const Secret::Generic* agreements[] = {&original, &move_assigned, clone.get(), relocated.get()};
	for (const Secret::Generic* agreement : agreements) {
		ASSERT_TRUE(agreement->Type() == Secret::Type::X25519);
		const auto actual = agreement->Share(peer->PublicKey());
		ASSERT_TRUE(actual.has_value());
		ASSERT_TRUE(actual.value() == expected.value());
	}
	RETURN_TEST(0);
}

int test_x25519_create() {
	auto local = KeyPair::X25519::Generate(256);
	auto peer = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(static_cast<bool>(local));
	ASSERT_TRUE(static_cast<bool>(peer));
	auto agreement = Secret::Create(Secret::Type::X25519, local);
	ASSERT_TRUE(static_cast<bool>(agreement));
	ASSERT_TRUE(agreement->Type() == Secret::Type::X25519);
	const auto actual = agreement->Share(peer->PublicKey());
	const auto expected = Secret::X25519::DeriveSharedSecret(peer, local->PublicKey());
	ASSERT_TRUE(actual.has_value());
	ASSERT_TRUE(expected.has_value());
	ASSERT_TRUE(actual.value() == expected.value());
	RETURN_TEST(0);
}

// -------------------
// Failure modes
// -------------------

int test_x25519_create_invalid_keys() {
	ASSERT_FALSE(static_cast<bool>(Secret::Create(Secret::Type::X25519, nullptr)));
	auto mismatched = KeyPair::ECDH::Generate(256);
	ASSERT_TRUE(static_cast<bool>(mismatched));
	ASSERT_FALSE(static_cast<bool>(Secret::Create(Secret::Type::X25519, mismatched)));
	RETURN_TEST(0);
}

int test_x25519_derive_shared_secret_invalid_key() {
	auto kp = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(static_cast<bool>(kp));
	Secret::X25519 x(kp);
	ASSERT_FALSE(x.Share("InvalidPublicKey").has_value());
	RETURN_TEST(0);
}

int test_x25519_derive_shared_secret_null_key() {
	ASSERT_FALSE(Secret::X25519::DeriveSharedSecret(nullptr, "InvalidPublicKey").has_value());
	Secret::X25519 agreement(nullptr);
	ASSERT_FALSE(agreement.Share("InvalidPublicKey").has_value());
	RETURN_TEST(0);
}

int test_x25519_malicious_third_party_key() {
	auto alice = KeyPair::X25519::Generate(256);
	auto bob = KeyPair::X25519::Generate(256);
	auto mallory = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(static_cast<bool>(alice));
	ASSERT_TRUE(static_cast<bool>(bob));
	ASSERT_TRUE(static_cast<bool>(mallory));
	Secret::X25519 xa(alice);
	Secret::X25519 xb(bob);
	Secret::X25519 xm(mallory);
	auto ab = xa.Share(bob->PublicKey());
	auto ba = xb.Share(alice->PublicKey());
	auto ma = xm.Share(alice->PublicKey());
	ASSERT_TRUE(ab.has_value());
	ASSERT_TRUE(ba.has_value());
	ASSERT_TRUE(ma.has_value());
	ASSERT_TRUE(ab.value() == ba.value());
	ASSERT_FALSE(ma.value() == ab.value());
	RETURN_TEST(0);
}

int test_x25519_share_empty_private_key() {
	auto peer = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(static_cast<bool>(peer));
	auto local = KeyPair::X25519::MakePointer<KeyPair::X25519>(peer->PublicKey(), Password());
	ASSERT_TRUE(local->HasPrivateKey());
	ASSERT_TRUE(local->PrivateKey()->Empty());
	Secret::X25519 agreement(local);
	ASSERT_FALSE(agreement.Share(peer->PublicKey()).has_value());
	ASSERT_FALSE(Secret::X25519::DeriveSharedSecret(local, peer->PublicKey()).has_value());
	RETURN_TEST(0);
}

int test_x25519_share_malformed_peer_keys() {
	auto local = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(static_cast<bool>(local));
	Secret::X25519 agreement(local);
	const StormByte::Safe::String nul_peer(std::string_view{"AA\0AA", 5});
	for (const StormByte::Safe::String& peer : {StormByte::Safe::String(), StormByte::Safe::String("%%%"), StormByte::Safe::String("AQ=="), nul_peer}) {
		ASSERT_FALSE(agreement.Share(peer).has_value());
		ASSERT_FALSE(Secret::X25519::DeriveSharedSecret(local, peer).has_value());
	}
	RETURN_TEST(0);
}

int test_x25519_share_without_private_key() {
	auto full = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(static_cast<bool>(full));
	auto pubOnly = KeyPair::X25519::MakePointer<KeyPair::X25519>(full->PublicKey());
	ASSERT_FALSE(pubOnly->HasPrivateKey());
	Secret::X25519 x(pubOnly);
	auto peer = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(static_cast<bool>(peer));
	ASSERT_FALSE(x.Share(peer->PublicKey()).has_value());
	ASSERT_FALSE(Secret::X25519::DeriveSharedSecret(pubOnly, peer->PublicKey()).has_value());
	RETURN_TEST(0);
}

int test_x25519_shared_secret_corrupted_keys() {
	auto kp = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(static_cast<bool>(kp));
	ASSERT_TRUE(kp->HasPrivateKey());
	const std::string_view public_key = kp->PublicKey();
	ASSERT_TRUE(public_key.size() > 1);
	StormByte::Safe::String corrupted(public_key.substr(0, public_key.size() / 2));
	auto badKp = KeyPair::X25519::MakePointer<KeyPair::X25519>(
		std::move(corrupted),
		Password("not-a-valid-x25519-private-key")
	);
	Secret::X25519 x(badKp);
	ASSERT_FALSE(x.Share(kp->PublicKey()).has_value());
	RETURN_TEST(0);
}

// -------------------
// Generate
// -------------------

int test_x25519_generate_key_pair() {
	auto kp = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(static_cast<bool>(kp));
	ASSERT_TRUE(kp->HasPrivateKey());
	ASSERT_TRUE(!kp->PublicKey().empty());
	RETURN_TEST(0);
}

// -------------------
// Share
// -------------------

int test_x25519_derive_shared_secret_static() {
	auto a = KeyPair::X25519::Generate(256);
	auto b = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(static_cast<bool>(a));
	ASSERT_TRUE(static_cast<bool>(b));
	auto s1 = Secret::X25519::DeriveSharedSecret(a, b->PublicKey());
	auto s2 = Secret::X25519::DeriveSharedSecret(b, a->PublicKey());
	ASSERT_TRUE(s1.has_value());
	ASSERT_TRUE(s2.has_value());
	ASSERT_TRUE(s1.value() == s2.value());
	RETURN_TEST(0);
}

int test_x25519_derive_shared_secret_valid_keys() {
	auto kp1 = KeyPair::X25519::Generate(256);
	auto kp2 = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(static_cast<bool>(kp1));
	ASSERT_TRUE(static_cast<bool>(kp2));
	Secret::X25519 a(kp1);
	Secret::X25519 b(kp2);
	auto s1 = a.Share(kp2->PublicKey());
	auto s2 = b.Share(kp1->PublicKey());
	ASSERT_TRUE(s1.has_value());
	ASSERT_TRUE(s2.has_value());
	ASSERT_TRUE(s1.value() == s2.value());
	RETURN_TEST(0);
}

int test_x25519_server_client_shared_secret() {
	auto server = KeyPair::X25519::Generate(256);
	auto client = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(static_cast<bool>(server));
	ASSERT_TRUE(static_cast<bool>(client));
	Secret::X25519 xs(server);
	Secret::X25519 xc(client);
	auto s1 = xs.Share(client->PublicKey());
	auto s2 = xc.Share(server->PublicKey());
	ASSERT_TRUE(s1.has_value());
	ASSERT_TRUE(s2.has_value());
	ASSERT_TRUE(s1.value() == s2.value());
	RETURN_TEST(0);
}

int test_x25519_share_idempotent() {
	auto a = KeyPair::X25519::Generate(256);
	auto b = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(static_cast<bool>(a));
	ASSERT_TRUE(static_cast<bool>(b));
	Secret::X25519 x(a);
	auto s1 = x.Share(b->PublicKey());
	auto s2 = x.Share(b->PublicKey());
	ASSERT_TRUE(s1.has_value());
	ASSERT_TRUE(s2.has_value());
	ASSERT_TRUE(s1.value() == s2.value());
	RETURN_TEST(0);
}

int test_x25519_shared_secret_snapshot_survives_reset() {
	auto alice = KeyPair::X25519::Generate(256);
	auto bob = KeyPair::X25519::Generate(256);
	ASSERT_TRUE(static_cast<bool>(alice));
	ASSERT_TRUE(static_cast<bool>(bob));
	Secret::X25519 agreement(alice);
	auto result = agreement.Share(bob->PublicKey());
	ASSERT_TRUE(result.has_value());
	const Password snapshot = result.value();
	result.reset();
	ASSERT_FALSE(result.has_value());
	ASSERT_FALSE(snapshot.Empty());
	const auto repeated = agreement.Share(bob->PublicKey());
	ASSERT_TRUE(repeated.has_value());
	ASSERT_TRUE(snapshot == repeated.value());
	RETURN_TEST(0);
}

int main() {
	int result = 0;

	// -------------------
	// Construct
	// -------------------
	result += test_x25519_copy_move_clone();
	result += test_x25519_create();

	// -------------------
	// Failure modes
	// -------------------
	result += test_x25519_create_invalid_keys();
	result += test_x25519_derive_shared_secret_invalid_key();
	result += test_x25519_derive_shared_secret_null_key();
	result += test_x25519_malicious_third_party_key();
	result += test_x25519_share_empty_private_key();
	result += test_x25519_share_malformed_peer_keys();
	result += test_x25519_share_without_private_key();
	result += test_x25519_shared_secret_corrupted_keys();

	// -------------------
	// Generate
	// -------------------
	result += test_x25519_generate_key_pair();

	// -------------------
	// Share
	// -------------------
	result += test_x25519_derive_shared_secret_static();
	result += test_x25519_derive_shared_secret_valid_keys();
	result += test_x25519_server_client_shared_secret();
	result += test_x25519_share_idempotent();
	result += test_x25519_shared_secret_snapshot_survives_reset();

	if (result == 0)
		std::cout << "All tests passed!" << std::endl;
	else
		std::cout << result << " tests failed." << std::endl;
	return result;
}
