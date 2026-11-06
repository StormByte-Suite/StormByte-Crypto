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

#include <StormByte/crypto/x509/native_trust.hxx>
#include <StormByte/crypto/x509/trust_path.hxx>
#include <StormByte/test_handlers.h>

#include "public_chain_fixtures.hxx"
#include "tls_peer_fixtures.hxx"

#include <array>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string_view>

using namespace StormByte::Crypto::X509;
using namespace TLSPeerFixtures;

namespace {
	/**
	 * @brief Loads a public fixture without any private-key or store mutation.
	 * @param pem Fixture text.
	 * @return Parsed certificate.
	 * @throws std::runtime_error Fixture is invalid.
	 */
	Certificate Cert(std::string_view pem) {
		auto certificate = Load(std::as_bytes(std::span(pem.data(), pem.size())));
		if (!certificate)
			throw std::runtime_error("native trust fixture failed to load");
		return *certificate;
	}
}

// -------------------
// Admission
// -------------------

/**
 * @brief Only explicit anchors determine trust, without requiring OS-root admission.
 * @return Number of failures.
 */
int test_isolated_admission() {
	const auto leaf = Cert(LeafRSA256);
	const std::array chain{Cert(InterRSA)};
	const std::array allowed{Cert(RootRSA)};
	const std::array other{Cert(Rogue)};
	ASSERT_TRUE(Detail::NativeTrustPath(leaf, chain, allowed, leaf.NotBefore()));
	ASSERT_TRUE(!Detail::NativeTrustPath(leaf, chain, other, leaf.NotBefore()));
	ASSERT_TRUE(!Detail::NativeTrustPath(leaf, chain, {}, leaf.NotBefore()));
	const std::array candidates{Cert(InterRSA), Cert(RootRSA)};
	ASSERT_TRUE(!Detail::NativeTrustPath(leaf, candidates, other, leaf.NotBefore()));
	RETURN_TEST(0);
}

/**
 * @brief Captured public RSA paths exercise native policy with only explicit object/memory roots.
 * @return Number of failures.
 */
int test_public_isolated_path() {
	const auto leaf = Cert(PublicChainFixtures::ProductionLeaf);
	const std::array chain{Cert(PublicChainFixtures::ProductionIntermediate)};
	const auto roots = LoadBundledTLSRoots();
	ASSERT_TRUE(static_cast<bool>(roots));
	const TimePoint at = std::chrono::sys_days(std::chrono::year(2026) / 10 / 31);
	ASSERT_TRUE(Detail::NativeTrustPath(leaf, chain, *roots, at));
	RETURN_TEST(0);
}

// -------------------
// Policy
// -------------------

/**
 * @brief Native intermediate path-length and TLS EKU constraints remain mandatory.
 * @return Number of failures.
 */
int test_native_constraints() {
	const auto leaf = Cert(Leaf);
	const std::array roots{Cert(Root)};
	const std::array chain{Cert(Inter)};
	ASSERT_TRUE(Detail::NativeTrustPath(leaf, chain, roots, leaf.NotBefore()));
	ASSERT_TRUE(!Detail::NativeTrustPath(Cert(LeafClient), chain, roots, leaf.NotBefore()));
	ASSERT_TRUE(!Detail::NativeTrustPath(leaf, std::array{Cert(InterClient)}, roots, leaf.NotBefore()));
	ASSERT_TRUE(!Detail::NativeTrustPath(Cert(LeafSub),
		std::array{Cert(Sub), Cert(InterPathZero)}, roots, leaf.NotBefore()));
	ASSERT_TRUE(!Detail::NativeTrustPath(leaf, chain, roots,
		leaf.NotAfter() + std::chrono::seconds(1)));
	RETURN_TEST(0);
}

/**
 * @brief A certificate with a changed signature cannot pass native trust.
 * @return Number of failures.
 */
int test_native_signature_failure() {
	const auto original = Cert(LeafRSA256);
	auto der = original.Der();
	der[StormByte::ByteSize(static_cast<std::size_t>(der.size()) - 1)] ^= std::byte(1);
	Certificate leaf;
	ASSERT_TRUE(Certificate::Parse(der.span(), leaf));
	const std::array roots{Cert(RootRSA)};
	ASSERT_TRUE(!Detail::NativeTrustPath(leaf, std::array{Cert(InterRSA)},
		roots, original.NotBefore()));
	RETURN_TEST(0);
}

/**
 * @brief Runs platform-only offline tests without OS certificate-store changes.
 * @return Aggregated failures.
 */
int main() {
	int result = 0;
	// -------------------
	// Admission
	// -------------------
	result += test_isolated_admission();
	result += test_public_isolated_path();
	// -------------------
	// Policy
	// -------------------
	result += test_native_constraints();
	result += test_native_signature_failure();
	return result;
}
