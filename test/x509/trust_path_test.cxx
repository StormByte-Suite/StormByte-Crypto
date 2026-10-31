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
namespace Safe = StormByte::Safe;

namespace {
	/**
	 * @brief Parses a public fixture.
	 * @param pem Fixture bytes.
	 * @return Parsed certificate.
	 * @throws std::runtime_error Fixture is invalid.
	 */
	Certificate Cert(std::string_view pem) {
		auto value = Load(std::as_bytes(std::span(pem.data(), pem.size())));
		if (!value)
			throw std::runtime_error("trust fixture failed to load");
		return *value;
	}

	/**
	 * @brief Constructs an expected DNS name.
	 * @param name ASCII hostname.
	 * @return Library-owned identity.
	 */
	SubjectAltName DNS(std::string_view name = "peer.example.com") {
		return SubjectAltName(SubjectAltNameType::DNS, Safe::Binary(name));
	}

	/**
	 * @brief Offline reference-chain validation time.
	 */
	const TimePoint ReferenceTime = std::chrono::sys_days(std::chrono::year(2026) / 10 / 31);
}

// -------------------
// Admission
// -------------------

/**
 * @brief Custom CA success never widens production bundled root admission.
 * @return Number of failures.
 */
int test_custom_separation() {
	const auto leaf = Cert(Leaf);
	const std::array chain{Cert(Inter)};
	const auto root = Cert(Root);
	ASSERT_TRUE(static_cast<bool>(ValidateCustomCATLSPath(leaf, chain, root, leaf.NotBefore(), DNS())));
	const auto bundled = ValidateBundledTLSPath(leaf, chain, leaf.NotBefore(), DNS());
	ASSERT_TRUE(!bundled);
#ifdef WINDOWS
	ASSERT_EQUAL(TrustPathError::NativePolicyRejected, *bundled.error());
#elifdef MACOS
	ASSERT_EQUAL(TrustPathError::NativePolicyRejected, *bundled.error());
#else
	ASSERT_EQUAL(TrustPathError::RootNotAdmitted, *bundled.error());
#endif
	ASSERT_TRUE(!ValidateCustomCATLSPath(leaf, chain, Cert(Rogue), leaf.NotBefore(), DNS()));
	RETURN_TEST(0);
}

/**
 * @brief Request errors cannot fall back to native or environment trust.
 * @return Number of failures.
 */
int test_invalid_requests() {
	const auto leaf = Cert(Leaf);
	const std::array chain{Cert(Inter)};
	ASSERT_TRUE(!ValidateBundledTLSPath(Certificate(), chain, leaf.NotBefore(), DNS()));
	ASSERT_TRUE(!ValidateBundledTLSPath(leaf, chain, leaf.NotBefore(), DNS("wrong.example.com")));
	ASSERT_TRUE(!ValidateBundledTLSPath(leaf, chain, leaf.NotBefore(), DNS("")));
	ASSERT_TRUE(!ValidateCustomCATLSPath(leaf, chain, Certificate(), leaf.NotBefore(), DNS()));
	const std::array emptyIssuer{Certificate()};
	ASSERT_TRUE(!ValidateBundledTLSPath(leaf, emptyIssuer, leaf.NotBefore(), DNS()));
	const SubjectAltName invalid(static_cast<SubjectAltNameType>(99), Safe::Binary("peer.example.com"));
	ASSERT_TRUE(!ValidateBundledTLSPath(leaf, chain, leaf.NotBefore(), invalid));
	std::array<Certificate, 17> excessive;
	excessive.fill(Cert(Inter));
	ASSERT_TRUE(!ValidateBundledTLSPath(leaf, excessive, leaf.NotBefore(), DNS()));
	RETURN_TEST(0);
}

/**
 * @brief Offline public PayPal reference chains exercise bundled admission, not a TLS handshake.
 * @return Number of failures.
 */
int test_public_reference_paths() {
	using namespace PublicChainFixtures;
	const std::array chain{Cert(ProductionIntermediate)};
	const auto leaf = Cert(ProductionLeaf);
#ifdef WINDOWS
	// Public native OS admission is host policy, not a portable fixture assertion.
	ASSERT_TRUE(!ValidateBundledTLSPath(leaf, chain, ReferenceTime, DNS("wrong.example.com")));
#elifdef MACOS
	ASSERT_TRUE(!ValidateBundledTLSPath(leaf, chain, ReferenceTime, DNS("wrong.example.com")));
#else
	ASSERT_TRUE(static_cast<bool>(ValidateBundledTLSPath(leaf, chain, ReferenceTime, DNS("api-m.paypal.com"))));
	const auto roots = LoadBundledTLSRoots();
	ASSERT_TRUE(static_cast<bool>(roots));
	bool digicert = false;
	for (const auto& root : *roots) {
		if (!chain.back().IsIssuedBy(root))
			continue;
		const auto name = root.SubjectCommonName();
		ASSERT_EQUAL(std::string_view("DigiCert Global Root G2"), static_cast<std::string_view>(name));
		const auto identity = DNS("api-m.paypal.com");
		ASSERT_TRUE(static_cast<bool>(TLSPeerVerifier::Verify(leaf, chain, root, ReferenceTime,
			TLSRole::Server, &identity)));
		digicert = true;
	}
	ASSERT_TRUE(digicert);
	ASSERT_TRUE(static_cast<bool>(ValidateBundledTLSPath(Cert(SandboxLeaf),
		std::array{Cert(SandboxIntermediate)}, ReferenceTime, DNS("api-m.sandbox.paypal.com"))));
	ASSERT_TRUE(!ValidateBundledTLSPath(leaf, {}, ReferenceTime, DNS("api-m.paypal.com")));
	ASSERT_TRUE(!ValidateBundledTLSPath(leaf, chain, leaf.NotAfter() + std::chrono::seconds(1), DNS("api-m.paypal.com")));
	const auto root = std::ranges::find_if(*roots, [](const Certificate& candidate) {
		return static_cast<std::string_view>(candidate.SubjectCommonName()) == "DigiCert Global Root G2";
	});
	ASSERT_TRUE(root != roots->end());
	const auto payment = VerifyPaymentPeer(leaf, chain, *root, ReferenceTime,
		DNS("api-m.paypal.com"), {});
	ASSERT_TRUE(!payment);
	ASSERT_EQUAL(PaymentPeerError::RevocationUnavailable, *payment.error());
#endif
	RETURN_TEST(0);
}

// -------------------
// Constraints
// -------------------

/**
 * @brief Linux keeps explicit unsupported restrictions, instead of accepting a flat bundle.
 * @return Number of failures.
 */
int test_constrained_linux_path() {
#ifdef WINDOWS
	RETURN_TEST(0);
#elifdef MACOS
	RETURN_TEST(0);
#else
	const auto leaf = Cert(Leaf);
	const std::array chain{Cert(InterNC)};
	const auto result = ValidateCustomCATLSPath(leaf, chain, Cert(Root), leaf.NotBefore(), DNS());
	ASSERT_TRUE(!result);
	ASSERT_EQUAL(TrustPathError::PeerPathRejected, *result.error());
	const auto identity = DNS();
	const auto detailed = TLSPeerVerifier::Verify(leaf, chain, Cert(Root), leaf.NotBefore(), TLSRole::Server, &identity);
	ASSERT_TRUE(!detailed);
	RETURN_TEST(0);
#endif
}

/**
 * @brief Server purpose and time failures remain enforced in custom mode.
 * @return Number of failures.
 */
int test_custom_policy_failures() {
	const auto leaf = Cert(Leaf);
	const std::array chain{Cert(Inter)};
	ASSERT_TRUE(!ValidateCustomCATLSPath(Cert(LeafClient), chain, Cert(Root), leaf.NotBefore(), DNS()));
	ASSERT_TRUE(!ValidateCustomCATLSPath(Cert(LeafBadKU), chain, Cert(Root), leaf.NotBefore(), DNS()));
	ASSERT_TRUE(!ValidateCustomCATLSPath(leaf, chain, Cert(Root), leaf.NotAfter() + std::chrono::seconds(1), DNS()));
	RETURN_TEST(0);
}

// -------------------
// Snapshot
// -------------------

/**
 * @brief Digest, count, provenance, exclusions and copied-root isolation are deterministic.
 * @return Number of failures.
 */
int test_snapshot_integrity() {
	auto roots = LoadBundledTLSRoots();
	ASSERT_TRUE(static_cast<bool>(roots));
	ASSERT_EQUAL(std::size_t(117), static_cast<std::size_t>(roots->size()));
	ASSERT_EQUAL(std::string_view("0a2b0c75fa036930d98331b721c0780693a3e17a"),
		std::string_view(BundledTLSRootsRevision()));
	ASSERT_EQUAL(std::string_view("605910d60aa2dedf70cca0d048c17b60f6edb3931f8471dde17822b4df49b5a3"),
		std::string_view(BundledTLSRootsSHA256()));
	for (const auto& root : *roots) {
		ASSERT_TRUE(root.IsCA());
		const auto name = root.SubjectCommonName();
		ASSERT_TRUE(static_cast<std::string_view>(name).find("Entrust") == std::string_view::npos);
	}
	roots->clear();
	const auto fresh = LoadBundledTLSRoots();
	ASSERT_TRUE(static_cast<bool>(fresh));
	ASSERT_EQUAL(std::size_t(117), static_cast<std::size_t>(fresh->size()));
	RETURN_TEST(0);
}

/**
 * @brief Runs the offline trust tests.
 * @return Aggregated failures.
 */
int main() {
	int result = 0;
	// -------------------
	// Admission
	// -------------------
	result += test_custom_separation();
	result += test_invalid_requests();
	result += test_public_reference_paths();
	// -------------------
	// Constraints
	// -------------------
	result += test_constrained_linux_path();
	result += test_custom_policy_failures();
	// -------------------
	// Snapshot
	// -------------------
	result += test_snapshot_integrity();
	return result;
}
