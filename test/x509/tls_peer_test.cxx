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

#include <StormByte/crypto/x509/tls_peer.hxx>
#include <StormByte/test_handlers.h>

#include "tls_peer_fixtures.hxx"

#include <algorithm>
#include <array>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <utility>

using namespace StormByte::Crypto::X509;
using namespace TLSPeerFixtures;
namespace Safe = StormByte::Safe;

namespace {
	/**
	 * @brief Loads a generated public certificate.
	 * @param pem Public PEM fixture.
	 * @return Parsed certificate.
	 * @throws std::runtime_error Fixture cannot be parsed.
	 */
	Certificate Cert(std::string_view pem) {
		auto certificate = Load(std::as_bytes(std::span(pem.data(), pem.size())));
		if (!certificate)
			throw std::runtime_error("peer fixture did not load");
		return *certificate;
	}

	/**
	 * @brief Constructs caller-supplied DNS identity text.
	 * @param value Expected ASCII DNS name.
	 * @return Identity with library-owned Safe bytes.
	 */
	SubjectAltName DNS(std::string_view value = "peer.example.com") {
		return SubjectAltName(SubjectAltNameType::DNS, Safe::Binary(value));
	}

	/**
	 * @brief Checks category and certificate position.
	 * @param result Verification result.
	 * @param code Expected category.
	 * @param index Expected leaf-to-anchor position.
	 * @return true for the exact indexed failure.
	 */
	bool Fails(const ExpectedTLSPeer& result, TLSPeerError code, std::size_t index = 0) {
		return !result && result.error()->Code() == code && result.error()->CertificateIndex() == index;
	}

	/**
	 * @brief Checks a preserved purpose failure.
	 * @param result Verification result.
	 * @param detail Exact original error.
	 * @param index Certificate position.
	 * @return true for the exact purpose failure.
	 */
	bool PurposeFails(const ExpectedTLSPeer& result, PurposeError detail, std::size_t index = 0) {
		return Fails(result, TLSPeerError::Purpose, index) && result.error()->PurposeDetail() == detail;
	}

	/**
	 * @brief Checks a preserved identity failure.
	 * @param result Verification result.
	 * @param detail Exact original error.
	 * @param index Certificate position.
	 * @return true for the exact identity failure.
	 */
	bool IdentityFails(const ExpectedTLSPeer& result, IdentityError detail, std::size_t index = 0) {
		return Fails(result, TLSPeerError::Identity, index) && result.error()->IdentityDetail() == detail;
	}

	/**
	 * @brief Runs the usual one-intermediate fixture chain.
	 * @param pem Leaf fixture.
	 * @param role Signing role.
	 * @param issuer Intermediate fixture.
	 * @param root Anchor fixture.
	 * @return Verification with an expected server DNS name or identityless client.
	 */
	ExpectedTLSPeer Verify(std::string_view pem = Leaf, TLSRole role = TLSRole::Server,
		std::string_view issuer = Inter, std::string_view root = Root) {
		const auto leaf = Cert(pem);
		const std::array chain{Cert(issuer)};
		const auto identity = DNS();
		return TLSPeerVerifier::Verify(leaf, chain, Cert(root), leaf.NotBefore(), role,
			role == TLSRole::Server ? &identity : nullptr);
	}

	/**
	 * @brief Corrupts only the signature, leaving the TBS and extension DER intact.
	 * @param certificate Source.
	 * @return Parsed certificate with invalid signature.
	 * @throws std::runtime_error Mutated certificate cannot be parsed.
	 */
	Certificate BadSignature(const Certificate& certificate) {
		auto der = certificate.Der();
		const auto end = static_cast<std::size_t>(der.size()) - 1;
		der[StormByte::ByteSize{end}] ^= std::byte{1};
		Certificate result;
		if (!Certificate::Parse(der.span(), result))
			throw std::runtime_error("signature mutation did not parse");
		return result;
	}
}

// -------------------
// Constraints
// -------------------

/**
 * @brief Anchor restrictions are explicit local policy; its own signature is not trust.
 * @return Number of failures.
 */
int test_anchor_policy() {
	ASSERT_TRUE(PurposeFails(Verify(Leaf, TLSRole::Server, Inter, RootClient),
		PurposeError::ExtendedKeyUsageNotAllowed, 2));
	ASSERT_TRUE(static_cast<bool>(Verify(LeafClient, TLSRole::Client, Inter, RootClient)));
	ASSERT_TRUE(Fails(Verify(Leaf, TLSRole::Server, Inter, RootBadKU), TLSPeerError::IssuerKeyUsageNotAllowed, 2));
	ASSERT_TRUE(PurposeFails(Verify(Leaf, TLSRole::Server, Inter, RootBadEKU), PurposeError::MalformedExtendedKeyUsage, 2));
	ASSERT_TRUE(PurposeFails(Verify(Leaf, TLSRole::Server, Inter, RootMalformedKU), PurposeError::MalformedKeyUsage, 2));
	ASSERT_TRUE(Fails(Verify(Leaf, TLSRole::Server, Inter, RootNotCA), TLSPeerError::NotCA, 2));
	ASSERT_TRUE(Fails(Verify(Leaf, TLSRole::Server, Inter, RootNC), TLSPeerError::UnsupportedConstraint, 2));
	const auto leaf = Cert(Leaf);
	const auto identity = DNS();
	const std::array chain{Cert(Inter)};
	ASSERT_TRUE(static_cast<bool>(TLSPeerVerifier::Verify(leaf, chain, BadSignature(Cert(Root)),
		leaf.NotBefore(), TLSRole::Server, &identity)));
	ASSERT_TRUE(static_cast<bool>(Verify(Leaf, TLSRole::Server, Inter, RootSHA1)));
	RETURN_TEST(0);
}

/**
 * @brief Unsupported algorithms and weak keys never become successful peer checks.
 * @return Number of failures.
 */
int test_bounded_algorithms() {
	for (const auto pem : {LeafRSA, LeafP384, LeafP521})
		ASSERT_TRUE(static_cast<bool>(Verify(pem)));
	for (const auto pem : {LeafRSA256, LeafRSA384, LeafRSA512})
		ASSERT_TRUE(static_cast<bool>(Verify(pem, TLSRole::Server, InterRSA, RootRSA)));
	for (const auto pem : {LeafWeak, LeafCurve, LeafSHA1})
		ASSERT_TRUE(Fails(Verify(pem), TLSPeerError::UnsupportedAlgorithm));
	ASSERT_TRUE(Fails(Verify(Leaf, TLSRole::Server, InterWeak), TLSPeerError::UnsupportedAlgorithm, 1));
	ASSERT_TRUE(Fails(Verify(Leaf, TLSRole::Server, Inter, RootWeak), TLSPeerError::UnsupportedAlgorithm, 2));
	auto der = Cert(Leaf).Der();
	constexpr std::array pattern{std::byte{0x03}, std::byte{0x42}, std::byte{0}, std::byte{0x04}};
	std::size_t changes = 0;
	for (std::size_t i = 0; i + pattern.size() <= static_cast<std::size_t>(der.size()); ++i) {
		if (std::equal(pattern.begin(), pattern.end(), der.span().begin() + i)) {
			der[StormByte::ByteSize{i + 2}] = std::byte{1};
			++changes;
		}
	}
	ASSERT_EQUAL(std::size_t{1}, changes);
	Certificate malformed_key;
	ASSERT_TRUE(Certificate::Parse(der.span(), malformed_key));
	const auto identity = DNS();
	const std::array chain{Cert(Inter)};
	ASSERT_TRUE(Fails(TLSPeerVerifier::Verify(malformed_key, chain, Cert(Root),
		malformed_key.NotBefore(), TLSRole::Server, &identity), TLSPeerError::UnsupportedAlgorithm));
	RETURN_TEST(0);
}

/**
 * @brief Issuers require CA classification, strict KU, keyCertSign and chainwide role EKU.
 * @return Number of failures.
 */
int test_ca_key_usage_and_eku() {
	for (const auto pem : {InterNotCA, InterNoBC})
		ASSERT_TRUE(Fails(Verify(Leaf, TLSRole::Server, pem), TLSPeerError::NotCA, 1));
	ASSERT_TRUE(Fails(Verify(Leaf, TLSRole::Server, InterNoncriticalBC), TLSPeerError::MalformedExtension, 1));
	ASSERT_TRUE(Fails(Verify(Leaf, TLSRole::Server, InterBadKU), TLSPeerError::IssuerKeyUsageNotAllowed, 1));
	ASSERT_TRUE(PurposeFails(Verify(Leaf, TLSRole::Server, InterMalformedKU), PurposeError::MalformedKeyUsage, 1));
	for (const auto pem : {InterClient, InterAny})
		ASSERT_TRUE(PurposeFails(Verify(Leaf, TLSRole::Server, pem), PurposeError::ExtendedKeyUsageNotAllowed, 1));
	ASSERT_TRUE(PurposeFails(Verify(Leaf, TLSRole::Server, InterBadEKU), PurposeError::MalformedExtendedKeyUsage, 1));
	ASSERT_TRUE(static_cast<bool>(Verify(LeafClient, TLSRole::Client, InterClient)));
	for (const auto role : {TLSRole::Server, TLSRole::Client}) {
		ASSERT_TRUE(static_cast<bool>(Verify(Leaf, role, InterNoKU, RootNoKU)));
		ASSERT_TRUE(static_cast<bool>(Verify(LeafBothCriticalEKU, role, InterBothCriticalEKU)));
	}
	RETURN_TEST(0);
}

/**
 * @brief Critical extensions ignored by legacy VerifyChain fail in the new composition.
 * @return Number of failures.
 */
int test_critical_extensions() {
	for (const auto pem : {LeafUnknownCritical, LeafCriticalSKI, LeafCriticalAKI,
		LeafCriticalPolicies, LeafCriticalURI})
		ASSERT_TRUE(Fails(Verify(pem), TLSPeerError::UnsupportedCriticalExtension));
	ASSERT_TRUE(static_cast<bool>(Verify(LeafCriticalSAN)));
	ASSERT_TRUE(static_cast<bool>(Verify(LeafBenign)));
	const auto leaf = Cert(LeafCriticalSKI);
	const std::array chain{Cert(Inter)};
	ASSERT_TRUE(leaf.VerifyChain(chain, Cert(Root), leaf.NotBefore()));
	RETURN_TEST(0);
}

/**
 * @brief Leaf digitalSignature and explicit role purpose preserve existing typed errors.
 * @return Number of failures.
 */
int test_leaf_key_usage_and_eku() {
	ASSERT_TRUE(Fails(Verify(LeafCA), TLSPeerError::LeafIsCA));
	ASSERT_TRUE(PurposeFails(Verify(LeafBadKU), PurposeError::KeyUsageNotAllowed));
	ASSERT_TRUE(PurposeFails(Verify(LeafBadEKU), PurposeError::MalformedExtendedKeyUsage));
	ASSERT_TRUE(PurposeFails(Verify(LeafMalformedKU), PurposeError::MalformedKeyUsage));
	ASSERT_TRUE(Fails(Verify(LeafDecipher), TLSPeerError::MalformedExtension));
	ASSERT_TRUE(Fails(Verify(LeafSignsCA), TLSPeerError::MalformedExtension));
	ASSERT_TRUE(PurposeFails(Verify(LeafClient), PurposeError::ExtendedKeyUsageNotAllowed));
	ASSERT_TRUE(PurposeFails(Verify(LeafServer, TLSRole::Client), PurposeError::ExtendedKeyUsageNotAllowed));
	ASSERT_TRUE(static_cast<bool>(Verify(LeafServer)));
	ASSERT_TRUE(static_cast<bool>(Verify(LeafClient, TLSRole::Client)));
	ASSERT_TRUE(static_cast<bool>(Verify(LeafNoUsage)));
	ASSERT_TRUE(Fails(Verify(LeafExplicitFalseBC), TLSPeerError::MalformedExtension));
	const std::string_view malformed = LeafMalformedBC;
	ASSERT_FALSE(Load(std::as_bytes(std::span(malformed.data(), malformed.size()))).has_value());
	RETURN_TEST(0);
}

/**
 * @brief Relevant malformed SAN fails even on issuers and identityless clients.
 * @return Number of failures.
 */
int test_malformed_san() {
	ASSERT_TRUE(IdentityFails(Verify(LeafBadSAN), IdentityError::MalformedSubjectAltName));
	ASSERT_TRUE(IdentityFails(Verify(LeafBadSAN, TLSRole::Client), IdentityError::MalformedSubjectAltName));
	ASSERT_TRUE(IdentityFails(Verify(Leaf, TLSRole::Server, InterBadSAN), IdentityError::MalformedSubjectAltName, 1));
	RETURN_TEST(0);
}

/**
 * @brief No unsupported path restriction is silently ignored, regardless of criticality.
 * @return Number of failures.
 */
int test_unprocessed_constraints() {
	for (const auto pem : {LeafNC, LeafPolicyMappings, LeafPolicyConstraints,
		LeafInhibitAnyPolicy, LeafTLSFeature, LeafProxy})
		ASSERT_TRUE(Fails(Verify(pem), TLSPeerError::UnsupportedConstraint));
	ASSERT_TRUE(Fails(Verify(Leaf, TLSRole::Server, InterNC), TLSPeerError::UnsupportedConstraint, 1));
	RETURN_TEST(0);
}

// -------------------
// Identity
// -------------------

/**
 * @brief Client identity is an explicit optional SAN policy, not application authorization.
 * @return Number of failures.
 */
int test_client_optional_identity() {
	ASSERT_TRUE(static_cast<bool>(Verify(LeafNoSAN, TLSRole::Client)));
	const auto leaf = Cert(LeafClient);
	const auto identity = DNS();
	const auto mismatch = DNS("other.example.com");
	const std::array chain{Cert(InterClient)};
	ASSERT_TRUE(static_cast<bool>(TLSPeerVerifier::Verify(leaf, chain, Cert(RootClient),
		leaf.NotBefore(), TLSRole::Client, &identity)));
	ASSERT_TRUE(IdentityFails(TLSPeerVerifier::Verify(leaf, chain, Cert(RootClient),
		leaf.NotBefore(), TLSRole::Client, &mismatch), IdentityError::NoMatch));
	RETURN_TEST(0);
}

/**
 * @brief DNS matching composes case, wildcard, rejection and no-CN-fallback semantics.
 * @return Number of failures.
 */
int test_dns_identity() {
	const auto leaf = Cert(Leaf);
	const std::array chain{Cert(Inter)};
	for (const auto text : {"peer.example.com", "PEER.EXAMPLE.COM.", "www.example.org"}) {
		const auto identity = DNS(text);
		ASSERT_TRUE(static_cast<bool>(TLSPeerVerifier::Verify(leaf, chain, Cert(Root),
			leaf.NotBefore(), TLSRole::Server, &identity)));
	}
	for (const auto text : {"other.example.com", "example.org", "a.b.example.org"}) {
		const auto identity = DNS(text);
		ASSERT_TRUE(IdentityFails(TLSPeerVerifier::Verify(leaf, chain, Cert(Root),
			leaf.NotBefore(), TLSRole::Server, &identity), IdentityError::NoMatch));
	}
	const auto invalid = DNS("192.0.2.1");
	ASSERT_TRUE(IdentityFails(TLSPeerVerifier::Verify(leaf, chain, Cert(Root),
		leaf.NotBefore(), TLSRole::Server, &invalid), IdentityError::InvalidExpectedName));
	ASSERT_TRUE(IdentityFails(Verify(LeafNoSAN), IdentityError::MissingSubjectAltName));
	RETURN_TEST(0);
}

/**
 * @brief Network-order IPv4 and IPv6 compose exact matching and address errors.
 * @return Number of failures.
 */
int test_ip_identity() {
	const auto leaf = Cert(Leaf);
	const std::array chain{Cert(Inter)};
	constexpr std::array v4{std::byte{192}, std::byte{0}, std::byte{2}, std::byte{1}};
	constexpr std::array v6{std::byte{0x20}, std::byte{0x01}, std::byte{0x0d}, std::byte{0xb8},
		std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
		std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
		std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}};
	for (const auto bytes : {std::span<const std::byte>(v4), std::span<const std::byte>(v6)}) {
		const SubjectAltName identity(SubjectAltNameType::IP, Safe::Binary(bytes));
		ASSERT_TRUE(static_cast<bool>(TLSPeerVerifier::Verify(leaf, chain, Cert(Root),
			leaf.NotBefore(), TLSRole::Server, &identity)));
	}
	auto wrong = v4;
	wrong[3] = std::byte{2};
	const SubjectAltName mismatch(SubjectAltNameType::IP, Safe::Binary(wrong));
	ASSERT_TRUE(IdentityFails(TLSPeerVerifier::Verify(leaf, chain, Cert(Root),
		leaf.NotBefore(), TLSRole::Server, &mismatch), IdentityError::NoMatch));
	const SubjectAltName malformed(SubjectAltNameType::IP, Safe::Binary(std::span(v4).first(3)));
	ASSERT_TRUE(IdentityFails(TLSPeerVerifier::Verify(leaf, chain, Cert(Root),
		leaf.NotBefore(), TLSRole::Server, &malformed), IdentityError::InvalidExpectedAddress));
	RETURN_TEST(0);
}

// -------------------
// Lifecycle
// -------------------

/**
 * @brief Failure value operations and Safe Expected storage preserve details and ownership.
 * @return Number of failures.
 */
int test_failure_lifecycle() {
	TLSPeerFailure empty;
	ASSERT_TRUE(empty.Code() == TLSPeerError::InvalidCertificate);
	const TLSPeerFailure purpose(PurposeError::MalformedKeyUsage, 2);
	TLSPeerFailure copy(purpose);
	TLSPeerFailure moved(std::move(copy));
	empty = purpose;
	copy = std::move(moved);
	for (const auto* value : std::array<const TLSPeerFailure*, 4>{&empty, &purpose, &copy, &moved}) {
		ASSERT_TRUE(value->Code() == TLSPeerError::Purpose);
		ASSERT_EQUAL(std::size_t{2}, value->CertificateIndex());
		ASSERT_TRUE(value->PurposeDetail() == PurposeError::MalformedKeyUsage);
	}
	const TLSPeerFailure identity(IdentityError::NoMatch);
	ASSERT_TRUE(identity.IdentityDetail() == IdentityError::NoMatch);
	Safe::Vector<TLSPeerFailure> failures;
	failures.push_back(purpose);
	failures.push_back(identity);
	auto result = Verify(LeafBadKU);
	auto copied_result = result;
	auto moved_result = std::move(copied_result);
	ASSERT_TRUE(PurposeFails(moved_result, PurposeError::KeyUsageNotAllowed));
	ASSERT_TRUE(failures[0].PurposeDetail() == PurposeError::MalformedKeyUsage);
	ASSERT_TRUE(failures[1].IdentityDetail() == IdentityError::NoMatch);
	RETURN_TEST(0);
}

/**
 * @brief Invalid roles, missing server identity and moved certificates fail explicitly.
 * @return Number of failures.
 */
int test_request_and_certificate_lifecycle() {
	const auto leaf = Cert(Leaf);
	const auto identity = DNS();
	const std::array chain{Cert(Inter)};
	const auto root = Cert(Root);
	ASSERT_TRUE(Fails(TLSPeerVerifier::Verify(leaf, chain, root, leaf.NotBefore(),
		static_cast<TLSRole>(99), &identity), TLSPeerError::UnsupportedRole));
	ASSERT_TRUE(Fails(TLSPeerVerifier::Verify(leaf, chain, root, leaf.NotBefore(),
		TLSRole::Server), TLSPeerError::MissingServerIdentity));
	const SubjectAltName unsupported(static_cast<SubjectAltNameType>(99), Safe::Binary{});
	ASSERT_TRUE(Fails(TLSPeerVerifier::Verify(leaf, chain, root, leaf.NotBefore(),
		TLSRole::Server, &unsupported), TLSPeerError::UnsupportedIdentity));
	Certificate copied(leaf);
	Certificate moved(std::move(copied));
	ASSERT_TRUE(Fails(TLSPeerVerifier::Verify(copied, chain, root, leaf.NotBefore(),
		TLSRole::Server, &identity), TLSPeerError::InvalidCertificate));
	ASSERT_TRUE(static_cast<bool>(TLSPeerVerifier::Verify(moved, chain, root, leaf.NotBefore(),
		TLSRole::Server, &identity)));
	const std::array empty_chain{Certificate{}};
	ASSERT_TRUE(Fails(TLSPeerVerifier::Verify(leaf, empty_chain, root, leaf.NotBefore(),
		TLSRole::Server, &identity), TLSPeerError::InvalidCertificate, 1));
	ASSERT_TRUE(Fails(TLSPeerVerifier::Verify(leaf, chain, Certificate{}, leaf.NotBefore(),
		TLSRole::Server, &identity), TLSPeerError::InvalidCertificate, 2));
	RETURN_TEST(0);
}

// -------------------
// Trust
// -------------------

/**
 * @brief Explicit caller time has inclusive exact boundaries on leaf and anchor.
 * @return Number of failures.
 */
int test_explicit_time() {
	const auto leaf = Cert(Leaf);
	const auto identity = DNS();
	const std::array chain{Cert(Inter)};
	const auto root = Cert(Root);
	for (const auto at : {leaf.NotBefore(), leaf.NotAfter()})
		ASSERT_TRUE(static_cast<bool>(TLSPeerVerifier::Verify(leaf, chain, root, at, TLSRole::Server, &identity)));
	for (const auto at : {leaf.NotBefore() - std::chrono::seconds{1}, leaf.NotAfter() + std::chrono::seconds{1}})
		ASSERT_TRUE(Fails(TLSPeerVerifier::Verify(leaf, chain, root, at,
			TLSRole::Server, &identity), TLSPeerError::InvalidTime));
	const auto short_root = Cert(RootShort);
	ASSERT_TRUE(static_cast<bool>(TLSPeerVerifier::Verify(leaf, chain, short_root,
		short_root.NotAfter(), TLSRole::Server, &identity)));
	ASSERT_TRUE(Fails(TLSPeerVerifier::Verify(leaf, chain, short_root,
		short_root.NotAfter() + std::chrono::seconds{1}, TLSRole::Server, &identity), TLSPeerError::InvalidTime, 2));
	const auto short_intermediate = Cert(InterShort);
	const std::array short_chain{short_intermediate};
	ASSERT_TRUE(static_cast<bool>(TLSPeerVerifier::Verify(leaf, short_chain, root,
		short_intermediate.NotAfter(), TLSRole::Server, &identity)));
	ASSERT_TRUE(Fails(TLSPeerVerifier::Verify(leaf, short_chain, root,
		short_intermediate.NotAfter() + std::chrono::seconds{1}, TLSRole::Server, &identity), TLSPeerError::InvalidTime, 1));
	RETURN_TEST(0);
}

/**
 * @brief Ordered chains do not build paths, search anchors or accept extraneous certificates.
 * @return Number of failures.
 */
int test_ordered_chain_and_path_length() {
	const auto leaf = Cert(LeafSub);
	const auto identity = DNS();
	const std::array ordered{Cert(Sub), Cert(Inter)};
	ASSERT_TRUE(static_cast<bool>(TLSPeerVerifier::Verify(leaf, ordered, Cert(Root),
		leaf.NotBefore(), TLSRole::Server, &identity)));
	const std::array reversed{Cert(Inter), Cert(Sub)};
	ASSERT_TRUE(Fails(TLSPeerVerifier::Verify(leaf, reversed, Cert(Root),
		leaf.NotBefore(), TLSRole::Server, &identity), TLSPeerError::SignatureOrIssuerMismatch));
	const std::array constrained{Cert(Sub), Cert(InterPathZero)};
	ASSERT_TRUE(Fails(TLSPeerVerifier::Verify(leaf, constrained, Cert(Root),
		leaf.NotBefore(), TLSRole::Server, &identity), TLSPeerError::PathLengthExceeded, 2));
	ASSERT_TRUE(Fails(Verify(Leaf, TLSRole::Server, Inter, RootPathZero), TLSPeerError::PathLengthExceeded, 2));
	const auto direct = Cert(LeafDirect);
	ASSERT_TRUE(static_cast<bool>(TLSPeerVerifier::Verify(direct, {}, Cert(RootPathZero),
		direct.NotBefore(), TLSRole::Server, &identity)));
	const std::array duplicate{Cert(Inter), Cert(Inter)};
	const auto usual = Cert(Leaf);
	ASSERT_TRUE(Fails(TLSPeerVerifier::Verify(usual, duplicate, Cert(Root),
		usual.NotBefore(), TLSRole::Server, &identity), TLSPeerError::SignatureOrIssuerMismatch, 1));
	RETURN_TEST(0);
}

/**
 * @brief Every non-anchor signature verifies against precisely the selected issuer.
 * @return Number of failures.
 */
int test_signatures_and_selected_anchor() {
	const auto leaf = Cert(Leaf);
	const auto identity = DNS();
	const std::array chain{Cert(Inter)};
	ASSERT_TRUE(Fails(Verify(Leaf, TLSRole::Server, Inter, Rogue), TLSPeerError::SignatureOrIssuerMismatch, 1));
	ASSERT_TRUE(Fails(TLSPeerVerifier::Verify(leaf, {}, Cert(Root),
		leaf.NotBefore(), TLSRole::Server, &identity), TLSPeerError::SignatureOrIssuerMismatch));
	ASSERT_TRUE(Fails(TLSPeerVerifier::Verify(BadSignature(leaf), chain, Cert(Root),
		leaf.NotBefore(), TLSRole::Server, &identity), TLSPeerError::SignatureOrIssuerMismatch));
	const std::array bad_chain{BadSignature(Cert(Inter))};
	ASSERT_TRUE(Fails(TLSPeerVerifier::Verify(leaf, bad_chain, Cert(Root),
		leaf.NotBefore(), TLSRole::Server, &identity), TLSPeerError::SignatureOrIssuerMismatch, 1));
	RETURN_TEST(0);
}

/**
 * @brief Runs constrained peer-certificate composition tests.
 * @return Nonzero on failure.
 */
int main() {
	int result = 0;
	// -------------------
	// Constraints
	// -------------------
	result += test_anchor_policy();
	result += test_bounded_algorithms();
	result += test_ca_key_usage_and_eku();
	result += test_critical_extensions();
	result += test_leaf_key_usage_and_eku();
	result += test_malformed_san();
	result += test_unprocessed_constraints();
	// -------------------
	// Identity
	// -------------------
	result += test_client_optional_identity();
	result += test_dns_identity();
	result += test_ip_identity();
	// -------------------
	// Lifecycle
	// -------------------
	result += test_failure_lifecycle();
	result += test_request_and_certificate_lifecycle();
	// -------------------
	// Trust
	// -------------------
	result += test_explicit_time();
	result += test_ordered_chain_and_path_length();
	result += test_signatures_and_selected_anchor();
	return result;
}
