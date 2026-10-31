/*
 * Copyright (C) 2024-2026 David C. Manuelda (StormBytePP)
 *
 * This file is part of StormByte-Crypto.
 *
 * StormByte-Crypto original source is dual-licensed:
 *
 * 1. GNU Lesser General Public License v3.0 (or later)
 *    You may redistribute and/or modify this file under the terms of the
 *    GNU Lesser General Public License v3.0 (or later).
 *
 * 2. Commercial license
 *    Alternatively, this file may be used under the terms of a commercial
 *    license agreement with the copyright holder
 *    (David C. Manuelda <StormByte@gmail.com>).
 *
 * Both licenses apply only to original StormByte-Crypto source in this
 * repository. They do not cover third-party material.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-StormByte-Commercial
 */

#include <StormByte/crypto/x509/revocation.hxx>
#include <StormByte/test_handlers.h>

#include "revocation_fixtures.hxx"

#include <chrono>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <vector>

using namespace StormByte::Crypto::X509;

namespace {
	/**
	 * @brief Parses a generated public certificate.
	 * @param pem Certificate fixture.
	 * @return Parsed certificate.
	 * @throws std::runtime_error Fixture is invalid.
	 */
	Certificate Cert(std::string_view pem) {
		auto certificate = Load(std::as_bytes(std::span(pem.data(), pem.size())));
		if (!certificate)
			throw std::runtime_error("revocation certificate fixture failed to load");
		return *certificate;
	}

	/**
	 * @brief Views a generated DER evidence fixture.
	 * @tparam N Array size, including the terminating NUL.
	 * @param data NUL-terminated binary fixture.
	 * @return DER bytes excluding the terminator.
	 */
	template<std::size_t N>
	std::span<const std::byte> Der(const char (&data)[N]) {
		return std::as_bytes(std::span(data, N - 1));
	}

	/**
	 * @brief Reads one definite-length DER element.
	 * @param input Remaining encoded data.
	 * @param tag Expected tag.
	 * @param contents Receives the element contents.
	 * @return Whether a complete element with the expected tag was read.
	 */
	bool ReadElement(std::span<const std::byte>& input, std::byte tag, std::span<const std::byte>& contents) {
		if (input.size() < 2 || input.front() != tag)
			return false;
		std::size_t headerSize = 2;
		std::size_t length = std::to_integer<std::uint8_t>(input[1]);
		if ((length & 0x80) != 0) {
			const std::size_t lengthBytes = length & 0x7f;
			if (lengthBytes == 0 || lengthBytes > sizeof(std::size_t) || input.size() < 2 + lengthBytes)
				return false;
			length = 0;
			for (std::size_t index = 0; index < lengthBytes; ++index) {
				if (length > (std::numeric_limits<std::size_t>::max() >> 8))
					return false;
				length = (length << 8) | std::to_integer<std::uint8_t>(input[2 + index]);
			}
			headerSize += lengthBytes;
		}
		if (length > input.size() - headerSize)
			return false;
		contents = input.subspan(headerSize, length);
		input = input.subspan(headerSize + length);
		return true;
	}

	/**
	 * @brief Corrupts the signature bits in an OCSP response without altering its structure.
	 * @param evidence Mutable DER BasicOCSPResponse wrapper.
	 * @return Whether a signature byte was found and changed.
	 */
	bool CorruptOcspSignature(std::span<std::byte> evidence) {
		std::span<const std::byte> remaining = evidence;
		std::span<const std::byte> response, field, responseBytes, basic, responseData, algorithm, signature;
		if (!ReadElement(remaining, std::byte{0x30}, response) || !remaining.empty())
			return false;
		remaining = response;
		if (!ReadElement(remaining, std::byte{0x0a}, field)
			|| !ReadElement(remaining, std::byte{0xa0}, field))
			return false;
		remaining = field;
		if (!ReadElement(remaining, std::byte{0x30}, responseBytes) || !remaining.empty())
			return false;
		remaining = responseBytes;
		if (!ReadElement(remaining, std::byte{0x06}, field)
			|| !ReadElement(remaining, std::byte{0x04}, basic) || !remaining.empty())
			return false;
		remaining = basic;
		if (!ReadElement(remaining, std::byte{0x30}, response) || !remaining.empty())
			return false;
		remaining = response;
		if (!ReadElement(remaining, std::byte{0x30}, responseData)
			|| !ReadElement(remaining, std::byte{0x30}, algorithm)
			|| !ReadElement(remaining, std::byte{0x03}, signature)
			|| responseData.empty() || algorithm.empty()
			|| signature.size() < 2 || signature.front() != std::byte{0})
			return false;
		const auto signatureOffset = static_cast<std::size_t>(signature.data() - evidence.data());
		evidence[signatureOffset + 1] ^= std::byte{1};
		return true;
	}

	/**
	 * @brief Returns the generated fixture validation instant.
	 * @return The fixed epoch second recorded alongside the fixtures.
	 */
	TimePoint Now() {
		return TimePoint{std::chrono::seconds{RevocationFixtures::ValidationTime}};
	}
}

/**
 * @brief Signed CRLs return good/revoked and reject tampering, wrong issuer and stale evidence.
 * @return Number of failures.
 */
int test_crl_status_and_failures() {
	const auto root = Cert(RevocationFixtures::Root);
	const auto good = Cert(RevocationFixtures::Good);
	const auto revoked = Cert(RevocationFixtures::Revoked);
	const auto futureRevoked = Cert(RevocationFixtures::FutureRevoked);
	const auto now = Now();
	auto status = RevocationVerifier::Verify(good, root, RevocationFormat::CRL, Der(RevocationFixtures::CRL), now);
	ASSERT_TRUE(static_cast<bool>(status));
	ASSERT_EQUAL(RevocationStatus::Good, *status);
	status = RevocationVerifier::Verify(revoked, root, RevocationFormat::CRL, Der(RevocationFixtures::CRL), now);
	ASSERT_TRUE(static_cast<bool>(status));
	ASSERT_EQUAL(RevocationStatus::Revoked, *status);
	status = RevocationVerifier::Verify(futureRevoked, root, RevocationFormat::CRL,
		Der(RevocationFixtures::CRL), now);
	ASSERT_TRUE(static_cast<bool>(status));
	ASSERT_EQUAL(RevocationStatus::Good, *status);
	status = RevocationVerifier::Verify(good, root, RevocationFormat::CRL, Der(RevocationFixtures::CRL),
		now + std::chrono::years(8));
	ASSERT_TRUE(!status);
	ASSERT_EQUAL(RevocationError::Stale, *status.error());
	status = RevocationVerifier::Verify(Cert(RevocationFixtures::OtherIssuer), root,
		RevocationFormat::CRL, Der(RevocationFixtures::CRL), now);
	ASSERT_TRUE(!status);
	ASSERT_EQUAL(RevocationError::InvalidRequest, *status.error());
	std::array<std::byte, sizeof(RevocationFixtures::CRL) - 1> tampered{};
	std::ranges::transform(Der(RevocationFixtures::CRL), tampered.begin(), [](std::byte value) { return value; });
	tampered.back() ^= std::byte{1};
	status = RevocationVerifier::Verify(good, root, RevocationFormat::CRL, tampered, now);
	ASSERT_TRUE(!status);
	ASSERT_TRUE(*status.error() == RevocationError::InvalidSignature
		|| *status.error() == RevocationError::MalformedEvidence);
	RETURN_TEST(0);
}

/**
 * @brief OCSP status, delegated responder authorization and freshness are verified offline.
 * @return Number of failures.
 */
int test_ocsp_status_and_failures() {
	const auto root = Cert(RevocationFixtures::Root);
	const auto good = Cert(RevocationFixtures::Good);
	const auto revoked = Cert(RevocationFixtures::Revoked);
	const auto futureRevoked = Cert(RevocationFixtures::FutureRevoked);
	const auto unknown = Cert(RevocationFixtures::Unknown);
	const auto now = Now();
	auto status = RevocationVerifier::Verify(good, root, RevocationFormat::OCSP,
		Der(RevocationFixtures::OCSPGood), now);
	ASSERT_TRUE(static_cast<bool>(status));
	ASSERT_EQUAL(RevocationStatus::Good, *status);
	status = RevocationVerifier::Verify(revoked, root, RevocationFormat::OCSP,
		Der(RevocationFixtures::OCSPRevoked), now);
	ASSERT_TRUE(static_cast<bool>(status));
	ASSERT_EQUAL(RevocationStatus::Revoked, *status);
	status = RevocationVerifier::Verify(futureRevoked, root, RevocationFormat::OCSP,
		Der(RevocationFixtures::OCSPFutureRevoked), now);
	ASSERT_TRUE(static_cast<bool>(status));
	ASSERT_EQUAL(RevocationStatus::Good, *status);
	status = RevocationVerifier::Verify(unknown, root, RevocationFormat::OCSP,
		Der(RevocationFixtures::OCSPUnknown), now);
	ASSERT_TRUE(static_cast<bool>(status));
	ASSERT_EQUAL(RevocationStatus::Unknown, *status);
	status = RevocationVerifier::Verify(good, root, RevocationFormat::OCSP,
		Der(RevocationFixtures::OCSPDelegated), now);
	ASSERT_TRUE(static_cast<bool>(status));
	ASSERT_EQUAL(RevocationStatus::Good, *status);
	status = RevocationVerifier::Verify(good, root, RevocationFormat::OCSP,
		Der(RevocationFixtures::OCSPUnauthorized), now);
	ASSERT_TRUE(!status);
	ASSERT_EQUAL(RevocationError::ResponderUnauthorized, *status.error());
	status = RevocationVerifier::Verify(good, root, RevocationFormat::OCSP,
		Der(RevocationFixtures::OCSPNonce), now);
	ASSERT_TRUE(!status);
	ASSERT_EQUAL(RevocationError::UnsupportedFeature, *status.error());
	status = RevocationVerifier::Verify(good, root, RevocationFormat::OCSP,
		Der(RevocationFixtures::OCSPUnknown), now);
	ASSERT_TRUE(!status);
	ASSERT_EQUAL(RevocationError::CertificateMismatch, *status.error());
	status = RevocationVerifier::Verify(good, root, RevocationFormat::OCSP,
		Der(RevocationFixtures::OCSPOtherIssuerSameSerial), now);
	ASSERT_TRUE(!status);
	ASSERT_EQUAL(RevocationError::IssuerMismatch, *status.error());
	status = RevocationVerifier::Verify(good, root, RevocationFormat::OCSP,
		Der(RevocationFixtures::OCSPGood), now + std::chrono::years(8));
	ASSERT_TRUE(!status);
	ASSERT_EQUAL(RevocationError::Stale, *status.error());
	std::array<std::byte, sizeof(RevocationFixtures::OCSPGood) - 1> tampered{};
	std::ranges::transform(Der(RevocationFixtures::OCSPGood), tampered.begin(),
		[](std::byte value) { return value; });
	ASSERT_TRUE(CorruptOcspSignature(tampered));
	status = RevocationVerifier::Verify(good, root, RevocationFormat::OCSP, tampered, now);
	ASSERT_TRUE(!status);
	ASSERT_TRUE(*status.error() == RevocationError::InvalidSignature
		|| *status.error() == RevocationError::ResponderUnauthorized
		|| *status.error() == RevocationError::MalformedEvidence);
	status = RevocationVerifier::Verify(good, root, RevocationFormat::OCSP,
		Der(RevocationFixtures::OCSPGood).first(12), now);
	ASSERT_TRUE(!status);
	ASSERT_EQUAL(RevocationError::MalformedEvidence, *status.error());
	status = RevocationVerifier::Verify(good, root, RevocationFormat::OCSP, {}, now);
	ASSERT_TRUE(!status);
	ASSERT_EQUAL(RevocationError::InvalidRequest, *status.error());
	std::vector<std::byte> oversized(4 * 1024 * 1024 + 1);
	status = RevocationVerifier::Verify(good, root, RevocationFormat::OCSP, oversized, now);
	ASSERT_TRUE(!status);
	ASSERT_EQUAL(RevocationError::InvalidRequest, *status.error());
	RETURN_TEST(0);
}

/**
 * @brief Runs offline CRL and OCSP verification regressions.
 * @return Aggregated failures.
 */
int main() {
	int result = 0;
	result += test_crl_status_and_failures();
	result += test_ocsp_status_and_failures();
	return result;
}
