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

#include <StormByte/crypto/x509/certificate.hxx>
#include <StormByte/safe/vector.hxx>
#include <StormByte/test_handlers.h>

#include "purpose_fixtures.hxx"

#include <array>
#include <cstddef>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <utility>

using namespace StormByte::Crypto;
using namespace StormByte::Crypto::X509;
using namespace PurposeFixtures;

namespace {
	/// Both supported TLS certificate roles.
	constexpr std::array Roles{TLSRole::Server, TLSRole::Client};

	/**
	 * @brief Loads a public fixture without trusting it.
	 * @param pem PEM certificate text.
	 * @return Parsed certificate.
	 * @throws std::runtime_error Fixture did not load.
	 */
	Certificate Cert(std::string_view pem) {
		auto value = X509::Load(std::as_bytes(std::span(pem.data(), pem.size())));
		if (!value)
			throw std::runtime_error("purpose fixture failed to load");
		return *value;
	}

	/**
	 * @brief Checks a typed purpose failure.
	 * @param result Purpose result.
	 * @param error Expected failure.
	 * @return true exactly when the result contains the expected error.
	 */
	bool Fails(const ExpectedPurpose& result, PurposeError error) {
		return !result && *result.error() == error;
	}
}

/**
 * @brief Absent EKU/KU is unrestricted for either signing role, on EC and RSA.
 * @return Number of failures.
 */
int test_absent_usage_and_public_keys() {
	for (const auto pem : {EC_Absent, RSA_Absent, EC_Both, RSA_Both}) {
		const auto certificate = Cert(pem);
		ASSERT_TRUE(certificate.PublicKey() != nullptr);
		ASSERT_FALSE(certificate.IsCA());
		for (const auto role : Roles)
			ASSERT_TRUE(static_cast<bool>(certificate.VerifyTLSPurpose(role)));
	}
	RETURN_TEST(0);
}

/**
 * @brief Explicit EKU matching is role-specific; unknown and repeated OIDs are handled.
 * @return Number of failures.
 */
int test_role_specific_eku() {
	const auto server = Cert(EC_Server);
	const auto client = Cert(EC_Client);
	ASSERT_TRUE(static_cast<bool>(server.VerifyTLSPurpose(TLSRole::Server)));
	ASSERT_TRUE(Fails(server.VerifyTLSPurpose(TLSRole::Client), PurposeError::ExtendedKeyUsageNotAllowed));
	ASSERT_TRUE(static_cast<bool>(client.VerifyTLSPurpose(TLSRole::Client)));
	ASSERT_TRUE(Fails(client.VerifyTLSPurpose(TLSRole::Server), PurposeError::ExtendedKeyUsageNotAllowed));
	for (const auto role : Roles) {
		for (const auto pem : {EC_Both, EC_BothCritical, EC_Repeated, EC_LargeUnknown, EC_UnknownThenBoth, EC_BothThenUnknown})
			ASSERT_TRUE(static_cast<bool>(Cert(pem).VerifyTLSPurpose(role)));
		for (const auto pem : {EC_Unrelated, EC_WrongAnyOid})
			ASSERT_TRUE(Fails(Cert(pem).VerifyTLSPurpose(role), PurposeError::ExtendedKeyUsageNotAllowed));
	}
	RETURN_TEST(0);
}

/**
 * @brief RFC 5280's permitted explicit-purpose policy does not accept anyEKU alone.
 * @return Number of failures.
 */
int test_any_eku_policy() {
	for (const auto role : Roles) {
		ASSERT_TRUE(Fails(Cert(EC_Any).VerifyTLSPurpose(role), PurposeError::ExtendedKeyUsageNotAllowed));
		ASSERT_TRUE(Fails(Cert(EC_AnyCritical).VerifyTLSPurpose(role), PurposeError::ExtendedKeyUsageNotAllowed));
		ASSERT_TRUE(static_cast<bool>(Cert(EC_AnyBoth).VerifyTLSPurpose(role)));
	}
	ASSERT_TRUE(static_cast<bool>(Cert(EC_AnyServer).VerifyTLSPurpose(TLSRole::Server)));
	ASSERT_TRUE(Fails(Cert(EC_AnyServer).VerifyTLSPurpose(TLSRole::Client), PurposeError::ExtendedKeyUsageNotAllowed));
	RETURN_TEST(0);
}

/**
 * @brief Malformed EKU fails completely even when a matching entry precedes the defect.
 * @return Number of failures.
 */
int test_malformed_eku() {
	const std::array malformed{
		EC_Empty, EC_TruncatedTag, EC_WrongTag, EC_NonOid, EC_EmptyOid,
		EC_UnterminatedOid, EC_NonMinimalOid, EC_NonMinimalFirstArc,
		EC_UnterminatedFirstArc, EC_Trailing, EC_Truncated, EC_NonMinimalLength,
		EC_Indefinite, EC_ClientBadTail, EC_BadCritical, EC_BadHead
	};
	for (const auto pem : malformed) {
		const auto certificate = Cert(pem);
		for (const auto role : Roles)
			ASSERT_TRUE(Fails(certificate.VerifyTLSPurpose(role), PurposeError::MalformedExtendedKeyUsage));
	}
	RETURN_TEST(0);
}

/**
 * @brief Both TLS 1.3 roles require digitalSignature when KU is present, on EC and RSA.
 * @return Number of failures.
 */
int test_tls13_key_usage() {
	for (const auto role : Roles) {
		for (const auto pem : {EC_Sign, RSA_Sign, EC_SignEncipher, EC_SignAgreement, EC_SignDecipher})
			ASSERT_TRUE(static_cast<bool>(Cert(pem).VerifyTLSPurpose(role)));
		for (const auto pem : {EC_Encipher, RSA_Encipher, EC_Agreement, RSA_Agreement}) {
			const auto certificate = Cert(pem);
			ASSERT_TRUE(Fails(certificate.VerifyTLSPurpose(role), PurposeError::KeyUsageNotAllowed));
			ASSERT_FALSE(certificate.HasKeyUsage(KeyUsage::DigitalSignature));
		}
	}
	RETURN_TEST(0);
}

/**
 * @brief New KU DER validation does not change legacy Parse or HasKeyUsage.
 * @return Number of failures.
 */
int test_malformed_ku_and_error_order() {
	for (const auto pem : {EC_ZeroKU, EC_PaddingKU, EC_NonMinimalKU, EC_UndefinedKU, EC_DeniedEKUBadKU}) {
		const auto certificate = Cert(pem);
		for (const auto role : Roles)
			ASSERT_TRUE(Fails(certificate.VerifyTLSPurpose(role), PurposeError::MalformedKeyUsage));
	}
	ASSERT_TRUE(Cert(EC_PaddingKU).HasKeyUsage(KeyUsage::DigitalSignature));
	ASSERT_TRUE(Cert(EC_NonMinimalKU).HasKeyUsage(KeyUsage::DigitalSignature));
	for (const auto role : Roles)
		ASSERT_TRUE(Fails(Cert(EC_BadEKUDeniedKU).VerifyTLSPurpose(role), PurposeError::MalformedExtendedKeyUsage));
	RETURN_TEST(0);
}

/**
 * @brief Duplicate EKU extensions remain rejected by the original certificate parser.
 * @return Number of failures.
 */
int test_duplicate_eku_extension() {
	auto der = Cert(EC_Both).Der();
	constexpr unsigned char original[] = {0x06, 0x03, 0x55, 0x1D, 0x12};
	std::size_t patched = 0;
	for (std::size_t i = 0; i + sizeof(original) <= static_cast<std::size_t>(der.size()); ++i) {
		bool same = true;
		for (std::size_t j = 0; j < sizeof(original) && same; ++j)
			same = der.span()[i + j] == static_cast<std::byte>(original[j]);
		if (same) {
			der[StormByte::ByteSize{i + 4}] = std::byte{0x25};
			++patched;
		}
	}
	ASSERT_EQUAL(std::size_t{1}, patched);
	ASSERT_FALSE(X509::Load(der.span()).has_value());
	Certificate output = Cert(EC_Server);
	ASSERT_FALSE(Certificate::Parse(der.span(), output));
	ASSERT_TRUE(Fails(output.VerifyTLSPurpose(TLSRole::Server), PurposeError::InvalidCertificate));
	RETURN_TEST(0);
}

/**
 * @brief Roles are validated before certificate state; empty objects never pass.
 * @return Number of failures.
 */
int test_invalid_role_and_empty_certificate() {
	constexpr auto invalid = static_cast<TLSRole>(999);
	ASSERT_TRUE(Fails(Certificate{}.VerifyTLSPurpose(invalid), PurposeError::UnsupportedRole));
	ASSERT_TRUE(Fails(Cert(EC_Server).VerifyTLSPurpose(invalid), PurposeError::UnsupportedRole));
	for (const auto role : Roles)
		ASSERT_TRUE(Fails(Certificate{}.VerifyTLSPurpose(role), PurposeError::InvalidCertificate));
	RETURN_TEST(0);
}

/**
 * @brief Copy, move and Safe ownership preserve extension ranges and detached results.
 * @return Number of failures.
 */
int test_safe_lifecycle() {
	Certificate original = Cert(EC_BothCritical);
	Certificate copied(original);
	Certificate assigned;
	assigned = original;
	Certificate moved(std::move(copied));
	Certificate move_assigned;
	move_assigned = std::move(assigned);
	StormByte::Safe::Vector<Certificate> stored;
	stored.push_back(moved);
	stored.push_back(std::move(move_assigned));
	original = Certificate{};
	for (const auto role : Roles) {
		ASSERT_TRUE(Fails(copied.VerifyTLSPurpose(role), PurposeError::InvalidCertificate));
		ASSERT_TRUE(Fails(assigned.VerifyTLSPurpose(role), PurposeError::InvalidCertificate));
		for (const auto& certificate : stored)
			ASSERT_TRUE(static_cast<bool>(certificate.VerifyTLSPurpose(role)));
	}
	ExpectedPurpose result = Cert(EC_Client).VerifyTLSPurpose(TLSRole::Server);
	ExpectedPurpose copy(result);
	ExpectedPurpose move(std::move(copy));
	ASSERT_TRUE(Fails(move, PurposeError::ExtendedKeyUsageNotAllowed));
	RETURN_TEST(0);
}

/**
 * @brief Purpose checks do not classify CA flags, compare identities or verify trust.
 * @return Number of failures.
 */
int test_purpose_is_not_authentication() {
	const auto certificate = Cert(EC_BothCritical);
	ASSERT_FALSE(static_cast<bool>(certificate.VerifyDNSName("purpose-fixture.invalid")));
	ASSERT_TRUE(static_cast<bool>(certificate.VerifyTLSPurpose(TLSRole::Server)));
	ASSERT_FALSE(certificate.VerifyChain({}, certificate));
	const auto ca = Cert(EC_CA);
	ASSERT_TRUE(ca.IsCA());
	for (const auto role : Roles)
		ASSERT_TRUE(static_cast<bool>(ca.VerifyTLSPurpose(role)));
	RETURN_TEST(0);
}

/**
 * @brief Runs independent purpose-validation regression tests.
 * @return Zero on success, nonzero on a failed assertion or exception.
 */
int main() {
	int result = 0;
	try {
		result += test_absent_usage_and_public_keys();
		result += test_role_specific_eku();
		result += test_any_eku_policy();
		result += test_malformed_eku();
		result += test_tls13_key_usage();
		result += test_malformed_ku_and_error_order();
		result += test_duplicate_eku_extension();
		result += test_invalid_role_and_empty_certificate();
		result += test_safe_lifecycle();
		result += test_purpose_is_not_authentication();
	} catch (const std::exception& error) {
		std::cerr << "Unexpected exception: " << error.what() << std::endl;
		return 1;
	}
	if (result == 0)
		std::cout << "All 10 purpose tests passed!" << std::endl;
	return result;
}
