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

#include <StormByte/crypto/tls/policy.hxx>
#include <StormByte/safe/optional.hxx>
#include <StormByte/test_handlers.h>

#include <algorithm>
#include <array>
#include <iostream>
#include <type_traits>
#include <utility>

using namespace StormByte::Crypto;
using namespace StormByte::Crypto::TLS;

static_assert(std::is_same_v<decltype(std::declval<Policy&>().Preferences()), const Configuration&>);
static_assert(StormByte::Type::SafeValue<Configuration>);
static_assert(StormByte::Type::SafeValue<Policy>);
static_assert(StormByte::Type::SafeValue<CipherSuiteDefinition>);
static_assert(sizeof(Version) == 2 && sizeof(CipherSuite) == 2);
static_assert(sizeof(Group) == 2 && sizeof(SignatureScheme) == 2);

namespace {
	/**
	 * @brief Compare versions and all preference lists, including their order.
	 * @param left First configuration.
	 * @param right Second configuration.
	 * @return Whether both configurations contain exactly the same preferences.
	 */
	bool Equal(const Configuration& left, const Configuration& right) {
		return left.version == right.version
			&& std::ranges::equal(left.cipher_suites, right.cipher_suites)
			&& std::ranges::equal(left.groups, right.groups)
			&& std::ranges::equal(left.signature_schemes, right.signature_schemes);
	}

	/**
	 * @brief Check that validation rejects the input with the designated error.
	 * @param configuration Input to validate.
	 * @param error Expected typed rejection.
	 * @return Whether validation failed with the expected error.
	 * @throws StormByte::Safe::AllocationError Validation storage cannot be allocated.
	 */
	bool Rejected(const Configuration& configuration, Error error) {
		const auto result = Validate(configuration);
		return !result && *result.error() == error;
	}
}

// -------------------
// Algorithms and defaults
// -------------------

/**
 * @brief Check every profile combination and each inseparable primitive mapping.
 * @return Accumulated assertion failures.
 * @throws StormByte::Safe::AllocationError Test storage cannot be allocated.
 */
int test_fixed_suite_definitions_and_all_profile_entries() {
	const auto aes128 = DescribeCipherSuite(CipherSuite::TLS_AES_128_GCM_SHA256);
	ASSERT_TRUE(aes128);
	ASSERT_TRUE(aes128->aead == AEAD::Algorithm::AES128GCM);
	ASSERT_TRUE(aes128->hash == HKDF::Algorithm::SHA256);
	const auto aes256 = DescribeCipherSuite(CipherSuite::TLS_AES_256_GCM_SHA384);
	ASSERT_TRUE(aes256);
	ASSERT_TRUE(aes256->aead == AEAD::Algorithm::AES256GCM);
	ASSERT_TRUE(aes256->hash == HKDF::Algorithm::SHA384);
	for (const auto suite : InitialProfile().cipher_suites) {
		for (const auto group : InitialProfile().groups) {
			for (const auto scheme : InitialProfile().signature_schemes) {
				Configuration configuration;
				configuration.cipher_suites = {suite};
				configuration.groups = {group};
				configuration.signature_schemes = {scheme};
				const auto result = Validate(configuration);
				ASSERT_TRUE(result);
				ASSERT_TRUE(Equal(configuration, result->Preferences()));
				ASSERT_TRUE(DescribeCipherSuite(suite));
			}
		}
	}
	for (const auto id : {0, 0x1300, 0x1303, 0xffff}) {
		auto result = DescribeCipherSuite(static_cast<CipherSuite>(id));
		ASSERT_FALSE(result);
		ASSERT_TRUE(*result.error() == Error::UnsupportedCipherSuite);
	}
	RETURN_TEST(0);
}

/**
 * @brief Check exact registered identifiers and default preference order.
 * @return Accumulated assertion failures.
 * @throws StormByte::Safe::AllocationError Test storage cannot be allocated.
 */
int test_protocol_ids_and_defaults() {
	ASSERT_EQUAL(std::uint16_t{0x0304}, static_cast<std::uint16_t>(Version::TLS13));
	ASSERT_EQUAL(std::uint16_t{0x1301}, static_cast<std::uint16_t>(CipherSuite::TLS_AES_128_GCM_SHA256));
	ASSERT_EQUAL(std::uint16_t{0x1302}, static_cast<std::uint16_t>(CipherSuite::TLS_AES_256_GCM_SHA384));
	ASSERT_EQUAL(std::uint16_t{0x001d}, static_cast<std::uint16_t>(Group::X25519));
	ASSERT_EQUAL(std::uint16_t{0x0017}, static_cast<std::uint16_t>(Group::Secp256r1));
	ASSERT_EQUAL(std::uint16_t{0x0403}, static_cast<std::uint16_t>(SignatureScheme::ECDSA_SECP256R1_SHA256));
	const auto profile = InitialProfile();
	ASSERT_TRUE(profile.version == Version::TLS13);
	ASSERT_TRUE(std::ranges::equal(profile.cipher_suites, std::array{
		CipherSuite::TLS_AES_128_GCM_SHA256, CipherSuite::TLS_AES_256_GCM_SHA384}));
	ASSERT_TRUE(std::ranges::equal(profile.groups, std::array{Group::X25519, Group::Secp256r1}));
	ASSERT_TRUE(std::ranges::equal(profile.signature_schemes,
		std::array{SignatureScheme::ECDSA_SECP256R1_SHA256}));
	const auto result = Validate(Configuration{});
	ASSERT_TRUE(result);
	ASSERT_TRUE(Equal(profile, result->Preferences()));
	ASSERT_TRUE(Equal(profile, Policy{}.Preferences()));
	RETURN_TEST(0);
}

// -------------------
// Invalid configuration
// -------------------

/**
 * @brief Reject empty, repeated and undesignated values in every preference list.
 * @return Accumulated assertion failures.
 * @throws StormByte::Safe::AllocationError Test storage cannot be allocated.
 */
int test_empty_duplicate_and_unknown_preferences() {
	Configuration configuration;
	configuration.cipher_suites.clear();
	ASSERT_TRUE(Rejected(configuration, Error::EmptyCipherSuites));
	configuration = {};
	configuration.groups.clear();
	ASSERT_TRUE(Rejected(configuration, Error::EmptyGroups));
	configuration = {};
	configuration.signature_schemes.clear();
	ASSERT_TRUE(Rejected(configuration, Error::EmptySignatureSchemes));
	for (const auto suite : InitialProfile().cipher_suites) {
		configuration = {};
		configuration.cipher_suites.push_back(suite);
		ASSERT_TRUE(Rejected(configuration, Error::DuplicateCipherSuite));
	}
	for (const auto group : InitialProfile().groups) {
		configuration = {};
		configuration.groups.push_back(group);
		ASSERT_TRUE(Rejected(configuration, Error::DuplicateGroup));
	}
	configuration = {};
	configuration.signature_schemes.push_back(SignatureScheme::ECDSA_SECP256R1_SHA256);
	ASSERT_TRUE(Rejected(configuration, Error::DuplicateSignatureScheme));
	for (const auto id : {0, 0x1303, 0xffff}) {
		configuration = {};
		configuration.cipher_suites.push_back(static_cast<CipherSuite>(id));
		ASSERT_TRUE(Rejected(configuration, Error::UnsupportedCipherSuite));
		configuration.cipher_suites = {static_cast<CipherSuite>(id)};
		ASSERT_TRUE(Rejected(configuration, Error::UnsupportedCipherSuite));
	}
	for (const auto id : {0, 0x0018, 0xffff}) {
		configuration = {};
		configuration.groups.push_back(static_cast<Group>(id));
		ASSERT_TRUE(Rejected(configuration, Error::UnsupportedGroup));
		configuration.groups = {static_cast<Group>(id)};
		ASSERT_TRUE(Rejected(configuration, Error::UnsupportedGroup));
	}
	for (const auto id : {0, 0x0401, 0x0804, 0xffff}) {
		configuration = {};
		configuration.signature_schemes.push_back(static_cast<SignatureScheme>(id));
		ASSERT_TRUE(Rejected(configuration, Error::UnsupportedSignatureScheme));
		configuration.signature_schemes = {static_cast<SignatureScheme>(id)};
		ASSERT_TRUE(Rejected(configuration, Error::UnsupportedSignatureScheme));
	}
	RETURN_TEST(0);
}

/**
 * @brief Reject non-TLS-1.3 versions and check deterministic first-error ordering.
 * @return Accumulated assertion failures.
 * @throws StormByte::Safe::AllocationError Test storage cannot be allocated.
 */
int test_version_rejection_and_error_precedence() {
	for (const auto id : {0, 0x0301, 0x0302, 0x0303, 0x0305, 0xffff}) {
		Configuration configuration;
		configuration.version = static_cast<Version>(id);
		ASSERT_TRUE(Rejected(configuration, Error::UnsupportedVersion));
		configuration.cipher_suites.clear();
		ASSERT_TRUE(Rejected(configuration, Error::UnsupportedVersion));
	}
	Configuration configuration;
	configuration.cipher_suites.clear();
	configuration.groups.clear();
	configuration.signature_schemes.clear();
	ASSERT_TRUE(Rejected(configuration, Error::EmptyCipherSuites));
	configuration.cipher_suites = InitialProfile().cipher_suites;
	ASSERT_TRUE(Rejected(configuration, Error::EmptyGroups));
	configuration.groups = InitialProfile().groups;
	ASSERT_TRUE(Rejected(configuration, Error::EmptySignatureSchemes));
	configuration = {};
	configuration.cipher_suites = {static_cast<CipherSuite>(0xffff),
		CipherSuite::TLS_AES_128_GCM_SHA256, CipherSuite::TLS_AES_128_GCM_SHA256};
	ASSERT_TRUE(Rejected(configuration, Error::UnsupportedCipherSuite));
	configuration.cipher_suites = {CipherSuite::TLS_AES_128_GCM_SHA256,
		CipherSuite::TLS_AES_128_GCM_SHA256, static_cast<CipherSuite>(0xffff)};
	ASSERT_TRUE(Rejected(configuration, Error::DuplicateCipherSuite));
	RETURN_TEST(0);
}

// -------------------
// Lifecycle
// -------------------

/**
 * @brief Exercise immutable snapshots, Safe ownership and all value operations.
 * @return Accumulated assertion failures.
 * @throws StormByte::Safe::AllocationError Test storage cannot be allocated.
 */
int test_order_snapshot_and_safe_lifecycle() {
	StormByte::Safe::Optional<Policy> retained;
	StormByte::Safe::Vector<Policy> stored;
	Configuration expected;
	expected.cipher_suites = {CipherSuite::TLS_AES_256_GCM_SHA384, CipherSuite::TLS_AES_128_GCM_SHA256};
	expected.groups = {Group::Secp256r1, Group::X25519};
	Configuration inputCopy(expected);
	Configuration inputMoved(std::move(inputCopy));
	ASSERT_TRUE(Equal(expected, inputMoved));
	ASSERT_TRUE(inputCopy.cipher_suites.empty() && inputCopy.groups.empty()
		&& inputCopy.signature_schemes.empty());
	Configuration inputAssigned;
	inputAssigned = inputMoved;
	Configuration inputMoveAssigned;
	inputMoveAssigned = std::move(inputAssigned);
	ASSERT_TRUE(Equal(expected, inputMoveAssigned));
	ASSERT_TRUE(inputAssigned.cipher_suites.empty() && inputAssigned.groups.empty()
		&& inputAssigned.signature_schemes.empty());
	inputMoveAssigned.groups.clear();
	ASSERT_TRUE(Equal(expected, inputMoved));
	{
		auto configuration = expected;
		auto result = Validate(configuration);
		ASSERT_TRUE(result);
		ASSERT_TRUE(Equal(expected, result->Preferences()));
		configuration.cipher_suites.clear();
		configuration.groups.clear();
		configuration.signature_schemes.clear();
		ASSERT_TRUE(Equal(expected, result->Preferences()));
		Policy copied(*result);
		Policy moved(std::move(copied));
		ASSERT_TRUE(Equal(expected, copied.Preferences()));
		ASSERT_TRUE(Equal(expected, moved.Preferences()));
		Policy assigned;
		assigned = moved;
		Policy moveAssigned;
		moveAssigned = std::move(assigned);
		ASSERT_TRUE(Equal(expected, assigned.Preferences()));
		ASSERT_TRUE(Equal(expected, moveAssigned.Preferences()));
		auto* self = &moveAssigned;
		moveAssigned = *self;
		moveAssigned = std::move(*self);
		ASSERT_TRUE(Equal(expected, moveAssigned.Preferences()));
		auto expectedCopy = result;
		auto expectedMoved = std::move(expectedCopy);
		ASSERT_TRUE(expectedCopy && expectedMoved);
		ASSERT_TRUE(Equal(expected, expectedCopy->Preferences()));
		retained = std::move(*expectedMoved);
		stored.push_back(moveAssigned);
		stored.push_back(std::move(moved));
		ASSERT_TRUE(Equal(expected, moved.Preferences()));
	}
	ASSERT_TRUE(Equal(expected, retained->Preferences()));
	for (const auto& policy : stored)
		ASSERT_TRUE(Equal(expected, policy.Preferences()));
	auto copied = stored;
	auto moved = std::move(copied);
	ASSERT_TRUE(copied.empty());
	stored.clear();
	retained = std::nullopt;
	ASSERT_TRUE(Equal(expected, moved[StormByte::Size{0}].Preferences()));
	auto profile = InitialProfile();
	profile.cipher_suites.clear();
	ASSERT_TRUE(Equal(Configuration{}, InitialProfile()));
	Configuration invalid;
	invalid.groups.clear();
	auto failure = Validate(invalid);
	auto failureCopy = failure;
	auto failureMoved = std::move(failureCopy);
	ASSERT_FALSE(failureMoved);
	ASSERT_TRUE(*failureMoved.error() == Error::EmptyGroups);
	RETURN_TEST(0);
}

/**
 * @brief Run all bounded TLS policy tests without attempting a connection.
 * @return Zero on success, accumulated assertion failures otherwise.
 * @throws StormByte::Safe::AllocationError Test storage cannot be allocated.
 */
int main() {
	int result = 0;
	// -------------------
	// Algorithms and defaults
	// -------------------
	result += test_fixed_suite_definitions_and_all_profile_entries();
	result += test_protocol_ids_and_defaults();
	// -------------------
	// Invalid configuration
	// -------------------
	result += test_empty_duplicate_and_unknown_preferences();
	result += test_version_rejection_and_error_precedence();
	// -------------------
	// Lifecycle
	// -------------------
	result += test_order_snapshot_and_safe_lifecycle();
	if (result == 0)
		std::cout << "All TLS policy tests passed!" << std::endl;
	return result;
}
