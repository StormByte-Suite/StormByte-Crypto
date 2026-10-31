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

#include <algorithm>

namespace {
	using namespace StormByte::Crypto::TLS;

	/**
	 * @brief Check one ordered list without sorting or inserting profile entries.
	 * @tparam T Safe protocol identifier enum.
	 * @param preferences Caller-specified allowed identifiers, preferred first.
	 * @param profile Identifiers designated for the initial profile.
	 * @param empty Error for an empty list.
	 * @param unsupported Error for an identifier outside the profile.
	 * @param duplicate Error for a repeated identifier.
	 * @return Success or the first typed list error.
	 * @throws StormByte::Safe::AllocationError Error storage cannot be allocated.
	 */
	template<class T>
	StormByte::Expected<void, Error> ValidateList(
		const StormByte::Safe::Vector<T>& preferences,
		const StormByte::Safe::Vector<T>& profile,
		Error empty,
		Error unsupported,
		Error duplicate
	) {
		if (preferences.empty())
			return StormByte::Unexpected(empty);
		for (auto current = preferences.begin(); current != preferences.end(); ++current) {
			if (std::find(profile.begin(), profile.end(), *current) == profile.end())
				return StormByte::Unexpected(unsupported);
			if (std::find(preferences.begin(), current, *current) != current)
				return StormByte::Unexpected(duplicate);
		}
		return {};
	}
}

using namespace StormByte::Crypto::TLS;

Configuration StormByte::Crypto::TLS::InitialProfile() {
	return {};
}

ExpectedCipherSuiteDefinition StormByte::Crypto::TLS::DescribeCipherSuite(CipherSuite suite) {
	switch (suite) {
		case CipherSuite::TLS_AES_128_GCM_SHA256:
			return CipherSuiteDefinition{AEAD::Algorithm::AES128GCM, HKDF::Algorithm::SHA256};
		case CipherSuite::TLS_AES_256_GCM_SHA384:
			return CipherSuiteDefinition{AEAD::Algorithm::AES256GCM, HKDF::Algorithm::SHA384};
	}
	return StormByte::Unexpected<Error>(Error::UnsupportedCipherSuite);
}

ExpectedPolicy StormByte::Crypto::TLS::Validate(const Configuration& configuration) {
	if (configuration.version != Version::TLS13)
		return StormByte::Unexpected<Error>(Error::UnsupportedVersion);
	const auto profile = InitialProfile();
	auto suites = ValidateList(configuration.cipher_suites, profile.cipher_suites,
		Error::EmptyCipherSuites, Error::UnsupportedCipherSuite, Error::DuplicateCipherSuite);
	if (!suites)
		return StormByte::Unexpected(suites.error());
	auto groups = ValidateList(configuration.groups, profile.groups,
		Error::EmptyGroups, Error::UnsupportedGroup, Error::DuplicateGroup);
	if (!groups)
		return StormByte::Unexpected(groups.error());
	auto signatures = ValidateList(configuration.signature_schemes, profile.signature_schemes,
		Error::EmptySignatureSchemes, Error::UnsupportedSignatureScheme, Error::DuplicateSignatureScheme);
	if (!signatures)
		return StormByte::Unexpected(signatures.error());
	return Policy(configuration);
}

Policy::Policy(): Policy(Configuration{}) {}

Policy::Policy(const Configuration& configuration):
	m_configuration(StormByte::Safe::MakeShared<Configuration>(configuration)) {}

Policy::Policy(const Policy& other) = default;

Policy::Policy(Policy&& other) noexcept: m_configuration(other.m_configuration) {}

Policy::~Policy() noexcept = default;

Policy& Policy::operator=(const Policy& other) = default;

Policy& Policy::operator=(Policy&& other) noexcept {
	m_configuration = other.m_configuration;
	return *this;
}

const Configuration& Policy::Preferences() const noexcept {
	return *m_configuration;
}
