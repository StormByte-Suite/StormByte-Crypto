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

#pragma once

#include <StormByte/crypto/aead.hxx>
#include <StormByte/crypto/hkdf.hxx>
#include <StormByte/crypto/visibility.h>
#include <StormByte/expected.hxx>
#include <StormByte/safe/pointers.hxx>
#include <StormByte/safe/vector.hxx>

#include <cstdint>

/**
 * @namespace StormByte
 * @brief Root namespace of the StormByte suite.
 */
namespace StormByte {
	/**
	 * @namespace StormByte::Crypto
	 * @brief Cryptographic primitives and TLS 1.3 protocol implementation.
	 */
	namespace Crypto {
		/**
		 * @namespace StormByte::Crypto::TLS
		 * @brief TLS 1.3 policy and buffer-driven session engine.
		 */
		namespace TLS {
			/**
			 * @enum Version
			 * @brief Protocol versions designated for policy configuration.
			 */
			enum class Version: std::uint16_t {
				TLS13 = 0x0304	///< TLS 1.3 supported_versions identifier, not the record legacy version.
			};

			/**
			 * @enum CipherSuite
			 * @brief TLS 1.3 suites supported by the buffer-driven session engine.
			 */
			enum class CipherSuite: std::uint16_t {
				TLS_AES_128_GCM_SHA256 = 0x1301,	///< AES-128-GCM with SHA-256 transcript and HKDF.
				TLS_AES_256_GCM_SHA384 = 0x1302	///< AES-256-GCM with SHA-384 transcript and HKDF.
			};

			/**
			 * @enum Group
			 * @brief Named groups supported by the initial TLS 1.3 profile.
			 */
			enum class Group: std::uint16_t {
				X25519 = 0x001d,	///< Curve25519 key agreement.
				Secp256r1 = 0x0017	///< NIST P-256 key agreement.
			};

			/**
			 * @enum SignatureScheme
			 * @brief TLS 1.3 signature schemes supported by the session engine.
			 */
			enum class SignatureScheme: std::uint16_t {
				ECDSA_SECP256R1_SHA256 = 0x0403,	///< P-256 ECDSA/SHA-256.
				RSA_PSS_RSAE_SHA256 = 0x0804	///< RSA-PSS/SHA-256 with an rsaEncryption certificate key.
			};

			/**
			 * @enum Error
			 * @brief Configuration failures; no connection or backend is exercised.
			 */
			enum class Error {
				UnsupportedVersion,	///< Version is not exactly TLS 1.3.
				EmptyCipherSuites,	///< No allowed cipher suite was specified.
				UnsupportedCipherSuite,	///< A suite is outside the designated initial profile.
				DuplicateCipherSuite,	///< A suite appears more than once.
				EmptyGroups,	///< No allowed group was specified.
				UnsupportedGroup,	///< A group is outside the designated initial profile.
				DuplicateGroup,	///< A group appears more than once.
				EmptySignatureSchemes,	///< No allowed signature scheme was specified.
				UnsupportedSignatureScheme,	///< A scheme is outside the supported TLS 1.3 profile.
				DuplicateSignatureScheme	///< A scheme appears more than once.
			};

			/**
			 * @struct Configuration
			 * @brief Mutable input with independent ordered preference lists.
			 *
			 * Defaults contain the complete supported profile, preferred entries
			 * first (not a security-strength ranking).
			 * Subsets and reordering are permitted; validation neither sorts nor inserts
			 * fallbacks. Construction and copying can throw Base allocation errors.
			 */
			struct Configuration {
				/**
				 * @brief Construct the mutable default TLS 1.3 profile.
				 * @throws StormByte::Safe::AllocationError Preference storage cannot be allocated.
				 */
				Configuration() = default;

				/**
				 * @brief Independently copy the mutable preference lists.
				 * @param other Configuration to copy.
				 * @throws StormByte::Safe::AllocationError Preference storage cannot be allocated.
				 */
				Configuration(const Configuration& other) = default;

				/**
				 * @brief Transfer the mutable lists, leaving the source lists empty.
				 * @param other Configuration to move; requires reconfiguration before validation.
				 */
				Configuration(Configuration&& other) noexcept = default;

				/**
				 * @brief Release the Base-owned preference lists.
				 */
				~Configuration() noexcept = default;

				/**
				 * @brief Replace the mutable input with independent copies.
				 * @param other Configuration to copy.
				 * @return This configuration.
				 * @throws StormByte::Safe::AllocationError Preference storage cannot be allocated.
				 */
				Configuration& operator=(const Configuration& other) = default;

				/**
				 * @brief Replace the mutable lists by transferring their ownership.
				 * @param other Configuration to move; its lists are left empty.
				 * @return This configuration.
				 */
				Configuration& operator=(Configuration&& other) noexcept = default;

				Version version = Version::TLS13;	///< Only TLS 1.3 is accepted.

				/**
				 * @brief Allowed suites in descending preference order.
				 */
				StormByte::Safe::Vector<CipherSuite> cipher_suites{
					CipherSuite::TLS_AES_128_GCM_SHA256, CipherSuite::TLS_AES_256_GCM_SHA384
				};

				/**
				 * @brief Allowed groups in descending preference order, independent of suites.
				 */
				StormByte::Safe::Vector<Group> groups{Group::X25519, Group::Secp256r1};

				/**
				 * @brief Allowed signature schemes in descending preference order.
				 */
				StormByte::Safe::Vector<SignatureScheme> signature_schemes{
					SignatureScheme::ECDSA_SECP256R1_SHA256, SignatureScheme::RSA_PSS_RSAE_SHA256
				};
			};

			/**
			 * @struct CipherSuiteDefinition
			 * @brief Fixed primitive mapping, not an independently selectable pair.
			 */
			struct CipherSuiteDefinition {
				AEAD::Algorithm aead;	///< Raw-key authenticated encryption primitive.

				HKDF::Algorithm hash;	///< Inseparable HKDF and TLS transcript hash designation.
			};
		}
	}
}

STORMBYTE_DECLARE_MAYBE_SAFE(StormByte::Crypto::TLS::Configuration);
STORMBYTE_DECLARE_MAYBE_SAFE(StormByte::Crypto::TLS::CipherSuiteDefinition);

/**
 * @namespace StormByte
 * @brief Root namespace of the StormByte suite.
 */
namespace StormByte {
	/**
	 * @namespace StormByte::Crypto
	 * @brief Cryptographic primitives and TLS 1.3 protocol implementation.
	 */
	namespace Crypto {
		/**
		 * @namespace StormByte::Crypto::TLS
		 * @brief TLS policy and buffer-driven session implementation.
		 */
		namespace TLS {
			/**
			 * @brief Forward declaration of the immutable validated policy owner.
			 */
			class Policy;

			/**
			 * @brief Validated policy or Base-owned typed configuration error.
			 */
			using ExpectedPolicy = StormByte::Expected<Policy, Error>;

			/**
			 * @brief Fixed suite definition or Base-owned unsupported-suite error.
			 */
			using ExpectedCipherSuiteDefinition = StormByte::Expected<CipherSuiteDefinition, Error>;

			/**
			 * @brief Validate only membership, nonempty lists and uniqueness for the profile.
			 * @param configuration Mutable caller input copied on success.
			 * @return Immutable owned snapshot or first typed error.
			 * @throws StormByte::Safe::AllocationError Profile, snapshot or error storage cannot be allocated.
			 * @note Validation order is version, suites, groups, signatures; within a list,
			 *       left to right. A valid configuration is used by the TLS session engine.
			 *       Allocation exceptions propagate; borrowed input is not retained.
			 */
			STORMBYTE_CRYPTO_PUBLIC ExpectedPolicy Validate(const Configuration& configuration);

			/**
			 * @brief All designated initial-profile entries in default preference order.
			 * @return Independently owned lists of every designated profile entry.
			 * @throws StormByte::Safe::AllocationError Preference storage cannot be allocated.
			 * @note This is the default TLS 1.3 policy profile.
			 *       Each call returns independently owned mutable Safe containers.
			 */
			STORMBYTE_CRYPTO_PUBLIC Configuration InitialProfile();

			/**
			 * @brief Describe a registered suite's fixed AEAD and HKDF/transcript hash.
			 * @param suite Registered cipher-suite identifier to describe.
			 * @return Fixed primitive mapping or UnsupportedCipherSuite.
			 * @throws StormByte::Safe::AllocationError Error storage cannot be allocated.
			 */
			STORMBYTE_CRYPTO_PUBLIC ExpectedCipherSuiteDefinition DescribeCipherSuite(CipherSuite suite);

			/**
			 * @class Policy
			 * @brief Immutable validated TLS 1.3 policy snapshot.
			 *
			 * Safe::Shared stores a const Configuration on Base's heap; the factory copies
			 * caller preferences. Copies and moves share immutable storage; moves preserve
			 * the source, so every Policy continues to contain a validated snapshot.
			 * Assignment replaces the entire snapshot, never edits it. References from
			 * Preferences() must not outlive their snapshot. Keep compatible Crypto/Base
			 * providers loaded while any Policy or returned Safe value exists.
			 *
			 * The policy is consumed by the buffer-driven TLS session; it does not
			 * configure network transports.
			 */
			class STORMBYTE_CRYPTO_PUBLIC Policy final {
				public:
					/**
					 * @brief Construct the validated default TLS 1.3 profile.
					 * @throws StormByte::Safe::AllocationError Snapshot or preference storage cannot be allocated.
					 */
					Policy();

					/**
					 * @brief Share the immutable validated snapshot.
					 * @param other Policy whose snapshot is retained.
					 */
					Policy(const Policy& other);

					/**
					 * @brief Retain the immutable snapshot without invalidating the source.
					 * @param other Policy whose snapshot is shared; it remains unchanged.
					 */
					Policy(Policy&& other) noexcept;

					/**
					 * @brief Release this snapshot reference; the last owner releases Base storage.
					 */
					~Policy() noexcept;

					/**
					 * @brief Replace this snapshot with the source's immutable snapshot.
					 * @param other Policy whose snapshot is retained.
					 * @return This policy.
					 */
					Policy& operator=(const Policy& other);

					/**
					 * @brief Replace this snapshot while preserving the source policy.
					 * @param other Policy whose snapshot is shared; it remains unchanged.
					 * @return This policy.
					 */
					Policy& operator=(Policy&& other) noexcept;

					/**
					 * @brief Read the exact validated preferences; no mutable access.
					 * @return Borrowed immutable configuration owned by the retained snapshot.
					 */
					const Configuration& Preferences() const noexcept;

				private:
					/**
					 * @brief Copy already validated preferences into an immutable Base-owned snapshot.
					 * @param configuration Input whose membership and lists were checked by Validate.
					 * @throws StormByte::Safe::AllocationError Snapshot or preference storage cannot be allocated.
					 */
					explicit Policy(const Configuration& configuration);

					/**
					 * @brief Permit snapshot construction only after designated-profile validation.
					 * @param configuration Caller input to validate and copy.
					 * @return Immutable owned snapshot or first typed configuration error.
					 * @throws StormByte::Safe::AllocationError Profile, snapshot or error storage cannot be allocated.
					 */
					friend ExpectedPolicy Validate(const Configuration& configuration);

					StormByte::Safe::Shared<const Configuration> m_configuration;	///< Non-null immutable Base-owned snapshot.
			};
		}
	}
}

STORMBYTE_DECLARE_MAYBE_SAFE(StormByte::Crypto::TLS::Policy);
