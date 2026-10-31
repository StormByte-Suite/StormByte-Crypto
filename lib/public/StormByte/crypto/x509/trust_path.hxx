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

#include <StormByte/crypto/x509/tls_peer.hxx>

/**
 * @namespace StormByte
 * @brief Root namespace of the StormByte suite.
 */
namespace StormByte {
	/**
	 * @namespace StormByte::Crypto
	 * @brief Crypto module of the StormByte suite.
	 */
	namespace Crypto {
		/**
		 * @namespace StormByte::Crypto::X509
		 * @brief X.509 certificate parsing and verification.
		 */
		namespace X509 {
			/**
			 * @enum TrustPathError
			 * @brief Failures of path validation, never a full authentication verdict.
			 */
			enum class TrustPathError {
				BundleInvalid,			///< Snapshot digest, count or certificate parsing failed.
				InvalidRequest,			///< Empty certificate, invalid identity or excessive chain length.
				RootNotAdmitted,			///< No matching root belongs to the bundled server snapshot.
				PeerPathRejected,		///< Linux's documented constrained verifier rejected the path.
				NativePolicyRejected	///< Native TLS policy or intersection with native trust rejected it.
			};

			/**
			 * @enum PaymentPeerError
			 * @brief Fail-closed payment peer failures until mandatory revocation is implemented.
			 */
			enum class PaymentPeerError {
				TrustPathRejected,		///< Path validation failed before revocation processing.
				RevocationUnavailable	///< No authenticated, fresh CRL/OCSP evidence can be validated yet.
			};

			/**
			 * @brief Library-owned certificates or an integrity/parse failure.
			 */
			using ExpectedBundledTLSRoots = StormByte::Expected<Safe::Vector<Certificate>, TrustPathError>;

			/**
			 * @brief Path-only success or an explicit failure, with no revocation assertion.
			 */
			using ExpectedTrustPath = StormByte::Expected<void, TrustPathError>;

			/**
			 * @brief Payment verification result; this unit never returns success.
			 */
			using ExpectedPaymentPeer = StormByte::Expected<void, PaymentPeerError>;

			/**
			 * @brief Returns the immutable snapshot revision.
			 * @return Library-owned NSS revision identifier.
			 */
			STORMBYTE_CRYPTO_PUBLIC const char* BundledTLSRootsRevision() noexcept;

			/**
			 * @brief Returns the embedded PEM integrity fingerprint.
			 * @return Library-owned lowercase SHA-256 hexadecimal text.
			 */
			STORMBYTE_CRYPTO_PUBLIC const char* BundledTLSRootsSHA256() noexcept;

			/**
			 * @brief Loads a verified copy of the versioned, curated Mozilla server roots.
			 * @return Safe certificate vector, or BundleInvalid; never system or environment roots.
			 * @throws StormByte::Safe::AllocationError Storage cannot be allocated.
			 * @note Updating the returned copy cannot modify production trust. No file or network I/O.
			 */
			STORMBYTE_CRYPTO_PUBLIC ExpectedBundledTLSRoots LoadBundledTLSRoots();

			/**
			 * @brief Validates only a server trust path and SAN identity against bundled admission.
			 * @param leaf Untrusted server certificate.
			 * @param intermediates Issuers, excluding leaf and root; Linux requires exact order.
			 * @param at Explicit validation time, with second precision.
			 * @param identity Expected DNS or network-order IP identity; no CN fallback.
			 * @return Path-only result. Success is NOT peer authentication or payment authorization.
			 * @throws StormByte::Safe::AllocationError Storage cannot be allocated.
			 *
			 * Linux uses only the embedded roots and the constrained TLSPeerVerifier subset,
			 * including unsupported-constraint failures. It never consults distro, environment
			 * or system CA files. Windows/macOS require BOTH scoped bundled anchors AND native
			 * TLS policy with native system trust, with the same terminal root in both paths.
			 * Network fetching is disabled. No CRL/OCSP validation or proof of key possession.
			 * See doc/trust-path-validation.md for exclusions and exact policy limitations.
			 */
			STORMBYTE_CRYPTO_PUBLIC ExpectedTrustPath ValidateBundledTLSPath(const Certificate& leaf,
				std::span<const Certificate> intermediates, TimePoint at, const SubjectAltName& identity);

			/**
			 * @brief Validates a separate, explicitly opted-in custom-CA server path.
			 * @param leaf Untrusted server certificate.
			 * @param intermediates Issuers, excluding leaf and anchor.
			 * @param anchor Explicit caller-selected custom trust anchor.
			 * @param at Explicit validation time.
			 * @param identity Expected DNS or IP identity.
			 * @return Path-only result; custom trust never modifies bundled admission.
			 * @throws StormByte::Safe::AllocationError Storage cannot be allocated.
			 * @note Native platforms apply scoped native TLS policy, without requiring OS root
			 *       admission of the custom CA. Linux retains TLSPeerVerifier's constraints.
			 */
			STORMBYTE_CRYPTO_PUBLIC ExpectedTrustPath ValidateCustomCATLSPath(const Certificate& leaf,
				std::span<const Certificate> intermediates, const Certificate& anchor,
				TimePoint at, const SubjectAltName& identity);

			/**
			 * @brief Fails closed after path validation because payment revocation is mandatory.
			 * @param leaf Untrusted server certificate.
			 * @param intermediates Issuers, excluding leaf and root.
			 * @param at Explicit validation time.
			 * @param identity Expected payment endpoint DNS or IP identity.
			 * @return TrustPathRejected or RevocationUnavailable; never success.
			 * @throws StormByte::Safe::AllocationError Storage cannot be allocated.
			 * @note Absent, unknown, stale or invalid revocation evidence must fail. No caller
			 *       flag can bypass this gate. Actual CRL/OCSP validation is a mandatory next unit.
			 */
			STORMBYTE_CRYPTO_PUBLIC ExpectedPaymentPeer VerifyPaymentPeer(const Certificate& leaf,
				std::span<const Certificate> intermediates, TimePoint at, const SubjectAltName& identity);
		}
	}
}
