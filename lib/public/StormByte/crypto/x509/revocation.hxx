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
 *    Foundation, either version 3 of the License, or (at your option) any
 *    later version.
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * version 3 along with StormByte-Crypto. If not, see
 * <https://www.gnu.org/licenses/lgpl-3.0.html>.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-StormByte-Commercial
 */

#pragma once

#include <StormByte/crypto/x509/certificate.hxx>

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
			 * @enum RevocationFormat
			 * @brief Encoding of offline revocation evidence supplied by the caller.
			 */
			enum class RevocationFormat {
				CRL,	///< DER-encoded complete X.509 CertificateList.
				OCSP	///< DER-encoded successful OCSPResponse containing BasicOCSPResponse.
			};

			/**
			 * @enum RevocationStatus
			 * @brief Authenticated status reported by a verified evidence object.
			 */
			enum class RevocationStatus {
				Good,		///< Evidence covers the certificate and does not report it revoked.
				Revoked,	///< A verified CRL or OCSP response reports revocation.
				Unknown		///< A verified OCSP response explicitly reports unknown status.
			};

			/**
			 * @enum RevocationError
			 * @brief Failures that prevent trusting revocation evidence.
			 */
			enum class RevocationError {
				InvalidRequest,		///< Empty certificates, invalid issuer relationship or oversized evidence.
				MalformedEvidence,	///< Invalid DER, duplicate fields, or malformed status data.
				UnsupportedFeature,	///< Unsupported algorithm, CRL scope, extension or response type.
				IssuerMismatch,		///< Evidence issuer or OCSP CertID does not match the supplied issuer.
				CertificateMismatch,	///< Evidence does not contain a status for the target certificate.
				InvalidSignature,		///< Evidence signature cannot be verified with an authorized key.
				ResponderUnauthorized,	///< OCSP signer is not the issuer or an authorized delegated responder.
				NotYetValid,		///< Evidence was produced after the requested validation time.
				Stale,			///< Evidence validity interval does not cover the requested time.
				MissingNextUpdate	///< Evidence has no bounded freshness interval.
			};

			/**
			 * @brief Authenticated certificate status or a typed evidence-validation failure.
			 */
			using ExpectedRevocation = StormByte::Expected<RevocationStatus, RevocationError>;

			/**
			 * @struct RevocationEvidence
			 * @brief Borrowed DER evidence for one certificate in a chain.
			 */
			struct RevocationEvidence final {
				RevocationFormat format;	///< CRL or OCSP encoding.
				std::span<const std::byte> der;	///< Untrusted DER, consumed synchronously.
			};

			/**
			 * @class RevocationVerifier
			 * @brief Verifies supplied CRL/OCSP evidence offline using Crypto primitives.
			 *
			 * This verifier performs no network, filesystem, native trust-store, cache or
			 * clock access. It only accepts bounded signed evidence with an explicit
			 * validation time. Unsupported CRL distribution scopes and extensions fail
			 * closed; delegated OCSP responders must be embedded and directly authorized
			 * by the certificate issuer.
			 */
			class STORMBYTE_CRYPTO_PUBLIC RevocationVerifier final {
				public:
					/**
					 * @brief Verifies one complete CRL or OCSP response for a certificate.
					 * @param certificate Certificate whose status is requested.
					 * @param issuer Certificate that issued @p certificate and signs the evidence.
					 * @param format Evidence encoding.
					 * @param der Untrusted DER evidence; maximum size is 4 MiB.
					 * @param at Explicit validation instant.
					 * @return Authenticated Good, Revoked or Unknown status, or a validation error.
					 * @throws StormByte::Safe::AllocationError Safe-owned certificate data cannot be allocated.
					 * @note OCSP supports SHA-1/SHA-256/SHA-384/SHA-512 CertID hashes and
					 *       issuer-signed or embedded, directly delegated OCSP-signing certificates.
					 *       CRL and OCSP signatures support the certificate verifier's SHA-2 RSA
					 *       PKCS#1 v1.5 and ECDSA algorithms; SHA-1 and RSA-PSS signatures fail.
					 *       CRLs must be complete, issuer-wide, time-bounded and directly signed
					 *       by the issuer; delta and indirect CRLs are not supported. OCSP
					 *       response/per-certificate extensions, including nonce, are rejected.
					 */
					static ExpectedRevocation Verify(const Certificate& certificate, const Certificate& issuer,
						RevocationFormat format, std::span<const std::byte> der, TimePoint at);
			};
		}
	}
}
