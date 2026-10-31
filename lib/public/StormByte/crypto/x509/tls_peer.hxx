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
			 * @enum TLSPeerError
			 * @brief Failures of the constrained, offline TLS signing-certificate verifier.
			 */
			enum class TLSPeerError {
				UnsupportedRole,				///< Role is neither Server nor Client.
				MissingServerIdentity,			///< A server requires an expected DNS or IP identity.
				UnsupportedIdentity,			///< Identity kind is neither DNS nor IP.
				InvalidCertificate,				///< A leaf, intermediate or anchor is empty.
				InvalidTime,					///< Caller time is outside a certificate's inclusive validity interval.
				LeafIsCA,						///< Peer leaf must not be a CA.
				NotCA,							///< Issuer is not a version 3 CA.
				IssuerKeyUsageNotAllowed,		///< Present issuer KU lacks keyCertSign.
				PathLengthExceeded,				///< Supplied CA count exceeds an issuer's pathLenConstraint.
				SignatureOrIssuerMismatch,		///< Ordered issuer name or certificate signature does not verify.
				UnsupportedAlgorithm,			///< Signature or public key is outside the documented subset.
				UnsupportedCriticalExtension,	///< Critical extension is not fully processed by this verifier.
				UnsupportedConstraint,			///< Present path restriction requires unsupported processing.
				MalformedExtension,				///< Relevant extension has invalid DER or inconsistent semantics.
				Purpose,						///< PurposeDetail supplies the exact EKU/KU failure.
				Identity						///< IdentityDetail supplies the exact SAN failure.
			};

			/**
			 * @class TLSPeerFailure
			 * @brief DLL-safe typed failure, with a leaf-to-anchor certificate index.
			 * @note All state is trivial; all value operations are out of line.
			 */
			class STORMBYTE_CRYPTO_PUBLIC TLSPeerFailure {
				public:
					/**
					 * @brief Constructs an invalid-certificate failure at the leaf.
					 */
					TLSPeerFailure() noexcept;

					/**
					 * @brief Constructs a chain or request failure.
					 * @param code Failure category.
					 * @param index Leaf is 0, intermediates are 1..N, anchor is N+1.
					 */
					explicit TLSPeerFailure(TLSPeerError code, std::size_t index = 0) noexcept;

					/**
					 * @brief Preserves a purpose failure.
					 * @param detail Exact purpose error.
					 * @param index Certificate that failed.
					 */
					explicit TLSPeerFailure(PurposeError detail, std::size_t index) noexcept;

					/**
					 * @brief Preserves an identity or SAN-validation failure.
					 * @param detail Exact identity error.
					 * @param index Certificate that failed; identity matching uses the leaf.
					 */
					explicit TLSPeerFailure(IdentityError detail, std::size_t index = 0) noexcept;

					/**
					 * @brief Copies a failure.
					 * @param other Source.
					 */
					TLSPeerFailure(const TLSPeerFailure& other) noexcept;

					/**
					 * @brief Moves a failure; the source remains usable.
					 * @param other Source.
					 */
					TLSPeerFailure(TLSPeerFailure&& other) noexcept;

					/**
					 * @brief Destroys a failure.
					 */
					~TLSPeerFailure() noexcept;

					/**
					 * @brief Copies a failure.
					 * @param other Source.
					 * @return This failure.
					 */
					TLSPeerFailure& operator=(const TLSPeerFailure& other) noexcept;

					/**
					 * @brief Moves a failure; the source remains usable.
					 * @param other Source.
					 * @return This failure.
					 */
					TLSPeerFailure& operator=(TLSPeerFailure&& other) noexcept;

					/**
					 * @brief Returns the failure category.
					 * @return Failure category.
					 */
					TLSPeerError Code() const noexcept;

					/**
					 * @brief Returns the certificate position.
					 * @return Leaf-to-anchor index; request and identity-matching errors use 0.
					 */
					std::size_t CertificateIndex() const noexcept;

					/**
					 * @brief Returns the preserved purpose error.
					 * @return Purpose error; meaningful only when Code() is Purpose.
					 */
					PurposeError PurposeDetail() const noexcept;

					/**
					 * @brief Returns the preserved identity error.
					 * @return Identity error; meaningful only when Code() is Identity.
					 */
					IdentityError IdentityDetail() const noexcept;

				private:
					TLSPeerError m_code;			///< Category.
					std::size_t m_index;			///< Leaf-to-anchor position.
					PurposeError m_purpose;		///< Detail for Purpose.
					IdentityError m_identity;	///< Detail for Identity.
			};
		}
	}
}

STORMBYTE_DECLARE_MAYBE_SAFE(StormByte::Crypto::X509::TLSPeerFailure);

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
			 * @brief Offline peer-certificate success or a detailed, indexed failure.
			 */
			using ExpectedTLSPeer = StormByte::Expected<void, TLSPeerFailure>;

			/**
			 * @class TLSPeerVerifier
			 * @brief Stateless composition for a deliberately constrained TLS 1.3 signing role.
			 *
			 * Not a TLS handshake or full RFC 5280 validator; no proof of key possession,
			 * revocation, path building, trust discovery, network access or policy evaluation.
			 * Success alone is NOT public HTTPS-ready authentication.
			 */
			class STORMBYTE_CRYPTO_PUBLIC TLSPeerVerifier {
				public:
					/**
					 * @brief Non-instantiable stateless verifier.
					 */
					TLSPeerVerifier() = delete;

					/**
					 * @brief Non-copyable stateless verifier.
					 * @param other Unavailable source.
					 */
					TLSPeerVerifier(const TLSPeerVerifier& other) = delete;

					/**
					 * @brief Non-movable stateless verifier.
					 * @param other Unavailable source.
					 */
					TLSPeerVerifier(TLSPeerVerifier&& other) = delete;

					/**
					 * @brief No instances exist to destroy.
					 */
					~TLSPeerVerifier() = delete;

					/**
					 * @brief Copy assignment is unavailable.
					 * @param other Unavailable source.
					 * @return No instance can be assigned.
					 */
					TLSPeerVerifier& operator=(const TLSPeerVerifier& other) = delete;

					/**
					 * @brief Move assignment is unavailable.
					 * @param other Unavailable source.
					 * @return No instance can be assigned.
					 */
					TLSPeerVerifier& operator=(TLSPeerVerifier&& other) = delete;

					/**
					 * @brief Verifies an ordered chain, signing purpose and optional SAN identity.
					 * @param leaf Untrusted non-CA peer certificate.
					 * @param intermediates Issuers in exact leaf-to-anchor order; excludes leaf and anchor.
					 * @param anchor Caller-selected trusted CA certificate, not inferred from the chain.
					 * @param at Explicit caller time, tested inclusively on every certificate.
					 * @param role Server or Client signing role, not a TLS key-exchange policy.
					 * @param identity Caller-owned DNS text or network-order IP bytes in SubjectAltName.
					 *        Required for Server. Null for Client checks trust/purpose only and makes
					 *        no client-identity or application-authorization assertion.
					 * @return Success for this subset, or the first typed failure with certificate index.
					 * @throws StormByte::Safe::AllocationError Result or SAN storage cannot be allocated.
					 *
					 * Composes the existing signature/name, validity, CA/pathLen, KU and SAN helpers
					 * without changing Certificate::VerifyChain. Each issuer requires keyCertSign
					 * if KU exists; only the leaf requires digitalSignature. Each present EKU,
					 * including on the anchor, must explicitly grant the role (anyEKU alone fails).
					 *
					 * The anchor is external trust input, so its self-signature and issuer name
					 * are NOT verified. As a deliberate local policy, its validity, v3 CA status,
					 * pathLen, KU, EKU, public-key suitability and extensions ARE enforced just
					 * like an issuer; this is stricter than RFC 5280's abstract trust-anchor input.
					 * Names chain by exact DER, and pathLen counts every supplied intermediate,
					 * including self-issued ones (conservative; no self-issued rollover processing).
					 *
					 * Keys: RSA 2048..8192 bits or named-curve ECDSA P-256/P-384/P-521.
					 * Non-anchor signatures: RSA PKCS#1 v1.5 or ECDSA with SHA-256/384/512.
					 * Critical BC, KU, EKU and DNS/IP-only SAN are processed. All other critical
					 * extensions, including SKI/AKI and certificatePolicies, fail unsupported.
					 * Name constraints, policy mappings, policy constraints and inhibitAnyPolicy
					 * fail unsupported even when noncritical. Noncritical certificatePolicies
					 * asserts policies but does not itself restrict a path: it is ignored, with
					 * no requested-policy acceptance claim. Other noncritical hints (SKI/AKI,
					 * AIA, CRL distribution points, issuerAltName, etc.) are ignored.
					 * TLS Feature (including OCSP Must-Staple) and proxyCertInfo also fail
					 * unsupported even when noncritical; their additional obligations cannot
					 * be satisfied by this certificate-only entrypoint.
					 *
					 * Every present SAN and KU/EKU is validated, even on issuers or identityless
					 * clients. KU agreement-only bits require keyAgreement; keyCertSign requires
					 * cA. No CN fallback. No CRL/OCSP checks; a revoked certificate can pass.
					 * See doc/tls-peer-verification.md for the supported-subset contract.
					 */
					static ExpectedTLSPeer Verify(const Certificate& leaf,
						std::span<const Certificate> intermediates, const Certificate& anchor,
						TimePoint at, TLSRole role, const SubjectAltName* identity = nullptr);
			};
		}
	}
}
