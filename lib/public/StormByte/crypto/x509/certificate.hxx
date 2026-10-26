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

#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/visibility.h>
#include <StormByte/safe/binary.hxx>
#include <StormByte/safe/optional.hxx>
#include <StormByte/safe/string.hxx>
#include <StormByte/safe/vector.hxx>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>

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
		 * @brief X.509 certificate parsing and chain verification.
		 */
		namespace X509 {
			/**
			 * @brief Point in time with second precision, as stored in certificates.
			 */
			using TimePoint = std::chrono::sys_seconds;

			/**
			 * @enum KeyUsage
			 * @brief Bits of the keyUsage extension (RFC 5280 §4.2.1.3).
			 */
			enum class KeyUsage: std::uint16_t {
				DigitalSignature	= 1u << 0,	///< digitalSignature
				NonRepudiation		= 1u << 1,	///< nonRepudiation (contentCommitment)
				KeyEncipherment		= 1u << 2,	///< keyEncipherment
				DataEncipherment	= 1u << 3,	///< dataEncipherment
				KeyAgreement		= 1u << 4,	///< keyAgreement
				KeyCertSign			= 1u << 5,	///< keyCertSign
				CRLSign				= 1u << 6,	///< cRLSign
				EncipherOnly		= 1u << 7,	///< encipherOnly
				DecipherOnly		= 1u << 8	///< decipherOnly
			};

			/**
			 * @class Certificate
			 * @brief Immutable, strictly DER-parsed X.509 certificate.
			 *
			 * Supported signatures: ecdsa-with-SHA256/384/512 and
			 * sha256/384/512WithRSAEncryption (PKCS#1 v1.5). Other algorithms load
			 * but never verify. Names are compared byte-for-byte, and revocation
			 * (CRL/OCSP) and name constraints are not processed.
			 * @note Certificates are public data; unlike keys they use @ref StormByte::Safe::Binary.
			 * @note Conditionally DLL-safe: all fields are Safe or trivial and value operations
			 *       are defined out of line in Crypto.
			 */
			class STORMBYTE_CRYPTO_PUBLIC Certificate {
				public:
					/**
					 * @name Construction
					 * @{
					 */
					/**
					 * @brief Empty certificate; it has no DER and never verifies.
					 */
					Certificate() noexcept;

					/**
					 * @brief Copy constructor.
					 * @param other Certificate to copy.
					 */
					Certificate(const Certificate& other);

					/**
					 * @brief Move constructor.
					 * @param other Certificate to move.
					 */
					Certificate(Certificate&& other) noexcept;

					/**
					 * @brief Destructor.
					 */
					~Certificate() noexcept;

					/**
					 * @brief Copy assignment.
					 * @param other Certificate to copy.
					 * @return Reference to this certificate.
					 */
					Certificate& operator=(const Certificate& other);

					/**
					 * @brief Move assignment.
					 * @param other Certificate to move.
					 * @return Reference to this certificate.
					 */
					Certificate& operator=(Certificate&& other) noexcept;

					/**
					 * @brief Compares the DER encodings.
					 * @param other Certificate to compare.
					 * @return true when both encodings are identical.
					 */
					bool operator==(const Certificate& other) const noexcept;
					/** @} */

					/**
					 * @name Encoding
					 * @{
					 */
					/**
					 * @brief Parses a single DER certificate; see also @ref X509::Load.
					 * @param der Candidate DER bytes, without trailing data.
					 * @param out Destination; reset to an empty certificate on failure.
					 * @return false on malformed input.
					 */
					static bool Parse(std::span<const std::byte> der, Certificate& out) noexcept;

					/**
					 * @brief Encodes the certificate.
					 * @param format PEM (CERTIFICATE block, 64-column Base64) or DER.
					 * @return Encoded certificate.
					 */
					Safe::Binary Save(KeyPair::StorageFormat format = KeyPair::StorageFormat::PEM) const;

					/**
					 * @brief Returns the original DER encoding.
					 * @return DER bytes.
					 */
					const Safe::Binary& Der() const noexcept;
					/** @} */

					/**
					 * @name Fields
					 * @{
					 */
					/**
					 * @brief Returns the certificate version.
					 * @return 1, 2 or 3.
					 */
					unsigned Version() const noexcept;

					/**
					 * @brief Returns the serial number.
					 * @return Big-endian two's-complement INTEGER contents.
					 */
					Safe::Binary SerialNumber() const;

					/**
					 * @brief Returns the subject common name.
					 * @return First CN attribute, or empty when absent or not a string type.
					 */
					Safe::String SubjectCommonName() const;

					/**
					 * @brief Returns the issuer common name.
					 * @return First CN attribute, or empty when absent or not a string type.
					 */
					Safe::String IssuerCommonName() const;

					/**
					 * @brief Returns the start of the validity period.
					 * @return notBefore.
					 */
					TimePoint NotBefore() const noexcept;

					/**
					 * @brief Returns the end of the validity period.
					 * @return notAfter, inclusive.
					 */
					TimePoint NotAfter() const noexcept;

					/**
					 * @brief Tells whether basicConstraints marks the certificate as a CA.
					 * @return true for cA = TRUE.
					 */
					bool IsCA() const noexcept;

					/**
					 * @brief Returns the basicConstraints path length constraint.
					 * @return Maximum number of intermediate CAs below this one, or empty when unlimited.
					 */
					Safe::Optional<std::uint32_t> PathLength() const;

					/**
					 * @brief Tells whether the key may be used for @p usage.
					 * @param usage Usage to test.
					 * @return true when the bit is set, or when keyUsage is absent (unrestricted).
					 */
					bool HasKeyUsage(KeyUsage usage) const noexcept;

					/**
					 * @brief Returns the subject public key.
					 * @return Public-only keypair (elliptic-curve keys load as @ref KeyPair::Type::ECC), or null when unsupported.
					 */
					KeyPair::Generic::PointerType PublicKey() const noexcept;
					/** @} */

					/**
					 * @name Verification
					 * @{
					 */
					/**
					 * @brief Checks the validity period.
					 * @param at Instant to test.
					 * @return true when notBefore <= @p at <= notAfter.
					 */
					bool IsValidAt(TimePoint at) const noexcept;

					/**
					 * @brief Checks name chaining and the signature against @p issuer.
					 * @param issuer Candidate issuer.
					 * @return true when the issuer name matches the subject of @p issuer
					 *         and its key verifies this certificate's signature.
					 * @note Does not check validity, CA flags or key usage; use @ref VerifyChain.
					 */
					bool IsIssuedBy(const Certificate& issuer) const noexcept;

					/**
					 * @brief Verifies this certificate up to a trusted anchor.
					 * @param intermediates Untrusted CAs ordered from the issuer of this certificate upwards.
					 * @param anchor Trusted CA that issued the last intermediate (or this certificate).
					 * @param at Instant used for validity periods.
					 * @return true when every link verifies.
					 *
					 * Every certificate, the anchor included, must be valid at @p at and carry
					 * no unrecognized critical extension. Every issuer, the anchor included, must
					 * be a version 3 CA allowed to sign certificates whose path length
					 * constraint covers the CAs below it. The anchor's own signature is not
					 * checked. This certificate's key usage is left to the caller.
					 */
					bool VerifyChain(std::span<const Certificate> intermediates, const Certificate& anchor,
						TimePoint at) const noexcept;

					/**
					 * @brief Verifies this certificate up to a trusted anchor at the current time.
					 * @param intermediates Untrusted CAs ordered from the issuer of this certificate upwards.
					 * @param anchor Trusted CA that issued the last intermediate (or this certificate).
					 * @return true when every link verifies.
					 */
					bool VerifyChain(std::span<const Certificate> intermediates, const Certificate& anchor) const noexcept;
					/** @} */

				private:
					/**
					 * @struct Range
					 * @brief Byte range inside @ref m_der.
					 */
					struct Range {
						std::size_t offset = 0;	///< First byte.
						std::size_t length = 0;	///< Byte count.
					};

					Safe::Binary m_der;						///< Original DER encoding.
					Range m_tbs;							///< Full TBSCertificate element.
					Range m_signature_algorithm;			///< Full outer AlgorithmIdentifier element.
					Range m_signature;						///< Signature bits without the unused-bits byte.
					Range m_serial;							///< Serial INTEGER contents.
					Range m_issuer;							///< Full issuer Name element.
					Range m_subject;						///< Full subject Name element.
					Range m_public_key;						///< Full SubjectPublicKeyInfo element.
					std::int64_t m_not_before = 0;			///< notBefore, seconds since the epoch.
					std::int64_t m_not_after = 0;			///< notAfter, seconds since the epoch.
					std::uint32_t m_path_length = 0;		///< Path length constraint when present.
					std::uint16_t m_key_usage = 0;			///< keyUsage bits when present.
					std::uint8_t m_version = 1;				///< Certificate version.
					bool m_ca = false;						///< basicConstraints cA.
					bool m_has_path_length = false;			///< Path length constraint present.
					bool m_has_key_usage = false;			///< keyUsage present.
					bool m_unknown_critical = false;		///< Unrecognized critical extension present.


					/**
					 * @brief Returns a view of @p range.
					 * @param range Range inside @ref m_der.
					 * @return Borrowed bytes.
					 */
					std::span<const std::byte> View(const Range& range) const noexcept;
			};
		}
	}
}

STORMBYTE_DECLARE_MAYBE_SAFE(StormByte::Crypto::X509::Certificate);

namespace StormByte::Crypto::X509 {
	/**
	 * @brief Loads one certificate from DER or PEM.
	 * @param data DER bytes, or PEM text whose first CERTIFICATE block is used.
	 * @return Parsed certificate, or empty on malformed input.
	 */
	STORMBYTE_CRYPTO_PUBLIC Safe::Optional<Certificate> Load(std::span<const std::byte> data) noexcept;

	/**
	 * @brief Loads every CERTIFICATE block of a PEM bundle, in order.
	 * @param data PEM text, or a single DER certificate.
	 * @return Parsed certificates; empty when there are none or any block is malformed.
	 */
	STORMBYTE_CRYPTO_PUBLIC Safe::Vector<Certificate> LoadAll(std::span<const std::byte> data) noexcept;
}
