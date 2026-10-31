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
#include <StormByte/expected.hxx>
#include <StormByte/safe/binary.hxx>
#include <StormByte/safe/optional.hxx>
#include <StormByte/safe/string.hxx>
#include <StormByte/safe/vector.hxx>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

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
			 * @enum SubjectAltNameType
			 * @brief Supported subjectAltName general name kinds (RFC 5280 §4.2.1.6).
			 */
			enum class SubjectAltNameType {
				DNS,	///< dNSName, an ASCII host name or a leftmost-label wildcard pattern.
				IP		///< iPAddress, 4 (IPv4) or 16 (IPv6) network-order bytes.
			};

			/**
			 * @enum IdentityError
			 * @brief Errors of subjectAltName extraction and expected-identity verification.
			 */
			enum class IdentityError {
				InvalidExpectedName,		///< The expected DNS name is not an acceptable ASCII host name.
				InvalidExpectedAddress,		///< The expected IP address is not exactly 4 or 16 bytes.
				MissingSubjectAltName,		///< The certificate has no subjectAltName extension.
				MalformedSubjectAltName,	///< The subjectAltName extension or one of its entries is malformed.
				NoMatch						///< The extension is well formed but no entry matches the expected identity.
			};

			/**
			 * @class SubjectAltName
			 * @brief One supported subjectAltName entry (a DNS name or an IP address).
			 * @note Conditionally DLL-safe: the value is a Safe type and all operations are defined
			 *       out of line in Crypto.
			 */
			class STORMBYTE_CRYPTO_PUBLIC SubjectAltName {
				public:
					/**
					 * @brief Empty DNS entry with no value.
					 */
					SubjectAltName() noexcept;

					/**
					 * @brief Builds an entry.
					 * @param type Kind of the entry.
					 * @param value Raw bytes: ASCII text for DNS, network-order address bytes for IP.
					 */
					SubjectAltName(SubjectAltNameType type, Safe::Binary value);

					/**
					 * @brief Copy constructor.
					 * @param other Entry to copy.
					 */
					SubjectAltName(const SubjectAltName& other);

					/**
					 * @brief Move constructor.
					 * @param other Entry to move.
					 */
					SubjectAltName(SubjectAltName&& other) noexcept;

					/**
					 * @brief Destructor.
					 */
					~SubjectAltName() noexcept;

					/**
					 * @brief Copy assignment.
					 * @param other Entry to copy.
					 * @return Reference to this entry.
					 */
					SubjectAltName& operator=(const SubjectAltName& other);

					/**
					 * @brief Move assignment.
					 * @param other Entry to move.
					 * @return Reference to this entry.
					 */
					SubjectAltName& operator=(SubjectAltName&& other) noexcept;

					/**
					 * @brief Returns the kind of the entry.
					 * @return DNS or IP.
					 */
					SubjectAltNameType Type() const noexcept;

					/**
					 * @brief Returns the raw value.
					 * @return Certificate bytes: DNS names keep their original case and wildcard,
					 *         IP addresses are 4 or 16 bytes.
					 */
					const Safe::Binary& Value() const noexcept;

				private:
					SubjectAltNameType m_type;	///< Kind of the entry.
					Safe::Binary m_value;		///< Raw entry value.
			};

		}
	}
}

STORMBYTE_DECLARE_MAYBE_SAFE(StormByte::Crypto::X509::SubjectAltName);

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
			 * @brief Supported subjectAltName entries, or a typed extraction error.
			 */
			using ExpectedSubjectAltNames = StormByte::Expected<Safe::Vector<SubjectAltName>, IdentityError>;

			/**
			 * @brief Success when the expected identity is present, or a typed error.
			 */
			using ExpectedIdentity = StormByte::Expected<void, IdentityError>;

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

					/**
					 * @name Identity
					 * @{
					 */
					/**
					 * @brief Extracts the supported entries of the subjectAltName extension.
					 * @return dNSName and iPAddress entries in certificate order, or an error.
					 * @throws StormByte::Safe::AllocationError Entry or error storage cannot be allocated.
					 *
					 * The whole extension is validated strictly: a non-empty DER SEQUENCE of
					 * general names with known context tags, non-empty contents, dNSName values
					 * that are valid ASCII host names (labels of letters, digits and inner
					 * hyphens, at most 63 bytes each, 253 in total, no trailing dot, final label
					 * not all digits) or a wildcard whose complete leftmost label is `*` over at
					 * least two further labels, and iPAddress values of exactly 4 or 16 bytes.
					 * Other well-formed general-name kinds (email, URI, directory, other) are
					 * skipped. Any malformed entry fails the whole call with
					 * @ref IdentityError::MalformedSubjectAltName; an absent extension yields
					 * @ref IdentityError::MissingSubjectAltName. The subject common name is never
					 * consulted. Duplicate extensions are already rejected by @ref Parse.
					 */
					ExpectedSubjectAltNames SubjectAltNames() const;

					/**
					 * @brief Checks that the certificate asserts an expected DNS host name.
					 * @param expected ASCII host name supplied by the caller (for example from the
					 *        connection URL), never taken from this certificate. Internationalized
					 *        names must already be ASCII A-labels; no IDNA conversion is done.
					 * @return Success when a dNSName entry matches, or an error.
					 * @throws StormByte::Safe::AllocationError Entry or error storage cannot be allocated.
					 *
					 * @p expected is normalized by dropping exactly one trailing dot and is
					 * rejected with @ref IdentityError::InvalidExpectedName when empty, malformed,
					 * containing NUL or non-hostname bytes, a wildcard, or ending in an all-digit
					 * label (IP literals must use @ref VerifyIPAddress). Matching is a full,
					 * ASCII case-insensitive comparison against dNSName entries only. A wildcard
					 * entry matches exactly one non-empty leftmost label (`*.example.com` matches
					 * `www.example.com`, not `example.com` or `a.b.example.com`). The common name
					 * is never a fallback and DNS names never match iPAddress entries. The
					 * extension is validated as in @ref SubjectAltNames before any matching, so a
					 * malformed entry fails even when another entry matches; no matching entry
					 * yields @ref IdentityError::NoMatch.
					 * @note This only compares names. It does not verify a chain, validity,
					 *       key usage or extended key usage and does not authenticate a peer.
					 */
					ExpectedIdentity VerifyDNSName(std::string_view expected) const;

					/**
					 * @brief Checks that the certificate asserts an expected IP address.
					 * @param expected Binary address supplied by the caller: 4 bytes (IPv4) or
					 *        16 bytes (IPv6) in network order; any other size is rejected with
					 *        @ref IdentityError::InvalidExpectedAddress.
					 * @return Success when an iPAddress entry has exactly the same bytes, or an error.
					 * @throws StormByte::Safe::AllocationError Entry or error storage cannot be allocated.
					 *
					 * Comparison is exact over the bytes; there is no textual parsing, no DNS
					 * fallback, no wildcard and no IPv4-mapped IPv6 equivalence. Extension
					 * validation and errors follow @ref VerifyDNSName.
					 * @note This only compares addresses; it is not chain or peer authentication.
					 */
					ExpectedIdentity VerifyIPAddress(std::span<const std::byte> expected) const;
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
					Range m_subject_alt_name;				///< subjectAltName extnValue contents (the GeneralNames SEQUENCE).
					std::int64_t m_not_before = 0;			///< notBefore, seconds since the epoch.
					std::int64_t m_not_after = 0;			///< notAfter, seconds since the epoch.
					std::uint32_t m_path_length = 0;		///< Path length constraint when present.
					std::uint16_t m_key_usage = 0;			///< keyUsage bits when present.
					std::uint8_t m_version = 1;				///< Certificate version.
					bool m_ca = false;						///< basicConstraints cA.
					bool m_has_path_length = false;			///< Path length constraint present.
					bool m_has_key_usage = false;			///< keyUsage present.
					bool m_unknown_critical = false;		///< Unrecognized critical extension present.
					bool m_has_subject_alt_name = false;	///< subjectAltName present.


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
