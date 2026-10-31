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

#include <StormByte/crypto/x509/revocation.hxx>

#include <sha.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <limits>

namespace StormByte::Crypto::X509 {
	namespace {
		using Bytes = std::span<const std::byte>;

		constexpr std::uint8_t Sequence = 0x30;
		constexpr std::uint8_t Set = 0x31;
		constexpr std::uint8_t Integer = 0x02;
		constexpr std::uint8_t BitString = 0x03;
		constexpr std::uint8_t OctetString = 0x04;
		constexpr std::uint8_t Null = 0x05;
		constexpr std::uint8_t Oid = 0x06;
		constexpr std::uint8_t Boolean = 0x01;
		constexpr std::uint8_t Enumerated = 0x0A;
		constexpr std::uint8_t UtcTime = 0x17;
		constexpr std::uint8_t GeneralizedTime = 0x18;
		constexpr std::uint8_t Version = 0xA0;
		constexpr std::uint8_t Extensions = 0xA3;
		constexpr std::uint8_t OcspResponseBytes = 0xA0;
		constexpr std::uint8_t ResponderByName = 0xA1;
		constexpr std::uint8_t ResponderByKey = 0x82;
		constexpr std::uint8_t OcspRevoked = 0xA1;
		constexpr std::uint8_t OcspUnknown = 0x82;
		constexpr std::uint8_t ExplicitNextUpdate = 0xA0;
		constexpr std::uint8_t ExplicitSingleExtensions = 0xA1;
		constexpr std::uint8_t ExplicitResponseExtensions = 0xA1;
		constexpr std::uint8_t ExplicitCertificates = 0xA0;
		constexpr std::uint8_t ExplicitCrlExtensions = 0xA0;

		constexpr std::uint8_t OidSha1[] = {0x2B, 0x0E, 0x03, 0x02, 0x1A};
		constexpr std::uint8_t OidSha256[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
		constexpr std::uint8_t OidSha384[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02};
		constexpr std::uint8_t OidSha512[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03};
		constexpr std::uint8_t OidBasicOcsp[] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01};
		constexpr std::uint8_t OidOcspSigning[] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09};
		constexpr std::uint8_t OidOcspNoCheck[] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x05};
		constexpr std::uint8_t OidSubjectKeyId[] = {0x55, 0x1D, 0x0E};
		constexpr std::uint8_t OidAuthorityKeyId[] = {0x55, 0x1D, 0x23};
		constexpr std::uint8_t OidCrlNumber[] = {0x55, 0x1D, 0x14};
		constexpr std::uint8_t OidDeltaCrl[] = {0x55, 0x1D, 0x1B};
		constexpr std::uint8_t OidIssuingDistributionPoint[] = {0x55, 0x1D, 0x1C};
		constexpr std::uint8_t OidCrlReason[] = {0x55, 0x1D, 0x15};
		constexpr std::uint8_t OidInvalidityDate[] = {0x55, 0x1D, 0x18};
		constexpr std::uint8_t OidCertificateIssuer[] = {0x55, 0x1D, 0x1D};
		constexpr std::uint8_t OidExtendedKeyUsage[] = {0x55, 0x1D, 0x25};

		/**
		 * @struct Element
		 * @brief One strict DER tag-length-value element.
		 */
		struct Element final {
			std::uint8_t tag = 0;		///< Encoded identifier.
			std::size_t start = 0;		///< Identifier offset.
			std::size_t value = 0;		///< Contents offset.
			std::size_t length = 0;		///< Contents length.

			/**
			 * @brief Returns the first byte after the element.
			 * @return Exclusive end offset.
			 */
			std::size_t End() const noexcept { return value + length; }

			/**
			 * @brief Returns the full encoded element length.
			 * @return Encoded size.
			 */
			std::size_t Size() const noexcept { return End() - start; }
		};

		/**
		 * @class Reader
		 * @brief Bounds-checked strict DER reader.
		 */
		class Reader final {
			public:
				/**
				 * @brief Reads a complete byte range.
				 * @param data DER buffer.
				 * @param begin First byte.
				 * @param end Exclusive bound.
				 */
				Reader(Bytes data, std::size_t begin, std::size_t end) noexcept:
					m_data(data), m_position(begin), m_end(end) {}

				/**
				 * @brief Reads the contents of a parent element.
				 * @param data DER buffer.
				 * @param parent Parent element.
				 */
				Reader(Bytes data, const Element& parent) noexcept:
					Reader(data, parent.value, parent.End()) {}

				/**
				 * @brief Tells whether the bounded range was consumed.
				 * @return true at the exact end.
				 */
				bool AtEnd() const noexcept { return m_position == m_end; }

				/**
				 * @brief Checks the next tag without consuming it.
				 * @param tag Expected tag.
				 * @return true when it is present.
				 */
				bool Peek(std::uint8_t tag) const noexcept {
					return m_position < m_end && Byte(m_position) == tag;
				}

				/**
				 * @brief Reads the next DER element.
				 * @param out Receives the element.
				 * @return false on malformed or non-minimal DER.
				 */
				bool Next(Element& out) noexcept {
					if (m_position > m_end || m_end - m_position < 2)
						return false;
					out.start = m_position;
					out.tag = Byte(m_position++);
					if ((out.tag & 0x1F) == 0x1F)
						return false;
					const std::uint8_t first = Byte(m_position++);
					std::size_t length = 0;
					if (first < 0x80)
						length = first;
					else {
						const unsigned count = first & 0x7F;
						if (count == 0 || count > sizeof(std::uint32_t) || m_end - m_position < count
							|| Byte(m_position) == 0)
							return false;
						for (unsigned i = 0; i < count; ++i)
							length = (length << 8) | Byte(m_position++);
						if (length < 0x80)
							return false;
					}
					if (length > m_end - m_position)
						return false;
					out.value = m_position;
					out.length = length;
					m_position += length;
					return true;
				}

				/**
				 * @brief Reads the next element with the required tag.
				 * @param tag Required tag.
				 * @param out Receives the element.
				 * @return false when the element is absent, malformed or differently tagged.
				 */
				bool Next(std::uint8_t tag, Element& out) noexcept {
					return Next(out) && out.tag == tag;
				}

			private:
				Bytes m_data;			///< Borrowed DER bytes.
				std::size_t m_position;		///< Next unread offset.
				std::size_t m_end;		///< Exclusive bound.

				/**
				 * @brief Reads an already bounds-checked byte.
				 * @param position Byte offset.
				 * @return Unsigned octet.
				 */
				std::uint8_t Byte(std::size_t position) const noexcept {
					return std::to_integer<std::uint8_t>(m_data[position]);
				}
		};

		/**
		 * @brief Returns an element's full DER encoding.
		 * @param data Parent buffer.
		 * @param element Element range.
		 * @return Borrowed encoded bytes.
		 */
		Bytes Encoded(Bytes data, const Element& element) noexcept {
			return data.subspan(element.start, element.Size());
		}

		/**
		 * @brief Returns an element's content bytes.
		 * @param data Parent buffer.
		 * @param element Element range.
		 * @return Borrowed contents.
		 */
		Bytes Contents(Bytes data, const Element& element) noexcept {
			return data.subspan(element.value, element.length);
		}

		/**
		 * @brief Compares DER OID content with a constant.
		 * @tparam N Constant length.
		 * @param value Candidate OID content.
		 * @param expected Expected content bytes.
		 * @return true on exact match.
		 */
		template<std::size_t N>
		bool IsOid(Bytes value, const std::uint8_t (&expected)[N]) noexcept {
			return value.size() == N && std::equal(value.begin(), value.end(), expected,
				[](std::byte a, std::uint8_t b) { return std::to_integer<std::uint8_t>(a) == b; });
		}

		/**
		 * @brief Views a constant OID byte array as DER octets.
		 * @tparam N Array length.
		 * @param value OID octets.
		 * @return Borrowed byte view.
		 */
		template<std::size_t N>
		Bytes OidBytes(const std::uint8_t (&value)[N]) noexcept {
			return {reinterpret_cast<const std::byte*>(value), N};
		}

		/**
		 * @brief Parses a non-negative, minimally encoded DER INTEGER.
		 * @param value INTEGER content bytes.
		 * @return true when it is canonical and non-negative.
		 */
		bool ValidPositiveInteger(Bytes value) noexcept {
			return !value.empty() && (std::to_integer<unsigned>(value[0]) & 0x80) == 0
				&& !(value.size() > 1 && value[0] == std::byte{0}
					&& (std::to_integer<unsigned>(value[1]) & 0x80) == 0);
		}

		/**
		 * @brief Parses an ASN.1 UTC or Generalized time in canonical UTC form.
		 * @param data DER buffer.
		 * @param element Time element.
		 * @param output Receives epoch seconds.
		 * @return false for malformed calendar values or unsupported time syntax.
		 */
		bool ReadTime(Bytes data, const Element& element, std::int64_t& output) noexcept {
			const Bytes value = Contents(data, element);
			const std::size_t yearDigits = element.tag == UtcTime ? 2 : element.tag == GeneralizedTime ? 4 : 0;
			if (yearDigits == 0 || value.size() != yearDigits + 11
				|| std::to_integer<char>(value.back()) != 'Z')
				return false;
			std::size_t offset = 0;
			bool digitsValid = true;
			const auto read = [&](std::size_t count) {
				int result = 0;
				for (std::size_t i = 0; i < count; ++i) {
					const char digit = std::to_integer<char>(value[offset++]);
					digitsValid &= digit >= '0' && digit <= '9';
					result = result * 10 + digit - '0';
				}
				return result;
			};
			int year = read(yearDigits);
			if (yearDigits == 2)
				year += year >= 50 ? 1900 : 2000;
			const int month = read(2);
			const int day = read(2);
			const int hour = read(2);
			const int minute = read(2);
			const int second = read(2);
			const std::chrono::year_month_day date{
				std::chrono::year{year}, std::chrono::month{static_cast<unsigned>(month)},
				std::chrono::day{static_cast<unsigned>(day)}};
			if (!digitsValid || !date.ok() || hour > 23 || minute > 59 || second > 59)
				return false;
			output = std::chrono::duration_cast<std::chrono::seconds>(
				std::chrono::sys_days{date}.time_since_epoch()).count()
				+ hour * 3600LL + minute * 60LL + second;
			return true;
		}

		/**
		 * @brief Computes a supported digest over bytes.
		 * @param oid Digest algorithm OID.
		 * @param input Bytes to hash.
		 * @param output Receives the digest.
		 * @return true when the digest algorithm is supported and output size matches.
		 */
		bool Digest(Bytes oid, Bytes input, std::span<std::byte> output) {
			if (IsOid(oid, OidSha1)) {
				CryptoPP::SHA1 hash;
				if (output.size() != hash.DigestSize())
					return false;
				hash.CalculateDigest(reinterpret_cast<CryptoPP::byte*>(output.data()),
					reinterpret_cast<const CryptoPP::byte*>(input.data()), input.size());
				return true;
			}
			if (IsOid(oid, OidSha256)) {
				CryptoPP::SHA256 hash;
				if (output.size() != hash.DigestSize())
					return false;
				hash.CalculateDigest(reinterpret_cast<CryptoPP::byte*>(output.data()),
					reinterpret_cast<const CryptoPP::byte*>(input.data()), input.size());
				return true;
			}
			if (IsOid(oid, OidSha384)) {
				CryptoPP::SHA384 hash;
				if (output.size() != hash.DigestSize())
					return false;
				hash.CalculateDigest(reinterpret_cast<CryptoPP::byte*>(output.data()),
					reinterpret_cast<const CryptoPP::byte*>(input.data()), input.size());
				return true;
			}
			if (IsOid(oid, OidSha512)) {
				CryptoPP::SHA512 hash;
				if (output.size() != hash.DigestSize())
					return false;
				hash.CalculateDigest(reinterpret_cast<CryptoPP::byte*>(output.data()),
					reinterpret_cast<const CryptoPP::byte*>(input.data()), input.size());
				return true;
			}
			return false;
		}

		/**
		 * @brief Parses and validates a DER signature BIT STRING.
		 * @param data Source buffer.
		 * @param element Signature bit string.
		 * @param signature Receives signature bytes without unused-bit count.
		 * @return true for byte-aligned non-empty signature data.
		 */
		bool SignatureBits(Bytes data, const Element& element, Bytes& signature) noexcept {
			const Bytes bits = Contents(data, element);
			if (element.tag != BitString || bits.size() < 2 || bits[0] != std::byte{0})
				return false;
			signature = bits.subspan(1);
			return true;
		}

		/**
		 * @brief Parses a supported AlgorithmIdentifier without interpreting its signature OID.
		 * @param data DER buffer.
		 * @param element AlgorithmIdentifier sequence.
		 * @param oid Receives algorithm OID content.
		 * @return true for one OID and optional NULL parameters.
		 */
		bool ReadAlgorithm(Bytes data, const Element& element, Bytes& oid) noexcept {
			Reader reader(data, element);
			Element id;
			if (!reader.Next(Oid, id))
				return false;
			oid = Contents(data, id);
			if (!reader.AtEnd()) {
				Element parameters;
				if (!reader.Next(Null, parameters) || parameters.length != 0)
					return false;
			}
			return reader.AtEnd();
		}

		/**
		 * @brief Parses an extension list, rejecting duplicate OIDs.
		 * @param data Complete DER buffer.
		 * @param sequence Extensions SEQUENCE.
		 * @param callback Handles each OID, critical bit and OCTET STRING value.
		 * @return false for malformed DER, duplicates or callback rejection.
		 */
		template<typename Callback>
		bool ReadExtensions(Bytes data, const Element& sequence, Callback&& callback) {
			Reader extensions(data, sequence);
			std::array<Bytes, 64> seen{};
			std::size_t count = 0;
			while (!extensions.AtEnd()) {
				Element extension;
				if (!extensions.Next(Sequence, extension))
					return false;
				Reader fields(data, extension);
				Element oidElement, valueElement;
				if (!fields.Next(Oid, oidElement))
					return false;
				const Bytes oid = Contents(data, oidElement);
				if (count == seen.size()
					|| std::ranges::any_of(std::span(seen.data(), count), [oid](Bytes prior) {
						return std::ranges::equal(prior, oid);
					}))
					return false;
				seen[count++] = oid;
				bool critical = false;
				if (fields.Peek(Boolean)) {
					Element boolean;
					if (!fields.Next(Boolean, boolean) || boolean.length != 1
						|| (data[boolean.value] != std::byte{0}
							&& data[boolean.value] != std::byte{0xFF}))
						return false;
					if (data[boolean.value] == std::byte{0})
						return false;
					critical = data[boolean.value] == std::byte{0xFF};
				}
				if (!fields.Next(OctetString, valueElement) || !fields.AtEnd()
					|| !callback(oid, critical, Contents(data, valueElement)))
					return false;
			}
			return count != 0;
		}

		/**
		 * @brief Extracts subjectPublicKey BIT STRING content from a certificate SPKI.
		 * @param spki Full SubjectPublicKeyInfo DER.
		 * @param bits Receives the public-key bits.
		 * @return false for malformed SPKI.
		 */
		bool SubjectPublicKeyBits(Bytes spki, Bytes& bits) noexcept {
			Reader outer(spki, 0, spki.size());
			Element sequence, algorithm, keyBits;
			if (!outer.Next(Sequence, sequence) || !outer.AtEnd())
				return false;
			Reader fields(spki, sequence);
			if (!fields.Next(Sequence, algorithm) || !fields.Next(BitString, keyBits)
				|| !fields.AtEnd() || keyBits.length < 2 || spki[keyBits.value] != std::byte{0})
				return false;
			bits = Contents(spki, keyBits).subspan(1);
			return true;
		}

		/**
		 * @brief Extracts a certificate's subjectKeyIdentifier extension.
		 * @param certificate DER certificate.
		 * @param keyIdentifier Receives the identifier, empty when absent.
		 * @return false for malformed certificate extension encoding.
		 */
		bool ReadCertificateExtensions(Bytes certificate, const auto& callback) {
			Reader outer(certificate, 0, certificate.size());
			Element certificateSequence, tbs;
			if (!outer.Next(Sequence, certificateSequence) || !outer.AtEnd())
				return false;
			Reader certificateFields(certificate, certificateSequence);
			Element signatureAlgorithm, signature;
			if (!certificateFields.Next(Sequence, tbs) || !certificateFields.Next(Sequence, signatureAlgorithm)
				|| !certificateFields.Next(BitString, signature) || !certificateFields.AtEnd())
				return false;
			Reader fields(certificate, tbs);
			Element element;
			if (fields.Peek(Version) && !fields.Next(element))
				return false;
			for (unsigned index = 0; index < 6; ++index)
				if (!fields.Next(element))
					return false;
			for (const std::uint8_t tag : {std::uint8_t{0x81}, std::uint8_t{0x82}})
				if (fields.Peek(tag) && !fields.Next(element))
					return false;
			if (fields.AtEnd())
				return true;
			Element wrapper, extensions;
			if (!fields.Next(Extensions, wrapper) || !fields.AtEnd())
				return false;
			Reader wrapped(certificate, wrapper);
			if (!wrapped.Next(Sequence, extensions) || !wrapped.AtEnd())
				return false;
			return ReadExtensions(certificate, extensions, callback);
		}

		/**
		 * @brief Extracts a certificate subjectKeyIdentifier.
		 * @param certificate DER certificate.
		 * @param keyIdentifier Receives the identifier, empty when absent.
		 * @return false for malformed extension encoding.
		 */
		bool ReadSubjectKeyIdentifier(Bytes certificate, Bytes& keyIdentifier) {
			bool found = false;
			return ReadCertificateExtensions(certificate, [&](Bytes oid, bool, Bytes value) {
				if (!IsOid(oid, OidSubjectKeyId))
					return true;
				Reader ski(value, 0, value.size());
				Element octets;
				if (!ski.Next(OctetString, octets) || !ski.AtEnd() || octets.length == 0)
					return false;
				keyIdentifier = Contents(value, octets);
				found = true;
				return true;
			}) && (found || keyIdentifier.empty());
		}

		/**
		 * @brief Requires a correctly encoded, non-critical OCSP no-check extension.
		 * @param certificate Delegated OCSP responder certificate.
		 * @return true only when the extension is present and DER NULL.
		 */
		bool HasOcspNoCheck(Bytes certificate) {
			bool found = false;
			const bool valid = ReadCertificateExtensions(certificate, [&](Bytes oid, bool critical, Bytes value) {
				if (!IsOid(oid, OidOcspNoCheck))
					return true;
				constexpr std::byte nullDer[] = {std::byte{Null}, std::byte{0}};
				found = !critical && std::ranges::equal(value, nullDer);
				return found;
			});
			return valid && found;
		}

		struct ParsedStatus final {
			RevocationStatus status = RevocationStatus::Good;
			std::int64_t thisUpdate = 0;
			std::int64_t nextUpdate = 0;
			std::int64_t producedAt = 0;
			Bytes issuerName;
			Bytes signatureAlgorithm;
			Bytes signedData;
			Bytes signature;
			Bytes responderId;
			std::uint8_t responderIdTag = 0;
			std::array<Bytes, 4> certificates{};
			std::size_t certificateCount = 0;
		};

		/**
		 * @brief Parses signed CRL structure and finds the target serial status.
		 * @param der DER CertificateList.
		 * @param serial Target certificate serial INTEGER contents.
		 * @param status Receives signed CRL data and target status.
		 * @return Revocation validation error, or no error when parsing succeeds.
		 */
		RevocationError ParseCrl(Bytes der, Bytes serial, Bytes issuerKeyIdentifier,
			std::int64_t at, ParsedStatus& status) {
			Reader outer(der, 0, der.size());
			Element crl, tbs, outerAlgorithm, signatureElement;
			if (!outer.Next(Sequence, crl) || !outer.AtEnd())
				return RevocationError::MalformedEvidence;
			Reader crlFields(der, crl);
			if (!crlFields.Next(Sequence, tbs) || !crlFields.Next(Sequence, outerAlgorithm)
				|| !crlFields.Next(BitString, signatureElement) || !crlFields.AtEnd())
				return RevocationError::MalformedEvidence;
			Bytes signature;
			if (!SignatureBits(der, signatureElement, signature))
				return RevocationError::MalformedEvidence;
			status.signedData = Encoded(der, tbs);
			status.signatureAlgorithm = Encoded(der, outerAlgorithm);
			status.signature = signature;
			Reader fields(der, tbs);
			Element element;
			bool versionTwo = false;
			if (fields.Peek(Integer)) {
				if (!fields.Next(Integer, element) || !ValidPositiveInteger(Contents(der, element))
					|| Contents(der, element).size() != 1 || Contents(der, element)[0] != std::byte{1})
					return RevocationError::UnsupportedFeature;
				versionTwo = true;
			}
			Element tbsAlgorithm, issuerName, thisUpdateElement;
			if (!fields.Next(Sequence, tbsAlgorithm) || !fields.Next(Sequence, issuerName)
				|| !fields.Next(thisUpdateElement))
				return RevocationError::MalformedEvidence;
			if (!std::ranges::equal(Encoded(der, tbsAlgorithm), Encoded(der, outerAlgorithm)))
				return RevocationError::MalformedEvidence;
			status.issuerName = Encoded(der, issuerName);
			if (!ReadTime(der, thisUpdateElement, status.thisUpdate))
				return RevocationError::MalformedEvidence;
			Element nextUpdateElement;
			if (!fields.Next(nextUpdateElement) || !ReadTime(der, nextUpdateElement, status.nextUpdate))
				return RevocationError::MissingNextUpdate;
			if (status.nextUpdate < status.thisUpdate)
				return RevocationError::MalformedEvidence;
			if (fields.Peek(Sequence)) {
				Element revokedCertificates;
				if (!fields.Next(Sequence, revokedCertificates))
					return RevocationError::MalformedEvidence;
				Reader revoked(der, revokedCertificates);
				bool matchedSerial = false;
				while (!revoked.AtEnd()) {
					Element entry;
					if (!revoked.Next(Sequence, entry))
						return RevocationError::MalformedEvidence;
					Reader entryFields(der, entry);
					Element serialElement, dateElement;
					if (!entryFields.Next(Integer, serialElement)
						|| !ValidPositiveInteger(Contents(der, serialElement))
						|| !entryFields.Next(dateElement))
						return RevocationError::MalformedEvidence;
					std::int64_t revokedAt = 0;
					if (!ReadTime(der, dateElement, revokedAt))
						return RevocationError::MalformedEvidence;
					const bool matches = std::ranges::equal(Contents(der, serialElement), serial);
					if (entryFields.Peek(Sequence)) {
						Element entryExtensions;
						if (!versionTwo || !entryFields.Next(Sequence, entryExtensions)
							|| !ReadExtensions(der, entryExtensions, [&](Bytes oid, bool critical, Bytes value) {
								if (IsOid(oid, OidCrlReason)) {
									Reader reason(value, 0, value.size());
									Element code;
									return !critical && reason.Next(Enumerated, code) && reason.AtEnd()
										&& code.length == 1 && code.value < value.size()
										&& std::to_integer<std::uint8_t>(value[code.value]) <= 10
										&& value[code.value] != std::byte{8};
								}
								if (IsOid(oid, OidInvalidityDate)) {
									Reader invalidity(value, 0, value.size());
									Element time;
									std::int64_t ignored = 0;
									return !critical && invalidity.Next(GeneralizedTime, time) && invalidity.AtEnd()
										&& ReadTime(value, time, ignored);
								}
								return false;
							}))
							return RevocationError::UnsupportedFeature;
					}
					if (!entryFields.AtEnd())
						return RevocationError::MalformedEvidence;
					if (matches) {
						if (matchedSerial)
							return RevocationError::MalformedEvidence;
						matchedSerial = true;
						if (revokedAt <= at)
							status.status = RevocationStatus::Revoked;
					}
				}
			}
			if (fields.Peek(ExplicitCrlExtensions)) {
				Element wrapper, crlExtensions;
				if (!versionTwo || !fields.Next(ExplicitCrlExtensions, wrapper))
					return RevocationError::MalformedEvidence;
				Reader wrapped(der, wrapper);
				if (!wrapped.Next(Sequence, crlExtensions) || !wrapped.AtEnd()
					|| !ReadExtensions(der, crlExtensions, [&](Bytes oid, bool critical, Bytes value) {
						if (IsOid(oid, OidAuthorityKeyId)) {
							Reader authority(value, 0, value.size());
							Element sequence;
							if (!authority.Next(Sequence, sequence) || !authority.AtEnd())
								return false;
							Reader fields(value, sequence);
							Element item;
							bool foundKeyId = false;
							while (!fields.AtEnd()) {
								if (!fields.Next(item))
									return false;
								if (item.tag != 0x80 || foundKeyId || issuerKeyIdentifier.empty()
									|| !std::ranges::equal(Contents(value, item), issuerKeyIdentifier))
									return false;
								foundKeyId = true;
							}
							return !critical && foundKeyId;
						}
						if (IsOid(oid, OidCrlNumber)) {
							Reader number(value, 0, value.size());
							Element integer;
							return !critical && number.Next(Integer, integer) && number.AtEnd()
								&& ValidPositiveInteger(Contents(value, integer));
						}
						return false;
					}))
					return RevocationError::UnsupportedFeature;
			}
			if (!fields.AtEnd())
				return RevocationError::UnsupportedFeature;
			return RevocationError::InvalidRequest;
		}

		/**
		 * @brief Parses OCSP CertID and response status for the target.
		 * @param data BasicOCSPResponse DER.
		 * @param targetSerial Target serial INTEGER contents.
		 * @param issuerSubject Issuer subject Name DER.
		 * @param issuerKeyBits Issuer subjectPublicKey BIT STRING contents.
		 * @param status Receives response data and target status.
		 * @return Typed parsing or matching error.
		 */
		RevocationError ParseOcsp(Bytes data, Bytes targetSerial, Bytes issuerSubject,
			Bytes issuerKeyBits, std::int64_t at, ParsedStatus& status) {
			Reader outer(data, 0, data.size());
			Element basic, responseData, signatureAlgorithm, signatureElement;
			if (!outer.Next(Sequence, basic) || !outer.AtEnd())
				return RevocationError::MalformedEvidence;
			Reader basicFields(data, basic);
			if (!basicFields.Next(Sequence, responseData) || !basicFields.Next(Sequence, signatureAlgorithm)
				|| !basicFields.Next(BitString, signatureElement))
				return RevocationError::MalformedEvidence;
			if (!SignatureBits(data, signatureElement, status.signature))
				return RevocationError::MalformedEvidence;
			status.signedData = Encoded(data, responseData);
			status.signatureAlgorithm = Encoded(data, signatureAlgorithm);
			if (!basicFields.AtEnd()) {
				Element certificatesWrapper;
				if (!basicFields.Next(ExplicitCertificates, certificatesWrapper) || !basicFields.AtEnd())
					return RevocationError::UnsupportedFeature;
				Reader wrapped(data, certificatesWrapper);
				Element certificates;
				if (!wrapped.Next(Sequence, certificates) || !wrapped.AtEnd())
					return RevocationError::MalformedEvidence;
				Reader entries(data, certificates);
				while (!entries.AtEnd()) {
					Element certificate;
					if (status.certificateCount == status.certificates.size()
						|| !entries.Next(Sequence, certificate))
						return RevocationError::UnsupportedFeature;
					status.certificates[status.certificateCount++] = Encoded(data, certificate);
				}
			}
			Reader response(data, responseData);
			Element field;
			if (response.Peek(Version)) {
				Element wrapper, version;
				if (!response.Next(Version, wrapper))
					return RevocationError::MalformedEvidence;
				Reader wrapped(data, wrapper);
				if (!wrapped.Next(Integer, version) || !wrapped.AtEnd()
					|| Contents(data, version).size() != 1 || Contents(data, version)[0] != std::byte{0})
					return RevocationError::UnsupportedFeature;
			}
			Element responder;
			if (!response.Next(responder) || (responder.tag != ResponderByName && responder.tag != ResponderByKey)
				|| !response.Next(GeneralizedTime, field) || !ReadTime(data, field, status.producedAt))
				return RevocationError::MalformedEvidence;
			status.responderIdTag = responder.tag;
			status.responderId = Contents(data, responder);
			Element responses;
			if (!response.Next(Sequence, responses))
				return RevocationError::MalformedEvidence;
			Reader singles(data, responses);
			std::size_t matched = 0;
			while (!singles.AtEnd()) {
				Element single;
				if (!singles.Next(Sequence, single))
					return RevocationError::MalformedEvidence;
				Reader fields(data, single);
				Element certId, certStatus, thisUpdate;
				if (!fields.Next(Sequence, certId) || !fields.Next(certStatus) || !fields.Next(thisUpdate))
					return RevocationError::MalformedEvidence;
				Reader id(data, certId);
				Element hashAlgorithm, issuerNameHash, issuerKeyHash, serialElement, oidElement;
				if (!id.Next(Sequence, hashAlgorithm))
					return RevocationError::MalformedEvidence;
				Reader hashId(data, hashAlgorithm);
				if (!hashId.Next(Oid, oidElement))
					return RevocationError::MalformedEvidence;
				const Bytes hashOid = Contents(data, oidElement);
				if (!hashId.AtEnd()) {
					Element nullElement;
					if (!hashId.Next(Null, nullElement) || nullElement.length != 0 || !hashId.AtEnd())
						return RevocationError::MalformedEvidence;
				}
				if (!id.Next(OctetString, issuerNameHash) || !id.Next(OctetString, issuerKeyHash)
					|| !id.Next(Integer, serialElement) || !id.AtEnd()
					|| !ValidPositiveInteger(Contents(data, serialElement)))
					return RevocationError::MalformedEvidence;
				const Bytes candidateSerial = Contents(data, serialElement);
				std::int64_t update = 0;
				if (!ReadTime(data, thisUpdate, update))
					return RevocationError::MalformedEvidence;
				std::int64_t nextUpdate = 0;
				bool hasNextUpdate = false;
				if (fields.Peek(ExplicitNextUpdate)) {
					Element nextWrapper, next;
					if (!fields.Next(ExplicitNextUpdate, nextWrapper))
						return RevocationError::MalformedEvidence;
					Reader wrappedNext(data, nextWrapper);
					if (!wrappedNext.Next(GeneralizedTime, next) || !wrappedNext.AtEnd()
						|| !ReadTime(data, next, nextUpdate))
						return RevocationError::MalformedEvidence;
					hasNextUpdate = true;
				}
				if (std::ranges::equal(candidateSerial, targetSerial)) {
					++matched;
					std::array<std::byte, 64> digestBuffer{};
					std::size_t hashSize = Contents(data, issuerNameHash).size();
					if (hashSize != Contents(data, issuerKeyHash).size() || hashSize > digestBuffer.size())
						return RevocationError::MalformedEvidence;
					std::span<std::byte> nameHash(digestBuffer.data(), hashSize);
					if (!Digest(hashOid, issuerSubject, nameHash))
						return RevocationError::UnsupportedFeature;
					if (!std::ranges::equal(nameHash, Contents(data, issuerNameHash)))
						return RevocationError::IssuerMismatch;
					if (!Digest(hashOid, issuerKeyBits, nameHash)
						|| !std::ranges::equal(nameHash, Contents(data, issuerKeyHash)))
						return RevocationError::IssuerMismatch;
					status.thisUpdate = update;
					if (!hasNextUpdate)
						return RevocationError::MissingNextUpdate;
					status.nextUpdate = nextUpdate;
					if (certStatus.tag == 0x80 && certStatus.length == 0)
						status.status = RevocationStatus::Good;
					else if (certStatus.tag == OcspUnknown && certStatus.length == 0)
						status.status = RevocationStatus::Unknown;
					else if (certStatus.tag == OcspRevoked) {
						Reader info(data, certStatus);
						Element revocationTime;
						if (!info.Next(GeneralizedTime, revocationTime))
							return RevocationError::MalformedEvidence;
						std::int64_t revokedAt = 0;
						if (!ReadTime(data, revocationTime, revokedAt))
							return RevocationError::MalformedEvidence;
						status.status = revokedAt <= at ? RevocationStatus::Revoked
							: RevocationStatus::Good;
						if (!info.AtEnd()) {
							Element reasonWrapper, reason;
							if (!info.Next(0xA0, reasonWrapper) || !info.AtEnd())
								return RevocationError::UnsupportedFeature;
							Reader wrappedReason(data, reasonWrapper);
							if (!wrappedReason.Next(Enumerated, reason) || !wrappedReason.AtEnd()
								|| reason.length != 1 || reason.value >= data.size()
								|| std::to_integer<std::uint8_t>(data[reason.value]) > 10
								|| data[reason.value] == std::byte{8})
								return RevocationError::MalformedEvidence;
						}
					} else
						return RevocationError::MalformedEvidence;
				}
				while (!fields.AtEnd()) {
					Element optional;
					if (!fields.Next(optional))
						return RevocationError::MalformedEvidence;
					return optional.tag == ExplicitSingleExtensions
						? RevocationError::UnsupportedFeature : RevocationError::MalformedEvidence;
				}
			}
			if (matched == 0)
				return RevocationError::CertificateMismatch;
			if (matched != 1)
				return RevocationError::MalformedEvidence;
			while (!response.AtEnd()) {
				Element optional;
				if (!response.Next(optional) || optional.tag != ExplicitResponseExtensions)
					return RevocationError::UnsupportedFeature;
				return RevocationError::UnsupportedFeature;
			}
			return RevocationError::InvalidRequest;
		}
	}

	ExpectedRevocation RevocationVerifier::Verify(const Certificate& certificate, const Certificate& issuer,
		RevocationFormat format, std::span<const std::byte> der, TimePoint at) {
		const auto fail = [](RevocationError error) {
			return ExpectedRevocation(StormByte::Unexpected(error));
		};
		if (certificate.Der().empty() || issuer.Der().empty() || der.empty() || der.size() > 4 * 1024 * 1024
			|| !std::ranges::equal(certificate.View(certificate.m_issuer), issuer.View(issuer.m_subject))
			|| !issuer.IsCA() || !issuer.IsValidAt(at))
			return fail(RevocationError::InvalidRequest);

		ParsedStatus parsed;
		RevocationError parseError = RevocationError::MalformedEvidence;
		if (format == RevocationFormat::CRL) {
			if (issuer.m_has_key_usage && !issuer.HasKeyUsage(KeyUsage::CRLSign))
				return fail(RevocationError::InvalidRequest);
			Bytes issuerKeyIdentifier;
			if (!ReadSubjectKeyIdentifier(issuer.m_der.span(), issuerKeyIdentifier))
				return fail(RevocationError::InvalidRequest);
			parseError = ParseCrl(der, certificate.View(certificate.m_serial), issuerKeyIdentifier,
				at.time_since_epoch().count(), parsed);
			if (parseError != RevocationError::InvalidRequest)
				return fail(parseError);
			if (!std::ranges::equal(parsed.issuerName, issuer.View(issuer.m_subject)))
				return fail(RevocationError::IssuerMismatch);
			if (parsed.thisUpdate > at.time_since_epoch().count())
				return fail(RevocationError::NotYetValid);
			if (parsed.nextUpdate < at.time_since_epoch().count())
				return fail(RevocationError::Stale);
			if (!issuer.IsValidAt(TimePoint{std::chrono::seconds{parsed.thisUpdate}}))
				return fail(RevocationError::InvalidRequest);
			if (!issuer.VerifySignedData(parsed.signatureAlgorithm, parsed.signedData, parsed.signature))
				return fail(RevocationError::InvalidSignature);
			return parsed.status;
		}
		if (format != RevocationFormat::OCSP)
			return fail(RevocationError::UnsupportedFeature);
		Reader outer(der, 0, der.size());
		Element response, responseStatus, responseBytesWrapper;
		if (!outer.Next(Sequence, response) || !outer.AtEnd())
			return fail(RevocationError::MalformedEvidence);
		Reader fields(der, response);
		if (!fields.Next(Enumerated, responseStatus) || responseStatus.length != 1
			|| der[responseStatus.value] != std::byte{0})
			return fail(RevocationError::UnsupportedFeature);
		if (!fields.Next(OcspResponseBytes, responseBytesWrapper) || !fields.AtEnd())
			return fail(RevocationError::MalformedEvidence);
		Reader wrapped(der, responseBytesWrapper);
		Element responseBytes;
		if (!wrapped.Next(Sequence, responseBytes) || !wrapped.AtEnd())
			return fail(RevocationError::MalformedEvidence);
		Reader responseFields(der, responseBytes);
		Element responseType, responseOctets;
		if (!responseFields.Next(Oid, responseType) || !responseFields.Next(OctetString, responseOctets)
			|| !responseFields.AtEnd() || !IsOid(Contents(der, responseType), OidBasicOcsp))
			return fail(RevocationError::UnsupportedFeature);

		Bytes issuerKeyBits;
		if (!SubjectPublicKeyBits(issuer.View(issuer.m_public_key), issuerKeyBits))
			return fail(RevocationError::InvalidRequest);
		parseError = ParseOcsp(Contents(der, responseOctets), certificate.View(certificate.m_serial),
			issuer.View(issuer.m_subject), issuerKeyBits, at.time_since_epoch().count(), parsed);
		if (parseError != RevocationError::InvalidRequest)
			return fail(parseError);
		const std::int64_t now = at.time_since_epoch().count();
		if (parsed.producedAt > now)
			return fail(RevocationError::NotYetValid);
		if (parsed.thisUpdate > now || parsed.nextUpdate < now || parsed.nextUpdate < parsed.thisUpdate
			|| parsed.producedAt < parsed.thisUpdate || parsed.producedAt > parsed.nextUpdate)
			return fail(RevocationError::Stale);
		const TimePoint producedAt{std::chrono::seconds{parsed.producedAt}};
		if (!issuer.IsValidAt(producedAt))
			return fail(RevocationError::ResponderUnauthorized);

		const auto responderMatches = [&](const Certificate& responder) {
			if (parsed.responderIdTag == ResponderByName)
				return std::ranges::equal(parsed.responderId, responder.View(responder.m_subject));
			if (parsed.responderIdTag != ResponderByKey)
				return false;
			Bytes keyBits;
			if (!SubjectPublicKeyBits(responder.View(responder.m_public_key), keyBits)
				|| parsed.responderId.size() != 20)
				return false;
			std::array<std::byte, 20> digest{};
			return Digest(OidBytes(OidSha1), keyBits, digest) && std::ranges::equal(digest, parsed.responderId);
		};
		const bool directSignerAuthorized = (!issuer.m_has_key_usage
			|| issuer.HasKeyUsage(KeyUsage::DigitalSignature)) && responderMatches(issuer);
		bool signerAuthorized = directSignerAuthorized;
		bool signatureValid = directSignerAuthorized
			&& issuer.VerifySignedData(parsed.signatureAlgorithm, parsed.signedData, parsed.signature);
		for (std::size_t index = 0; !signatureValid && index < parsed.certificateCount; ++index) {
			Certificate responder;
			if ((issuer.m_has_key_usage && !issuer.HasKeyUsage(KeyUsage::KeyCertSign))
				|| !Certificate::Parse(parsed.certificates[index], responder) || responder.m_ca
				|| responder.m_unknown_critical || !responder.m_has_extended_key_usage
				|| !responder.m_has_key_usage || !responder.HasKeyUsage(KeyUsage::DigitalSignature)
				|| !responder.IsValidAt(producedAt)
				|| !HasOcspNoCheck(responder.m_der.span())
				|| !std::ranges::equal(responder.View(responder.m_issuer), issuer.View(issuer.m_subject))
				|| !issuer.VerifySignedData(responder.View(responder.m_signature_algorithm),
					responder.View(responder.m_tbs), responder.View(responder.m_signature))
				|| !responderMatches(responder))
				continue;
			Reader eku(responder.m_der.span(), responder.m_extended_key_usage.offset,
				responder.m_extended_key_usage.offset + responder.m_extended_key_usage.length);
			Element sequence;
			if (!eku.Next(Sequence, sequence) || !eku.AtEnd())
				continue;
			Reader usages(responder.m_der.span(), sequence);
			bool authorized = false;
			while (!usages.AtEnd()) {
				Element oid;
				if (!usages.Next(Oid, oid)) {
					authorized = false;
					break;
				}
				authorized |= IsOid(Contents(responder.m_der.span(), oid), OidOcspSigning);
			}
			if (authorized) {
				signerAuthorized = true;
				signatureValid = responder.VerifySignedData(parsed.signatureAlgorithm,
					parsed.signedData, parsed.signature);
			}
		}
		if (!signatureValid)
			return fail(signerAuthorized ? RevocationError::InvalidSignature
				: RevocationError::ResponderUnauthorized);
		return parsed.status;
	}
}
