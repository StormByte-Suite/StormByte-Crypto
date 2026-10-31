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

#include <StormByte/crypto/rng.hxx>
#include <StormByte/crypto/x509/certificate.hxx>
#include <StormByte/crypto/x509/tls_peer.hxx>

#include <base64.h>
#include <dsa.h>
#include <eccrypto.h>
#include <filters.h>
#include <rsa.h>
#include <sha.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <utility>

using namespace StormByte::Crypto::X509;
namespace Safe = StormByte::Safe;

namespace {
	using Bytes = std::span<const std::byte>;

	constexpr std::uint8_t TagBoolean = 0x01;
	constexpr std::uint8_t TagInteger = 0x02;
	constexpr std::uint8_t TagBitString = 0x03;
	constexpr std::uint8_t TagOctetString = 0x04;
	constexpr std::uint8_t TagNull = 0x05;
	constexpr std::uint8_t TagOid = 0x06;
	constexpr std::uint8_t TagUtcTime = 0x17;
	constexpr std::uint8_t TagGeneralizedTime = 0x18;
	constexpr std::uint8_t TagSequence = 0x30;
	constexpr std::uint8_t TagSet = 0x31;
	constexpr std::uint8_t TagVersion = 0xA0;
	constexpr std::uint8_t TagIssuerUid = 0x81;
	constexpr std::uint8_t TagSubjectUid = 0x82;
	constexpr std::uint8_t TagExtensions = 0xA3;

	constexpr std::uint8_t OidCommonName[] = {0x55, 0x04, 0x03};
	constexpr std::uint8_t OidBasicConstraints[] = {0x55, 0x1D, 0x13};
	constexpr std::uint8_t OidKeyUsage[] = {0x55, 0x1D, 0x0F};
	constexpr std::uint8_t OidExtendedKeyUsage[] = {0x55, 0x1D, 0x25};
	constexpr std::uint8_t OidServerAuth[] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01};	///< serverAuth OID contents.
	constexpr std::uint8_t OidClientAuth[] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02};	///< clientAuth OID contents.
	constexpr std::uint8_t OidSubjectKeyId[] = {0x55, 0x1D, 0x0E};
	constexpr std::uint8_t OidAuthorityKeyId[] = {0x55, 0x1D, 0x23};
	constexpr std::uint8_t OidSubjectAltName[] = {0x55, 0x1D, 0x11};
	constexpr std::uint8_t OidEcPublicKey[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
	constexpr std::uint8_t OidRsaEncryption[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};
	constexpr std::uint8_t OidEcdsaSha256[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02};
	constexpr std::uint8_t OidEcdsaSha384[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03};
	constexpr std::uint8_t OidEcdsaSha512[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04};
	constexpr std::uint8_t OidRsaSha256[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B};
	constexpr std::uint8_t OidRsaSha384[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C};
	constexpr std::uint8_t OidRsaSha512[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D};

	constexpr std::string_view PemBegin = "-----BEGIN CERTIFICATE-----";
	constexpr std::string_view PemEnd = "-----END CERTIFICATE-----";

	/**
	 * @struct Element
	 * @brief One DER tag-length-value inside a parent buffer.
	 */
	struct Element {
		std::uint8_t tag = 0;		///< Identifier octet.
		std::size_t start = 0;		///< Offset of the identifier octet.
		std::size_t value = 0;		///< Offset of the contents.
		std::size_t length = 0;		///< Contents length.

		std::size_t End() const noexcept { return value + length; }
		std::size_t Size() const noexcept { return End() - start; }
	};

	/**
	 * @class Reader
	 * @brief Sequential strict-DER reader over [position, limit) of a buffer.
	 */
	class Reader {
		public:
			Reader(Bytes data, std::size_t begin, std::size_t end) noexcept:
				m_data(data), m_position(begin), m_limit(end) {}

			Reader(Bytes data, const Element& parent) noexcept:
				Reader(data, parent.value, parent.End()) {}

			bool AtEnd() const noexcept { return m_position == m_limit; }

			bool Peek(std::uint8_t tag) const noexcept {
				return m_position < m_limit && std::to_integer<std::uint8_t>(m_data[m_position]) == tag;
			}

			/**
			 * @brief Reads the next element, which must carry @p tag.
			 */
			bool Next(std::uint8_t tag, Element& out) noexcept {
				return Next(out) && out.tag == tag;
			}

			/**
			 * @brief Reads the next element with definite, minimally encoded length.
			 */
			bool Next(Element& out) noexcept {
				if (m_limit - m_position < 2)
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
					if (count == 0 || count > sizeof(std::uint32_t) || m_limit - m_position < count)
						return false;
					if (Byte(m_position) == 0)
						return false;
					for (unsigned i = 0; i < count; ++i)
						length = (length << 8) | Byte(m_position++);
					if (length < 0x80)
						return false;
				}
				if (length > m_limit - m_position)
					return false;
				out.value = m_position;
				out.length = length;
				m_position += length;
				return true;
			}

		private:
			Bytes m_data;
			std::size_t m_position;
			std::size_t m_limit;

			std::uint8_t Byte(std::size_t index) const noexcept {
				return std::to_integer<std::uint8_t>(m_data[index]);
			}
	};

	Bytes Contents(Bytes data, const Element& element) noexcept {
		return data.subspan(element.value, element.length);
	}

	template<std::size_t N>
	bool Equals(Bytes bytes, const std::uint8_t (&expected)[N]) noexcept {
		return bytes.size() == N && std::equal(bytes.begin(), bytes.end(), expected,
			[](std::byte a, std::uint8_t b) { return std::to_integer<std::uint8_t>(a) == b; });
	}

	const CryptoPP::byte* Raw(Bytes bytes) noexcept {
		return reinterpret_cast<const CryptoPP::byte*>(bytes.data());
	}

	/**
	 * @brief Validates DER OID contents without imposing machine-sized arc limits.
	 * @param value OID contents, including the combined first two arcs.
	 * @return true for non-empty, minimally encoded, terminated base-128 subidentifiers.
	 */
	bool IsValidOid(Bytes value) noexcept {
		if (value.empty())
			return false;
		bool start = true;
		for (const std::byte byte : value) {
			const auto octet = std::to_integer<std::uint8_t>(byte);
			if (start && octet == 0x80)
				return false;
			start = (octet & 0x80) == 0;
		}
		return start;
	}

	/**
	 * @brief Strictly validates the complete EKU value and records a role match.
	 * @param data EKU extnValue contents.
	 * @param role Validated TLS role.
	 * @param allowed Receives whether an explicit role OID occurs, on success.
	 * @return false for an empty sequence, malformed TLV/OID or trailing bytes.
	 */
	bool ReadTLSExtendedKeyUsage(Bytes data, TLSRole role, bool& allowed) noexcept {
		Reader holder(data, 0, data.size());
		Element sequence;
		if (!holder.Next(TagSequence, sequence) || !holder.AtEnd() || sequence.length == 0)
			return false;
		Reader entries(data, sequence);
		allowed = false;
		while (!entries.AtEnd()) {
			Element oid;
			if (!entries.Next(TagOid, oid) || !IsValidOid(Contents(data, oid)))
				return false;
			const Bytes value = Contents(data, oid);
			allowed |= role == TLSRole::Server ? Equals(value, OidServerAuth) : Equals(value, OidClientAuth);
		}
		return true;
	}

	/**
	 * @brief Validates KU as a DER named BIT STRING over the nine defined bits.
	 * @param data KU extnValue contents.
	 * @return true for 1..9 bits, zero padding, and a set final significant bit.
	 */
	bool IsValidTLSKeyUsage(Bytes data) noexcept {
		Reader holder(data, 0, data.size());
		Element bits;
		if (!holder.Next(TagBitString, bits) || !holder.AtEnd() || bits.length < 2 || bits.length > 3)
			return false;
		const Bytes value = Contents(data, bits);
		const unsigned unused = std::to_integer<unsigned>(value[0]);
		if (unused > 7 || (value.size() - 1) * 8 - unused > 9)
			return false;
		const unsigned last = std::to_integer<unsigned>(value.back());
		return (last & ((1u << unused) - 1)) == 0 && (last & (1u << unused)) != 0;
	}

	/**
	 * @brief Parses a non-negative INTEGER that fits in 32 bits.
	 */
	bool ReadSmallUnsigned(Bytes value, std::uint32_t& out) noexcept {
		if (value.empty() || value.size() > 5)
			return false;
		const auto at = [&value](std::size_t i) { return std::to_integer<std::uint8_t>(value[i]); };
		if (at(0) & 0x80)
			return false;
		if (value.size() > 1 && at(0) == 0 && !(at(1) & 0x80))
			return false;
		std::uint64_t result = 0;
		for (std::size_t i = 0; i < value.size(); ++i)
			result = (result << 8) | at(i);
		if (result > std::numeric_limits<std::uint32_t>::max())
			return false;
		out = static_cast<std::uint32_t>(result);
		return true;
	}

	bool ReadBoolean(Bytes value, bool& out) noexcept {
		if (value.size() != 1)
			return false;
		const auto byte = std::to_integer<std::uint8_t>(value[0]);
		if (byte != 0x00 && byte != 0xFF)
			return false;
		out = byte == 0xFF;
		return true;
	}

	/**
	 * @brief Parses UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ).
	 */
	bool ReadTime(Bytes data, const Element& element, std::int64_t& out) noexcept {
		const Bytes value = Contents(data, element);
		const std::size_t year_digits = element.tag == TagUtcTime ? 2
			: element.tag == TagGeneralizedTime ? 4 : 0;
		if (year_digits == 0 || value.size() != year_digits + 11
			|| std::to_integer<char>(value.back()) != 'Z')
			return false;
		std::size_t position = 0;
		bool ok = true;
		const auto digits = [&](std::size_t count) {
			int result = 0;
			for (std::size_t i = 0; i < count; ++i) {
				const char c = std::to_integer<char>(value[position++]);
				ok = ok && c >= '0' && c <= '9';
				result = result * 10 + (c - '0');
			}
			return result;
		};
		int year = digits(year_digits);
		if (year_digits == 2)
			year += year >= 50 ? 1900 : 2000;
		const int month = digits(2), day = digits(2), hour = digits(2), minute = digits(2), second = digits(2);
		const std::chrono::year_month_day date{std::chrono::year{year},
			std::chrono::month{static_cast<unsigned>(month)}, std::chrono::day{static_cast<unsigned>(day)}};
		if (!ok || !date.ok() || hour > 23 || minute > 59 || second > 59)
			return false;
		out = std::chrono::sys_days{date}.time_since_epoch().count() * 86400LL
			+ hour * 3600LL + minute * 60LL + second;
		return true;
	}

	/**
	 * @brief Reads AlgorithmIdentifier ::= SEQUENCE { OID, parameters OPTIONAL }.
	 */
	bool ReadAlgorithm(Bytes data, const Element& algorithm, Bytes& oid, Bytes& parameters) noexcept {
		Reader reader(data, algorithm);
		Element id;
		if (!reader.Next(TagOid, id))
			return false;
		oid = Contents(data, id);
		parameters = {};
		if (!reader.AtEnd()) {
			Element params;
			if (!reader.Next(params))
				return false;
			parameters = data.subspan(params.start, params.Size());
		}
		return reader.AtEnd();
	}

	/**
	 * @brief Returns the first CommonName of a Name as text.
	 */
	Safe::String CommonName(Bytes data, std::size_t offset, std::size_t length) {
		Reader name(data, offset, offset + length);
		Element outer;
		if (!name.Next(TagSequence, outer))
			return {};
		Reader rdns(data, outer);
		Element rdn;
		while (rdns.Next(TagSet, rdn)) {
			Reader attributes(data, rdn);
			Element attribute;
			while (attributes.Next(TagSequence, attribute)) {
				Reader pair(data, attribute);
				Element type, value;
				if (!pair.Next(TagOid, type) || !pair.Next(value))
					return {};
				if (!Equals(Contents(data, type), OidCommonName))
					continue;
				// UTF8String, PrintableString, TeletexString and IA5String carry byte-compatible text.
				if (value.tag != 0x0C && value.tag != 0x13 && value.tag != 0x14 && value.tag != 0x16)
					return {};
				const Bytes text = Contents(data, value);
				return Safe::String(std::string_view(reinterpret_cast<const char*>(text.data()), text.size()));
			}
		}
		return {};
	}

	constexpr std::size_t MaxDnsName = 253;		///< Longest accepted host name in bytes, without trailing dot.
	constexpr std::size_t MaxDnsLabel = 63;		///< Longest accepted host name label in bytes.

	/**
	 * @brief Tells whether a byte is an ASCII letter, digit or hyphen.
	 * @param c Byte to test.
	 * @return true for a letter-digit-hyphen byte.
	 */
	bool IsLdh(char c) noexcept {
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-';
	}

	/**
	 * @brief Checks a host name label: 1..63 letters, digits or hyphens, no edge hyphen.
	 * @param label Candidate label without dots.
	 * @return true when the label is acceptable.
	 */
	bool IsDnsLabel(std::string_view label) noexcept {
		return !label.empty() && label.size() <= MaxDnsLabel && label.front() != '-' && label.back() != '-'
			&& std::ranges::all_of(label, IsLdh);
	}

	/**
	 * @brief Validates a host name and returns it lowercased in @p canonical.
	 * @param name Candidate ASCII name without a trailing dot; may contain NUL or non-ASCII bytes.
	 * @param wildcard Whether a complete leftmost `*` label over two or more labels is allowed.
	 * @param canonical Receives the lowercased name on success.
	 * @return true when the name is acceptable.
	 * @throws std::bad_alloc @p canonical cannot grow.
	 */
	bool CanonicalDnsName(std::string_view name, bool wildcard, std::string& canonical) {
		if (name.empty() || name.size() > MaxDnsName)
			return false;
		std::size_t labels = 0;
		std::string_view last;
		std::size_t begin = 0;
		while (true) {
			const std::size_t dot = name.find('.', begin);
			const std::string_view label = name.substr(begin, dot == std::string_view::npos ? dot : dot - begin);
			const bool star = wildcard && labels == 0 && label == "*" && dot != std::string_view::npos;
			if (!star && !IsDnsLabel(label))
				return false;
			++labels;
			last = label;
			if (dot == std::string_view::npos)
				break;
			begin = dot + 1;
		}
		if (wildcard && name.front() == '*' && labels < 3)
			return false;
		if (std::ranges::all_of(last, [](char c) { return c >= '0' && c <= '9'; }))
			return false;
		canonical.assign(name);
		for (char& c : canonical)
			if (c >= 'A' && c <= 'Z')
				c = static_cast<char>(c - 'A' + 'a');
		return true;
	}

	/**
	 * @brief Tells whether the canonical @p pattern, wildcard included, matches the canonical @p host.
	 * @param pattern Validated lowercase SAN name, possibly starting with `*.`.
	 * @param host Validated lowercase expected host name without wildcard.
	 * @return true when the names match in full, a wildcard standing for exactly one label.
	 */
	bool DnsMatches(const std::string& pattern, const std::string& host) noexcept {
		if (pattern.front() != '*')
			return pattern == host;
		const std::size_t dot = host.find('.');
		return dot != std::string::npos && dot > 0 && host.compare(dot, std::string::npos, pattern, 1, std::string::npos) == 0;
	}

	/**
	 * @brief Strictly decodes a subjectAltName extnValue into its DNS and IP entries.
	 * @param data Complete certificate DER.
	 * @param offset First byte of the extnValue contents inside @p data.
	 * @param length Byte count of the extnValue contents.
	 * @return Supported entries in order, or MalformedSubjectAltName for any structural defect.
	 * @throws StormByte::Safe::AllocationError Entry or error storage cannot be allocated.
	 */
	StormByte::Expected<StormByte::Safe::Vector<SubjectAltName>, IdentityError> DecodeSubjectAltNames(Bytes data,
		std::size_t offset, std::size_t length) {
		constexpr std::uint8_t TagDns = 0x82;
		constexpr std::uint8_t TagIp = 0x87;
		const auto malformed = [] { return StormByte::Unexpected<IdentityError>(IdentityError::MalformedSubjectAltName); };
		Reader holder(data, offset, offset + length);
		Element names;
		if (!holder.Next(TagSequence, names) || !holder.AtEnd() || names.length == 0)
			return malformed();
		Reader reader(data, names);
		Safe::Vector<SubjectAltName> result;
		while (!reader.AtEnd()) {
			Element name;
			if (!reader.Next(name) || name.length == 0)
				return malformed();
			const Bytes value = Contents(data, name);
			switch (name.tag) {
				case TagDns: {
					const std::string_view text(reinterpret_cast<const char*>(value.data()), value.size());
					std::string canonical;
					if (!CanonicalDnsName(text, true, canonical))
						return malformed();
					result.push_back(SubjectAltName(SubjectAltNameType::DNS, Safe::Binary(value)));
					break;
				}
				case TagIp:
					if (value.size() != 4 && value.size() != 16)
						return malformed();
					result.push_back(SubjectAltName(SubjectAltNameType::IP, Safe::Binary(value)));
					break;
				// otherName, rfc822Name, x400Address, directoryName, ediPartyName, URI and registeredID
				case 0xA0: case 0x81: case 0xA3: case 0xA4: case 0xA5: case 0x86: case 0x88:
					break;
				default:
					return malformed();
			}
		}
		return result;
	}

	template<typename Hash>
	bool VerifyEcdsa(Bytes public_key, Bytes message, Bytes signature) {
		typename CryptoPP::ECDSA<CryptoPP::ECP, Hash>::PublicKey key;
		CryptoPP::ArraySource source(Raw(public_key), public_key.size(), true);
		key.Load(source);
		if (!key.Validate(StormByte::Crypto::RNG(), 3))
			return false;
		typename CryptoPP::ECDSA<CryptoPP::ECP, Hash>::Verifier verifier(key);
		CryptoPP::SecByteBlock p1363(verifier.SignatureLength());
		const std::size_t size = CryptoPP::DSAConvertSignatureFormat(p1363, p1363.size(), CryptoPP::DSA_P1363,
			Raw(signature), signature.size(), CryptoPP::DSA_DER);
		return size == p1363.size()
			&& verifier.VerifyMessage(Raw(message), message.size(), p1363, size);
	}

	template<typename Hash>
	bool VerifyRsa(Bytes public_key, Bytes message, Bytes signature) {
		CryptoPP::RSA::PublicKey key;
		CryptoPP::ArraySource source(Raw(public_key), public_key.size(), true);
		key.Load(source);
		if (!key.Validate(StormByte::Crypto::RNG(), 3))
			return false;
		typename CryptoPP::RSASS<CryptoPP::PKCS1v15, Hash>::Verifier verifier(key);
		return signature.size() == verifier.SignatureLength()
			&& verifier.VerifyMessage(Raw(message), message.size(), Raw(signature), signature.size());
	}

	/**
	 * @brief Verifies @p message against a SubjectPublicKeyInfo using an X.509 signature algorithm.
	 */
	bool VerifySignature(Bytes algorithm, Bytes public_key, Bytes message, Bytes signature) noexcept {
		try {
			Bytes signature_oid, signature_parameters;
			Element algorithm_element;
			Reader algorithm_reader(algorithm, 0, algorithm.size());
			if (!algorithm_reader.Next(TagSequence, algorithm_element) || !algorithm_reader.AtEnd()
				|| !ReadAlgorithm(algorithm, algorithm_element, signature_oid, signature_parameters))
				return false;

			Reader key_reader(public_key, 0, public_key.size());
			Element spki, key_algorithm;
			if (!key_reader.Next(TagSequence, spki) || !key_reader.AtEnd())
				return false;
			Reader spki_reader(public_key, spki);
			Bytes key_oid, key_parameters;
			if (!spki_reader.Next(TagSequence, key_algorithm)
				|| !ReadAlgorithm(public_key, key_algorithm, key_oid, key_parameters))
				return false;

			const bool ecdsa = Equals(signature_oid, OidEcdsaSha256) || Equals(signature_oid, OidEcdsaSha384)
				|| Equals(signature_oid, OidEcdsaSha512);
			if (ecdsa) {
				if (!signature_parameters.empty() || !Equals(key_oid, OidEcPublicKey))
					return false;
				if (Equals(signature_oid, OidEcdsaSha256))
					return VerifyEcdsa<CryptoPP::SHA256>(public_key, message, signature);
				if (Equals(signature_oid, OidEcdsaSha384))
					return VerifyEcdsa<CryptoPP::SHA384>(public_key, message, signature);
				return VerifyEcdsa<CryptoPP::SHA512>(public_key, message, signature);
			}

			const bool rsa = Equals(signature_oid, OidRsaSha256) || Equals(signature_oid, OidRsaSha384)
				|| Equals(signature_oid, OidRsaSha512);
			if (!rsa || !Equals(key_oid, OidRsaEncryption))
				return false;
			constexpr std::byte Null[] = {std::byte{TagNull}, std::byte{0x00}};
			if (!signature_parameters.empty()
				&& !std::equal(signature_parameters.begin(), signature_parameters.end(), std::begin(Null), std::end(Null)))
				return false;
			if (Equals(signature_oid, OidRsaSha256))
				return VerifyRsa<CryptoPP::SHA256>(public_key, message, signature);
			if (Equals(signature_oid, OidRsaSha384))
				return VerifyRsa<CryptoPP::SHA384>(public_key, message, signature);
			return VerifyRsa<CryptoPP::SHA512>(public_key, message, signature);
		} catch (...) {
			return false;
		}
	}

	/**
	 * @brief Decodes the Base64 body of a PEM block into DER.
	 */
	bool DecodeBase64(std::string_view text, Safe::Binary& out) noexcept {
		try {
			for (const char c : text) {
				const bool valid = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
					|| c == '+' || c == '/' || c == '=' || c == '\r' || c == '\n' || c == ' ' || c == '\t';
				if (!valid)
					return false;
			}
			CryptoPP::Base64Decoder decoder;
			decoder.Put(reinterpret_cast<const CryptoPP::byte*>(text.data()), text.size());
			decoder.MessageEnd();
			out = Safe::Binary(StormByte::ByteSize{static_cast<std::size_t>(decoder.MaxRetrievable())});
			if (!out.empty())
				decoder.Get(reinterpret_cast<CryptoPP::byte*>(out.data()), static_cast<std::size_t>(out.size()));
			return !out.empty();
		} catch (...) {
			return false;
		}
	}

	bool IsPem(std::span<const std::byte> data) noexcept {
		const std::string_view text(reinterpret_cast<const char*>(data.data()), data.size());
		return text.find("-----BEGIN") != std::string_view::npos;
	}
}

SubjectAltName::SubjectAltName() noexcept: m_type(SubjectAltNameType::DNS) {}

SubjectAltName::SubjectAltName(SubjectAltNameType type, Safe::Binary value): m_type(type), m_value(std::move(value)) {}

SubjectAltName::SubjectAltName(const SubjectAltName& other) = default;

SubjectAltName::SubjectAltName(SubjectAltName&& other) noexcept = default;

SubjectAltName::~SubjectAltName() noexcept = default;

SubjectAltName& SubjectAltName::operator=(const SubjectAltName& other) = default;

SubjectAltName& SubjectAltName::operator=(SubjectAltName&& other) noexcept = default;

SubjectAltNameType SubjectAltName::Type() const noexcept {
	return m_type;
}

const Safe::Binary& SubjectAltName::Value() const noexcept {
	return m_value;
}

Certificate::Certificate() noexcept = default;

Certificate::Certificate(const Certificate& other) = default;

Certificate::Certificate(Certificate&& other) noexcept = default;

Certificate::~Certificate() noexcept = default;

Certificate& Certificate::operator=(const Certificate& other) = default;

Certificate& Certificate::operator=(Certificate&& other) noexcept = default;

bool Certificate::operator==(const Certificate& other) const noexcept {
	return m_der == other.m_der;
}

std::span<const std::byte> Certificate::View(const Range& range) const noexcept {
	return m_der.span().subspan(range.offset, range.length);
}

bool Certificate::Parse(std::span<const std::byte> der, Certificate& out) noexcept {
	out = Certificate();
	try {
		Certificate result;
		result.m_der = Safe::Binary(der);
		const Bytes data = result.m_der.span();
		const auto range = [](const Element& element) { return Range{element.start, element.Size()}; };

		Reader top(data, 0, data.size());
		Element certificate;
		if (!top.Next(TagSequence, certificate) || !top.AtEnd())
			return false;

		Reader outer(data, certificate);
		Element tbs, signature_algorithm, signature;
		if (!outer.Next(TagSequence, tbs) || !outer.Next(TagSequence, signature_algorithm)
			|| !outer.Next(TagBitString, signature) || !outer.AtEnd())
			return false;
		if (signature.length < 2 || data[signature.value] != std::byte{0})
			return false;
		result.m_tbs = range(tbs);
		result.m_signature_algorithm = range(signature_algorithm);
		result.m_signature = Range{signature.value + 1, signature.length - 1};

		Reader fields(data, tbs);
		Element element;
		if (fields.Peek(TagVersion)) {
			Element version_wrapper, version;
			fields.Next(version_wrapper);
			Reader version_reader(data, version_wrapper);
			std::uint32_t version_number = 0;
			if (!version_reader.Next(TagInteger, version) || !version_reader.AtEnd()
				|| !ReadSmallUnsigned(Contents(data, version), version_number) || version_number > 2)
				return false;
			result.m_version = static_cast<std::uint8_t>(version_number + 1);
		}

		if (!fields.Next(TagInteger, element) || element.length == 0)
			return false;
		result.m_serial = Range{element.value, element.length};

		Element inner_algorithm;
		if (!fields.Next(TagSequence, inner_algorithm))
			return false;
		if (!std::ranges::equal(data.subspan(inner_algorithm.start, inner_algorithm.Size()),
			data.subspan(signature_algorithm.start, signature_algorithm.Size())))
			return false;

		if (!fields.Next(TagSequence, element))
			return false;
		result.m_issuer = range(element);

		Element validity, not_before, not_after;
		if (!fields.Next(TagSequence, validity))
			return false;
		Reader validity_reader(data, validity);
		if (!validity_reader.Next(not_before) || !validity_reader.Next(not_after) || !validity_reader.AtEnd()
			|| !ReadTime(data, not_before, result.m_not_before) || !ReadTime(data, not_after, result.m_not_after))
			return false;

		if (!fields.Next(TagSequence, element))
			return false;
		result.m_subject = range(element);

		if (!fields.Next(TagSequence, element))
			return false;
		result.m_public_key = range(element);

		for (const std::uint8_t unique_id : {TagIssuerUid, TagSubjectUid})
			if (fields.Peek(unique_id) && (result.m_version < 2 || !fields.Next(element)))
				return false;

		if (fields.Peek(TagExtensions)) {
			Element wrapper, list;
			fields.Next(wrapper);
			Reader wrapper_reader(data, wrapper);
			if (result.m_version != 3 || !wrapper_reader.Next(TagSequence, list) || !wrapper_reader.AtEnd()
				|| list.length == 0)
				return false;
			Safe::Vector<std::size_t> seen;	// OID content offset/length pairs
			Reader extensions(data, list);
			while (!extensions.AtEnd()) {
				Element extension, oid, value;
				if (!extensions.Next(TagSequence, extension))
					return false;
				Reader extension_reader(data, extension);
				if (!extension_reader.Next(TagOid, oid))
					return false;
				bool critical = false;
				if (extension_reader.Peek(TagBoolean)) {
					Element flag;
					extension_reader.Next(flag);
					if (!ReadBoolean(Contents(data, flag), critical))
						return false;
				}
				if (!extension_reader.Next(TagOctetString, value) || !extension_reader.AtEnd())
					return false;

				const Bytes id = Contents(data, oid);
				for (std::size_t i = 0; i + 1 < seen.size(); i += 2)
					if (std::ranges::equal(data.subspan(seen[i], seen[i + 1]), id))
						return false;
				seen.push_back(oid.value);
				seen.push_back(oid.length);

				if (Equals(id, OidBasicConstraints)) {
					Reader holder(data, value);
					Element constraints;
					if (!holder.Next(TagSequence, constraints) || !holder.AtEnd())
						return false;
					Reader constraint_reader(data, constraints);
					if (constraint_reader.Peek(TagBoolean)) {
						constraint_reader.Next(element);
						if (!ReadBoolean(Contents(data, element), result.m_ca))
							return false;
					}
					if (constraint_reader.Peek(TagInteger)) {
						constraint_reader.Next(element);
						if (!ReadSmallUnsigned(Contents(data, element), result.m_path_length))
							return false;
						result.m_has_path_length = true;
					}
					if (!constraint_reader.AtEnd() || (result.m_has_path_length && !result.m_ca))
						return false;
				}
				else if (Equals(id, OidKeyUsage)) {
					Reader holder(data, value);
					Element bits;
					if (!holder.Next(TagBitString, bits) || !holder.AtEnd() || bits.length < 2 || bits.length > 3)
						return false;
					const Bytes content = Contents(data, bits);
					const unsigned unused = std::to_integer<unsigned>(content[0]);
					if (unused > 7)
						return false;
					std::uint16_t mask = 0;
					for (std::size_t bit = 0; bit < (content.size() - 1) * 8 - unused; ++bit)
						if (std::to_integer<std::uint8_t>(content[1 + bit / 8]) & (0x80u >> (bit % 8)))
							mask |= static_cast<std::uint16_t>(1u << bit);
					result.m_key_usage = mask;
					result.m_has_key_usage = true;
					result.m_key_usage_der = Range{value.value, value.length};
				}
				else if (Equals(id, OidExtendedKeyUsage)) {
					result.m_extended_key_usage = Range{value.value, value.length};
					result.m_has_extended_key_usage = true;
				}
				else if (Equals(id, OidSubjectAltName)) {
					result.m_subject_alt_name = Range{value.value, value.length};
					result.m_has_subject_alt_name = true;
				}
				else if (critical && !Equals(id, OidExtendedKeyUsage) && !Equals(id, OidSubjectKeyId)
					&& !Equals(id, OidAuthorityKeyId) && !Equals(id, OidSubjectAltName))
					result.m_unknown_critical = true;
			}
		}
		if (!fields.AtEnd())
			return false;
		out = std::move(result);
		return true;
	} catch (...) {
		return false;
	}
}

Safe::Optional<Certificate> StormByte::Crypto::X509::Load(std::span<const std::byte> data) noexcept {
	auto all = LoadAll(data);
	if (all.empty())
		return {};
	return std::move(all.front());
}

Safe::Vector<Certificate> StormByte::Crypto::X509::LoadAll(std::span<const std::byte> data) noexcept {
	try {
		Safe::Vector<Certificate> result;
		if (!IsPem(data)) {
			Certificate certificate;
			if (Certificate::Parse(data, certificate))
				result.push_back(std::move(certificate));
			return result;
		}
		const std::string_view text(reinterpret_cast<const char*>(data.data()), data.size());
		std::size_t position = 0;
		while ((position = text.find(PemBegin, position)) != std::string_view::npos) {
			const std::size_t body = position + PemBegin.size();
			const std::size_t end = text.find(PemEnd, body);
			if (end == std::string_view::npos)
				return {};
			Safe::Binary der;
			if (!DecodeBase64(text.substr(body, end - body), der))
				return {};
			Certificate certificate;
			if (!Certificate::Parse(der.span(), certificate))
				return {};
			result.push_back(std::move(certificate));
			position = end + PemEnd.size();
		}
		return result;
	} catch (...) {
		return {};
	}
}

Safe::Binary Certificate::Save(StormByte::Crypto::KeyPair::StorageFormat format) const {
	if (format == StormByte::Crypto::KeyPair::StorageFormat::DER)
		return m_der;
	std::string encoded;
	CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(encoded), true, 64);
	encoder.Put(reinterpret_cast<const CryptoPP::byte*>(m_der.data()), static_cast<std::size_t>(m_der.size()));
	encoder.MessageEnd();
	std::string pem;
	pem.reserve(encoded.size() + PemBegin.size() + PemEnd.size() + 3);
	pem.append(PemBegin).append("\n").append(encoded);
	if (!encoded.empty() && encoded.back() != '\n')
		pem.push_back('\n');
	pem.append(PemEnd).append("\n");
	return Safe::Binary(std::string_view(pem));
}

const Safe::Binary& Certificate::Der() const noexcept {
	return m_der;
}

unsigned Certificate::Version() const noexcept {
	return m_version;
}

Safe::Binary Certificate::SerialNumber() const {
	return Safe::Binary(View(m_serial));
}

Safe::String Certificate::SubjectCommonName() const {
	return CommonName(m_der.span(), m_subject.offset, m_subject.length);
}

Safe::String Certificate::IssuerCommonName() const {
	return CommonName(m_der.span(), m_issuer.offset, m_issuer.length);
}

TimePoint Certificate::NotBefore() const noexcept {
	return TimePoint{std::chrono::seconds{m_not_before}};
}

TimePoint Certificate::NotAfter() const noexcept {
	return TimePoint{std::chrono::seconds{m_not_after}};
}

bool Certificate::IsCA() const noexcept {
	return m_ca;
}

Safe::Optional<std::uint32_t> Certificate::PathLength() const {
	if (!m_has_path_length)
		return std::nullopt;
	return m_path_length;
}

bool Certificate::HasKeyUsage(KeyUsage usage) const noexcept {
	return !m_has_key_usage || (m_key_usage & static_cast<std::uint16_t>(usage)) != 0;
}

ExpectedPurpose Certificate::VerifyTLSPurpose(TLSRole role) const {
	if (role != TLSRole::Server && role != TLSRole::Client)
		return StormByte::Unexpected<PurposeError>(PurposeError::UnsupportedRole);
	if (m_der.empty())
		return StormByte::Unexpected<PurposeError>(PurposeError::InvalidCertificate);
	bool allowed = true;
	if (m_has_extended_key_usage && !ReadTLSExtendedKeyUsage(View(m_extended_key_usage), role, allowed))
		return StormByte::Unexpected<PurposeError>(PurposeError::MalformedExtendedKeyUsage);
	if (m_has_key_usage && !IsValidTLSKeyUsage(View(m_key_usage_der)))
		return StormByte::Unexpected<PurposeError>(PurposeError::MalformedKeyUsage);
	if (!allowed)
		return StormByte::Unexpected<PurposeError>(PurposeError::ExtendedKeyUsageNotAllowed);
	if (!HasKeyUsage(KeyUsage::DigitalSignature))
		return StormByte::Unexpected<PurposeError>(PurposeError::KeyUsageNotAllowed);
	return {};
}

StormByte::Crypto::KeyPair::Generic::PointerType Certificate::PublicKey() const noexcept {
	try {
		return StormByte::Crypto::KeyPair::Load(Safe::SecureBinary(View(m_public_key)));
	} catch (...) {
		return nullptr;
	}
}

ExpectedSubjectAltNames Certificate::SubjectAltNames() const {
	if (!m_has_subject_alt_name)
		return StormByte::Unexpected<IdentityError>(IdentityError::MissingSubjectAltName);
	return DecodeSubjectAltNames(m_der.span(), m_subject_alt_name.offset, m_subject_alt_name.length);
}

ExpectedIdentity Certificate::VerifyDNSName(std::string_view expected) const {
	if (expected.size() > 1 && expected.back() == '.')
		expected.remove_suffix(1);
	std::string host;
	if (!CanonicalDnsName(expected, false, host))
		return StormByte::Unexpected<IdentityError>(IdentityError::InvalidExpectedName);
	const auto names = SubjectAltNames();
	if (!names)
		return StormByte::Unexpected(names.error());
	for (const SubjectAltName& name : *names) {
		if (name.Type() != SubjectAltNameType::DNS)
			continue;
		const Bytes value = name.Value().span();
		std::string pattern;
		if (CanonicalDnsName(std::string_view(reinterpret_cast<const char*>(value.data()), value.size()), true, pattern)
			&& DnsMatches(pattern, host))
			return {};
	}
	return StormByte::Unexpected<IdentityError>(IdentityError::NoMatch);
}

ExpectedIdentity Certificate::VerifyIPAddress(std::span<const std::byte> expected) const {
	if (expected.size() != 4 && expected.size() != 16)
		return StormByte::Unexpected<IdentityError>(IdentityError::InvalidExpectedAddress);
	const auto names = SubjectAltNames();
	if (!names)
		return StormByte::Unexpected(names.error());
	for (const SubjectAltName& name : *names)
		if (name.Type() == SubjectAltNameType::IP && std::ranges::equal(name.Value().span(), expected))
			return {};
	return StormByte::Unexpected<IdentityError>(IdentityError::NoMatch);
}

bool Certificate::IsValidAt(TimePoint at) const noexcept {
	const std::int64_t seconds = at.time_since_epoch().count();
	return m_not_before <= seconds && seconds <= m_not_after;
}

bool Certificate::IsIssuedBy(const Certificate& issuer) const noexcept {
	return std::ranges::equal(View(m_issuer), issuer.View(issuer.m_subject))
		&& VerifySignature(View(m_signature_algorithm), issuer.View(issuer.m_public_key), View(m_tbs),
			View(m_signature));
}

bool Certificate::VerifyChain(std::span<const Certificate> intermediates, const Certificate& anchor,
	TimePoint at) const noexcept {
	const std::size_t length = intermediates.size() + 1;
	const auto at_index = [&](std::size_t index) -> const Certificate& {
		return index == 0 ? *this : index < length ? intermediates[index - 1] : anchor;
	};
	for (std::size_t index = 0; index <= length; ++index) {
		const Certificate& current = at_index(index);
		if (current.m_unknown_critical || !current.IsValidAt(at))
			return false;
		if (index == 0)
			continue;
		// Issuers must be v3 CAs that may sign certificates; index - 1 CAs sit below this one.
		if (current.m_version != 3 || !current.m_ca || !current.HasKeyUsage(KeyUsage::KeyCertSign))
			return false;
		if (current.m_has_path_length && index - 1 > current.m_path_length)
			return false;
		if (!at_index(index - 1).IsIssuedBy(current))
			return false;
	}
	return true;
}

bool Certificate::VerifyChain(std::span<const Certificate> intermediates, const Certificate& anchor) const noexcept {
	return VerifyChain(intermediates, anchor,
		std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now()));
}

namespace {
	/**
	 * @brief Checks the bounded signature-algorithm subset before signature verification.
	 * @param data Full signature AlgorithmIdentifier.
	 * @return true for supported SHA-2 RSA/ECDSA and valid parameters.
	 */
	bool IsPeerSignatureAlgorithm(Bytes data) noexcept {
		Reader reader(data, 0, data.size());
		Element sequence;
		Bytes oid, parameters;
		if (!reader.Next(TagSequence, sequence) || !reader.AtEnd()
			|| !ReadAlgorithm(data, sequence, oid, parameters))
			return false;
		if (Equals(oid, OidEcdsaSha256) || Equals(oid, OidEcdsaSha384) || Equals(oid, OidEcdsaSha512))
			return parameters.empty();
		if (!Equals(oid, OidRsaSha256) && !Equals(oid, OidRsaSha384) && !Equals(oid, OidRsaSha512))
			return false;
		constexpr std::uint8_t Null[] = {TagNull, 0};
		return parameters.empty() || Equals(parameters, Null);
	}

	/**
	 * @brief Validates a public key against the bounded peer-key policy.
	 * @param data Full SubjectPublicKeyInfo.
	 * @return true for a validated RSA 2048..8192 or ECDSA P-256/P-384/P-521 key.
	 * @throws StormByte::Safe::AllocationError Crypto operations cannot allocate Safe state.
	 */
	bool IsPeerPublicKey(Bytes data) {
		Reader reader(data, 0, data.size());
		Element sequence, algorithm, bits;
		Bytes oid, parameters;
		if (!reader.Next(TagSequence, sequence) || !reader.AtEnd())
			return false;
		Reader fields(data, sequence);
		if (!fields.Next(TagSequence, algorithm) || !ReadAlgorithm(data, algorithm, oid, parameters)
			|| !fields.Next(TagBitString, bits) || !fields.AtEnd() || bits.length < 2
			|| data[bits.value] != std::byte{0})
			return false;
		try {
			CryptoPP::ArraySource source(Raw(data), data.size(), true);
			if (Equals(oid, OidRsaEncryption)) {
				constexpr std::uint8_t Null[] = {TagNull, 0};
				if (!parameters.empty() && !Equals(parameters, Null))
					return false;
				CryptoPP::RSA::PublicKey key;
				key.Load(source);
				const auto bits = key.GetModulus().BitCount();
				return bits >= 2048 && bits <= 8192 && key.Validate(StormByte::Crypto::RNG(), 3);
			}
			if (!Equals(oid, OidEcPublicKey))
				return false;
			constexpr std::uint8_t P256[] = {TagOid, 8, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
			constexpr std::uint8_t P384[] = {TagOid, 5, 0x2B, 0x81, 0x04, 0x00, 0x22};
			constexpr std::uint8_t P521[] = {TagOid, 5, 0x2B, 0x81, 0x04, 0x00, 0x23};
			if (!Equals(parameters, P256) && !Equals(parameters, P384) && !Equals(parameters, P521))
				return false;
			CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey key;
			key.Load(source);
			return key.Validate(StormByte::Crypto::RNG(), 3);
		} catch (const CryptoPP::Exception&) {
			return false;
		}
	}

	/**
	 * @brief Audits extension restrictions not enforced by legacy chain verification.
	 * @param data Full TBSCertificate.
	 * @param index Leaf-to-anchor position.
	 * @return Success or an indexed unsupported/malformed extension failure.
	 */
	ExpectedTLSPeer CheckPeerExtensions(Bytes data, std::size_t index) {
		const auto fail = [index](TLSPeerError code) {
			return ExpectedTLSPeer(StormByte::Unexpected(TLSPeerFailure(code, index)));
		};
		Reader holder(data, 0, data.size());
		Element sequence, element;
		if (!holder.Next(TagSequence, sequence) || !holder.AtEnd())
			return fail(TLSPeerError::MalformedExtension);
		Reader fields(data, sequence);
		if (fields.Peek(TagVersion))
			fields.Next(element);
		for (unsigned i = 0; i < 6; ++i)
			if (!fields.Next(element))
				return fail(TLSPeerError::MalformedExtension);
		for (const auto tag : {TagIssuerUid, TagSubjectUid})
			if (fields.Peek(tag))
				fields.Next(element);
		if (fields.AtEnd())
			return {};
		Element wrapper, list;
		if (!fields.Next(TagExtensions, wrapper) || !fields.AtEnd())
			return fail(TLSPeerError::MalformedExtension);
		Reader wrapper_reader(data, wrapper);
		if (!wrapper_reader.Next(TagSequence, list) || !wrapper_reader.AtEnd())
			return fail(TLSPeerError::MalformedExtension);
		Reader extensions(data, list);
		while (!extensions.AtEnd()) {
			Element extension, oid, value;
			if (!extensions.Next(TagSequence, extension))
				return fail(TLSPeerError::MalformedExtension);
			Reader entries(data, extension);
			if (!entries.Next(TagOid, oid) || !IsValidOid(Contents(data, oid)))
				return fail(TLSPeerError::MalformedExtension);
			bool critical = false;
			if (entries.Peek(TagBoolean)) {
				entries.Next(element);
				if (!ReadBoolean(Contents(data, element), critical) || !critical)
					return fail(TLSPeerError::MalformedExtension);
			}
			if (!entries.Next(TagOctetString, value) || !entries.AtEnd())
				return fail(TLSPeerError::MalformedExtension);
			const Bytes id = Contents(data, oid);
			// These extensions restrict a path independently of their critical flag.
			constexpr std::uint8_t NameConstraints[] = {0x55, 0x1D, 0x1E};
			constexpr std::uint8_t PolicyMappings[] = {0x55, 0x1D, 0x21};
			constexpr std::uint8_t PolicyConstraints[] = {0x55, 0x1D, 0x24};
			constexpr std::uint8_t InhibitAnyPolicy[] = {0x55, 0x1D, 0x36};
			constexpr std::uint8_t TLSFeature[] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x18};
			constexpr std::uint8_t ProxyCertInfo[] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x0E};
			if (Equals(id, NameConstraints) || Equals(id, PolicyMappings)
				|| Equals(id, PolicyConstraints) || Equals(id, InhibitAnyPolicy)
				|| Equals(id, TLSFeature) || Equals(id, ProxyCertInfo))
				return fail(TLSPeerError::UnsupportedConstraint);
			if (Equals(id, OidBasicConstraints)) {
				Reader constraints(data, value);
				Element basic;
				if (!constraints.Next(TagSequence, basic) || !constraints.AtEnd())
					return fail(TLSPeerError::MalformedExtension);
				Reader content(data, basic);
				bool ca = false;
				if (content.Peek(TagBoolean)) {
					content.Next(element);
					if (!ReadBoolean(Contents(data, element), ca) || !ca)
						return fail(TLSPeerError::MalformedExtension);
				}
				if (ca && !critical)
					return fail(TLSPeerError::MalformedExtension);
			}
			else if (critical && !Equals(id, OidKeyUsage) && !Equals(id, OidExtendedKeyUsage)
				&& !Equals(id, OidSubjectAltName))
				return fail(TLSPeerError::UnsupportedCriticalExtension);
			if (critical && Equals(id, OidSubjectAltName)) {
				Reader names_holder(data, value);
				Element names;
				if (!names_holder.Next(TagSequence, names) || !names_holder.AtEnd())
					return fail(TLSPeerError::MalformedExtension);
				Reader names_reader(data, names);
				while (!names_reader.AtEnd()) {
					if (!names_reader.Next(element))
						return fail(TLSPeerError::MalformedExtension);
					if (element.tag != 0x82 && element.tag != 0x87)
						return fail(TLSPeerError::UnsupportedCriticalExtension);
				}
			}
		}
		return {};
	}
}

TLSPeerFailure::TLSPeerFailure() noexcept: TLSPeerFailure(TLSPeerError::InvalidCertificate) {}

TLSPeerFailure::TLSPeerFailure(TLSPeerError code, std::size_t index) noexcept:
	m_code(code), m_index(index), m_purpose(PurposeError::InvalidCertificate),
	m_identity(IdentityError::NoMatch) {}

TLSPeerFailure::TLSPeerFailure(PurposeError detail, std::size_t index) noexcept:
	TLSPeerFailure(TLSPeerError::Purpose, index) {
	m_purpose = detail;
}

TLSPeerFailure::TLSPeerFailure(IdentityError detail, std::size_t index) noexcept:
	TLSPeerFailure(TLSPeerError::Identity, index) {
	m_identity = detail;
}

TLSPeerFailure::TLSPeerFailure(const TLSPeerFailure& other) noexcept = default;

TLSPeerFailure::TLSPeerFailure(TLSPeerFailure&& other) noexcept = default;

TLSPeerFailure::~TLSPeerFailure() noexcept = default;

TLSPeerFailure& TLSPeerFailure::operator=(const TLSPeerFailure& other) noexcept = default;

TLSPeerFailure& TLSPeerFailure::operator=(TLSPeerFailure&& other) noexcept = default;

TLSPeerError TLSPeerFailure::Code() const noexcept {
	return m_code;
}

std::size_t TLSPeerFailure::CertificateIndex() const noexcept {
	return m_index;
}

PurposeError TLSPeerFailure::PurposeDetail() const noexcept {
	return m_purpose;
}

IdentityError TLSPeerFailure::IdentityDetail() const noexcept {
	return m_identity;
}

ExpectedTLSPeer TLSPeerVerifier::Verify(const Certificate& leaf,
	std::span<const Certificate> intermediates, const Certificate& anchor,
	TimePoint at, TLSRole role, const SubjectAltName* identity) {
	const auto fail = [](TLSPeerError code, std::size_t index = 0) {
		return ExpectedTLSPeer(StormByte::Unexpected(TLSPeerFailure(code, index)));
	};
	if (role != TLSRole::Server && role != TLSRole::Client)
		return fail(TLSPeerError::UnsupportedRole);
	if (!identity && role == TLSRole::Server)
		return fail(TLSPeerError::MissingServerIdentity);
	if (identity && identity->Type() != SubjectAltNameType::DNS && identity->Type() != SubjectAltNameType::IP)
		return fail(TLSPeerError::UnsupportedIdentity);
	const std::size_t last = intermediates.size() + 1;
	const auto certificate_at = [&](std::size_t index) -> const Certificate& {
		return index == 0 ? leaf : index == last ? anchor : intermediates[index - 1];
	};
	for (std::size_t index = 0; index <= last; ++index) {
		const auto& certificate = certificate_at(index);
		if (certificate.m_der.empty())
			return fail(TLSPeerError::InvalidCertificate, index);
		if (!certificate.IsValidAt(at))
			return fail(TLSPeerError::InvalidTime, index);
		if (index == 0 && certificate.IsCA())
			return fail(TLSPeerError::LeafIsCA);
		if (certificate.m_has_subject_alt_name) {
			const auto names = certificate.SubjectAltNames();
			if (!names)
				return StormByte::Unexpected(TLSPeerFailure(*names.error(), index));
		}
		const auto extensions = CheckPeerExtensions(certificate.View(certificate.m_tbs), index);
		if (!extensions)
			return extensions;
		if (index == 0) {
			const auto purpose = certificate.VerifyTLSPurpose(role);
			if (!purpose)
				return StormByte::Unexpected(TLSPeerFailure(*purpose.error(), index));
		}
		else {
			bool allowed = true;
			if (certificate.m_has_extended_key_usage
				&& !ReadTLSExtendedKeyUsage(certificate.View(certificate.m_extended_key_usage), role, allowed))
				return StormByte::Unexpected(TLSPeerFailure(PurposeError::MalformedExtendedKeyUsage, index));
			if (certificate.m_has_key_usage && !IsValidTLSKeyUsage(certificate.View(certificate.m_key_usage_der)))
				return StormByte::Unexpected(TLSPeerFailure(PurposeError::MalformedKeyUsage, index));
			if (!allowed)
				return StormByte::Unexpected(TLSPeerFailure(PurposeError::ExtendedKeyUsageNotAllowed, index));
			if (certificate.Version() != 3 || !certificate.IsCA())
				return fail(TLSPeerError::NotCA, index);
			if (!certificate.HasKeyUsage(KeyUsage::KeyCertSign))
				return fail(TLSPeerError::IssuerKeyUsageNotAllowed, index);
			if (certificate.m_has_path_length && index - 1 > certificate.m_path_length)
				return fail(TLSPeerError::PathLengthExceeded, index);
		}
		if (certificate.m_has_key_usage && !certificate.HasKeyUsage(KeyUsage::KeyAgreement)
			&& (certificate.HasKeyUsage(KeyUsage::EncipherOnly) || certificate.HasKeyUsage(KeyUsage::DecipherOnly)))
			return fail(TLSPeerError::MalformedExtension, index);
		if (certificate.m_has_key_usage && certificate.HasKeyUsage(KeyUsage::KeyCertSign) && !certificate.IsCA())
			return fail(TLSPeerError::MalformedExtension, index);
		if (!IsPeerPublicKey(certificate.View(certificate.m_public_key))
			|| (index != last && !IsPeerSignatureAlgorithm(certificate.View(certificate.m_signature_algorithm))))
			return fail(TLSPeerError::UnsupportedAlgorithm, index);
		if (index > 0 && !certificate_at(index - 1).IsIssuedBy(certificate))
			return fail(TLSPeerError::SignatureOrIssuerMismatch, index - 1);
	}
	if (identity) {
		const auto bytes = identity->Value().span();
		const auto matched = identity->Type() == SubjectAltNameType::DNS
			? leaf.VerifyDNSName(std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()))
			: leaf.VerifyIPAddress(bytes);
		if (!matched)
			return StormByte::Unexpected(TLSPeerFailure(*matched.error()));
	}
	return {};
}
