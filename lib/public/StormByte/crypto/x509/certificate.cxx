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

#include <base64.h>
#include <dsa.h>
#include <eccrypto.h>
#include <filters.h>
#include <rsa.h>
#include <sha.h>

#include <algorithm>
#include <limits>
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

StormByte::Crypto::KeyPair::Generic::PointerType Certificate::PublicKey() const noexcept {
	try {
		return StormByte::Crypto::KeyPair::Load(Safe::SecureBinary(View(m_public_key)));
	} catch (...) {
		return nullptr;
	}
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
