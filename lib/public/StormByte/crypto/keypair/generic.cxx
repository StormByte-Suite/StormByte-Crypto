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

#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/engine/keypair/api.hxx>
#include <StormByte/crypto/keypair/dsa.hxx>
#include <StormByte/crypto/keypair/ecc.hxx>
#include <StormByte/crypto/keypair/ecdh.hxx>
#include <StormByte/crypto/keypair/ecdsa.hxx>
#include <StormByte/crypto/keypair/ed25519.hxx>
#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/keypair/rsa.hxx>
#include <StormByte/crypto/keypair/x25519.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/crypto/random.hxx>
#include <StormByte/safe/optional.hxx>
#include <StormByte/safe/pair.hxx>
#include <StormByte/safe/string.hxx>
#include <StormByte/safe/vector.hxx>

#include <aes.h>
#include <algorithm>
#include <asn.h>
#include <base64.h>
#include <cctype>
#include <dsa.h>
#include <eccrypto.h>
#include <filters.h>
#include <fstream>
#include <hmac.h>
#include <initializer_list>
#include <integer.h>
#include <iterator>
#include <modes.h>
#include <oids.h>
#include <osrng.h>
#include <pwdbased.h>
#include <queue.h>
#include <rsa.h>
#include <secblock.h>
#include <sha.h>
#include <span>
#include <string_view>
#include <xed25519.h>

using namespace StormByte::Crypto::KeyPair;
using StormByte::Crypto::Helpers::PasswordAccess;
using StormByte::Crypto::Helpers::SecureWipe;
namespace Secure = StormByte::Crypto::Secure;
using StormByte::Crypto::Secure::Password;
using StormByte::Crypto::RNG;
namespace Safe = StormByte::Safe;

namespace {
	constexpr unsigned int kPkcs8Pbkdf2Iterations = 10000;

	using PemBlock = Safe::Pair<Safe::String, Safe::Vector<CryptoPP::byte>>;

	template<typename Cleanup>
	class WipeOnExit {
		public:
			explicit WipeOnExit(Cleanup cleanup): m_cleanup(std::move(cleanup)) {}

			WipeOnExit(const WipeOnExit&) = delete;

			WipeOnExit(WipeOnExit&&) = delete;

			~WipeOnExit() noexcept {
				if (m_active)
					m_cleanup();
			}

			WipeOnExit& operator=(const WipeOnExit&) = delete;

			WipeOnExit& operator=(WipeOnExit&&) = delete;

			void Release() noexcept { m_active = false; }

		private:
			Cleanup m_cleanup;
			bool m_active = true;
	};

	CryptoPP::OID MakeOid(std::initializer_list<CryptoPP::word32> arcs) {
		CryptoPP::OID oid;
		for (CryptoPP::word32 a : arcs)
			oid += a;
		return oid;
	}

	const CryptoPP::OID kOidPBES2 = MakeOid({1, 2, 840, 113549, 1, 5, 13});
	const CryptoPP::OID kOidPBKDF2 = MakeOid({1, 2, 840, 113549, 1, 5, 12});
	const CryptoPP::OID kOidHmacSha256 = MakeOid({1, 2, 840, 113549, 2, 9});
	const CryptoPP::OID kOidAes128Cbc = MakeOid({2, 16, 840, 1, 101, 3, 4, 1, 2});
	const CryptoPP::OID kOidAes192Cbc = MakeOid({2, 16, 840, 1, 101, 3, 4, 1, 22});
	const CryptoPP::OID kOidAes256Cbc = MakeOid({2, 16, 840, 1, 101, 3, 4, 1, 42});

	Safe::Vector<CryptoPP::byte> ReadFileBytes(const std::filesystem::path& path) noexcept {
		try {
			std::ifstream ifs(path, std::ios::in | std::ios::binary);
			if (!ifs)
				return {};
			CryptoPP::ByteQueue queue;
			for (std::istreambuf_iterator<char> current(ifs), end; current != end; ++current)
				queue.Put(static_cast<CryptoPP::byte>(*current));
			Safe::Vector<CryptoPP::byte> bytes(queue.CurrentSize());
			WipeOnExit wipeBytes([&]() noexcept { SecureWipe(bytes); });
			if (!bytes.empty())
				queue.Get(bytes.data(), bytes.size());
			wipeBytes.Release();
			return bytes;
		} catch (...) {
			return {};
		}
	}

	bool WriteFileBytes(const std::filesystem::path& path, const CryptoPP::byte* data, size_t len) noexcept {
		try {
			std::error_code ec;
			if (std::filesystem::is_symlink(std::filesystem::symlink_status(path, ec)))
				return false;
			std::ofstream ofs(path, std::ios::out | std::ios::binary | std::ios::trunc);
			if (!ofs)
				return false;
			if (len > 0 && data)
				ofs.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
			return static_cast<bool>(ofs);
		} catch (...) {
			return false;
		}
	}

	void RestrictToOwner(const std::filesystem::path& path) noexcept {
		std::error_code ec;
		std::filesystem::permissions(
			path,
			std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
			std::filesystem::perm_options::replace,
			ec
		);
	}

	bool IsPemText(std::span<const CryptoPP::byte> data) noexcept {
		if (data.size() < 11)
			return false;
		constexpr char marker[] = "-----BEGIN";
		const auto head = data.first(std::min<size_t>(data.size(), 64));
		return std::search(head.begin(), head.end(), marker, marker + sizeof(marker) - 1) != head.end();
	}

	Safe::String Base64Encode(const CryptoPP::byte* data, size_t len) {
		CryptoPP::Base64Encoder encoder(nullptr, false);
		encoder.Put(data, len);
		encoder.MessageEnd();
		Safe::String out;
		WipeOnExit wipeOutput([&]() noexcept { SecureWipe(out); });
		out.resize(encoder.MaxRetrievable());
		encoder.Get(reinterpret_cast<CryptoPP::byte*>(out.data()), static_cast<size_t>(out.size()));
		wipeOutput.Release();
		return out;
	}

	Safe::Vector<CryptoPP::byte> Base64Decode(const Safe::String& b64) {
		CryptoPP::Base64Decoder decoder;
		for (unsigned char c : b64) {
			if (!std::isspace(c))
				decoder.Put(c);
		}
		decoder.MessageEnd();
		Safe::Vector<CryptoPP::byte> decoded(decoder.MaxRetrievable());
		WipeOnExit wipeDecoded([&]() noexcept { SecureWipe(decoded); });
		decoder.Get(decoded.data(), decoded.size());
		wipeDecoded.Release();
		return decoded;
	}

	Safe::String PemEncode(std::string_view label, const CryptoPP::byte* der, size_t derLen) {
		auto b64 = Base64Encode(der, derLen);
		WipeOnExit wipeBase64([&]() noexcept { SecureWipe(b64); });
		Safe::String pem;
		WipeOnExit wipePemOnFailure([&]() noexcept { SecureWipe(pem); });
		const size_t encodedSize = static_cast<size_t>(b64.size());
		const size_t lineCount = encodedSize / 64 + (encodedSize % 64 != 0);
		pem.reserve(encodedSize + 2 * label.size() + 32 + lineCount);
		pem += "-----BEGIN ";
		pem += label;
		pem += "-----\n";
		for (size_t i = 0; i < static_cast<size_t>(b64.size()); i += 64) {
			pem.append(b64.data() + i, b64.data() + std::min(i + 64, encodedSize));
			pem += '\n';
		}
		pem += "-----END ";
		pem += label;
		pem += "-----\n";
		wipePemOnFailure.Release();
		return pem;
	}

	Safe::Vector<PemBlock> PemDecodeAll(std::span<const CryptoPP::byte> data) {
		Safe::Vector<PemBlock> blocks;
		WipeOnExit wipeBlocks([&]() noexcept {
			for (auto& block : blocks)
				SecureWipe(block.second);
		});
		Safe::String text(data.begin(), data.end());
		WipeOnExit wipeText([&]() noexcept { SecureWipe(text); });
		size_t pos = 0;
		while (pos < text.size()) {
			const size_t beginMark = static_cast<size_t>(text.find("-----BEGIN ", pos));
			if (beginMark == static_cast<size_t>(Safe::String::npos))
				break;
			const size_t labelStart = beginMark + 11;
			const size_t labelEnd = static_cast<size_t>(text.find("-----", labelStart));
			if (labelEnd == static_cast<size_t>(Safe::String::npos))
				break;
			Safe::String label(text, labelStart, labelEnd - labelStart);
			while (!label.empty() && std::isspace(static_cast<unsigned char>(label.back())))
				label.pop_back();
			const size_t headerEnd = labelEnd + 5;
			Safe::String endToken("-----END ");
			endToken += label;
			endToken += "-----";
			const size_t endMark = static_cast<size_t>(text.find(endToken, headerEnd));
			if (endMark == static_cast<size_t>(Safe::String::npos))
				break;
			Safe::String body(text, headerEnd, endMark - headerEnd);
			WipeOnExit wipeBody([&]() noexcept { SecureWipe(body); });
			PemBlock block;
			WipeOnExit wipeBlock([&]() noexcept { SecureWipe(block.second); });
			block.first = std::move(label);
			block.second = Base64Decode(body);
			if (!block.second.empty())
				blocks.push_back(std::move(block));
			pos = endMark + static_cast<size_t>(endToken.size());
		}
		wipeBlocks.Release();
		return blocks;
	}

	bool LabelIsPublic(std::string_view label) noexcept {
		return label == "PUBLIC KEY" || label == "RSA PUBLIC KEY" || label == "EC PUBLIC KEY";
	}

	bool LabelIsPrivate(std::string_view label) noexcept {
		return label == "PRIVATE KEY"
			|| label == "RSA PRIVATE KEY"
			|| label == "EC PRIVATE KEY"
			|| label == "DSA PRIVATE KEY"
			|| label == "ENCRYPTED PRIVATE KEY";
	}

	bool LabelIsEncrypted(std::string_view label, const Safe::String& fullText) noexcept {
		if (label == "ENCRYPTED PRIVATE KEY")
			return true;
		return fullText.find("Proc-Type:") != Safe::String::npos
			&& fullText.find("ENCRYPTED") != Safe::String::npos;
	}

	bool ContainsOid(std::span<const CryptoPP::byte> der, std::span<const CryptoPP::byte> oid) noexcept {
		if (oid.empty() || der.size() < oid.size())
			return false;
		for (size_t i = 0; i + oid.size() <= der.size(); ++i) {
			if (std::equal(oid.begin(), oid.end(), der.begin() + static_cast<std::ptrdiff_t>(i)))
				return true;
		}
		return false;
	}

	bool TryLoadRsaPrivate(std::span<const CryptoPP::byte> der, CryptoPP::RSA::PrivateKey& priv) noexcept {
		try {
			CryptoPP::ArraySource src(der.data(), der.size(), true);
			priv.Load(src);
			return priv.Validate(RNG(), 2);
		} catch (...) {}
		try {
			CryptoPP::ArraySource src(der.data(), der.size(), true);
			priv.BERDecodePrivateKey(src, false, static_cast<int>(der.size()));
			return priv.Validate(RNG(), 2);
		} catch (...) {
			return false;
		}
	}

	bool TryLoadDsaPrivate(std::span<const CryptoPP::byte> der, CryptoPP::DSA::PrivateKey& priv) noexcept {
		try {
			CryptoPP::ArraySource src(der.data(), der.size(), true);
			priv.Load(src);
			return priv.Validate(RNG(), 2);
		} catch (...) {}
		try {
			CryptoPP::ArraySource src(der.data(), der.size(), true);
			priv.BERDecodePrivateKey(src, false, static_cast<int>(der.size()));
			return priv.Validate(RNG(), 2);
		} catch (...) {
			return false;
		}
	}

	bool TryLoadEcPrivateSec1(std::span<const CryptoPP::byte> der, CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey& priv) noexcept {
		try {
			CryptoPP::ArraySource src(der.data(), der.size(), true);
			CryptoPP::BERSequenceDecoder seq(src);
			CryptoPP::word32 version = 0;
			CryptoPP::BERDecodeUnsigned(seq, version);
			CryptoPP::SecByteBlock privateKey;
			CryptoPP::BERDecodeOctetString(seq, privateKey);
			if (privateKey.empty())
				return false;
			CryptoPP::OID curveOid;
			bool haveCurve = false;
			while (!seq.EndReached()) {
				CryptoPP::byte next = 0;
				seq.Peek(next);
				const bool context = (next & CryptoPP::CONTEXT_SPECIFIC) != 0;
				if (!context) {
					seq.SkipAll();
					break;
				}
				const CryptoPP::byte tag = static_cast<CryptoPP::byte>(next & 0x1f);
				const bool constructed = (next & CryptoPP::CONSTRUCTED) != 0;
				if (tag == 0) {
					CryptoPP::BERGeneralDecoder params(
						seq,
						CryptoPP::CONTEXT_SPECIFIC | CryptoPP::CONSTRUCTED | 0
					);
					CryptoPP::byte peek = 0;
					params.Peek(peek);
					if (peek == CryptoPP::OBJECT_IDENTIFIER) {
						curveOid.BERDecode(params);
						haveCurve = true;
					} else {
						params.SkipAll();
					}
					params.MessageEnd();
				} else if (tag == 1) {
					CryptoPP::BERGeneralDecoder pubdec(
						seq,
						CryptoPP::CONTEXT_SPECIFIC | (constructed ? CryptoPP::CONSTRUCTED : 0) | 1
					);
					pubdec.SkipAll();
					pubdec.MessageEnd();
				} else {
					seq.SkipAll();
					break;
				}
			}
			seq.MessageEnd();
			if (!haveCurve)
				curveOid = CryptoPP::ASN1::secp256r1();
			priv.AccessGroupParameters().Initialize(curveOid);
			const CryptoPP::Integer x(privateKey.data(), privateKey.size());
			priv.SetPrivateExponent(x);
			return priv.Validate(RNG(), 2);
		} catch (...) {
			return false;
		}
	}

	bool TryLoadEcPrivate(std::span<const CryptoPP::byte> der, CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey& priv) noexcept {
		try {
			CryptoPP::ArraySource src(der.data(), der.size(), true);
			priv.Load(src);
			return priv.Validate(RNG(), 2);
		} catch (...) {}
		try {
			CryptoPP::ArraySource src(der.data(), der.size(), true);
			priv.BERDecodePrivateKey(src, false, static_cast<int>(der.size()));
			return priv.Validate(RNG(), 2);
		} catch (...) {}
		return TryLoadEcPrivateSec1(der, priv);
	}

	Safe::Vector<CryptoPP::byte> RsaPrivateToPkcs8Der(const CryptoPP::RSA::PrivateKey& priv) {
		CryptoPP::ByteQueue q;
		priv.Save(q);
		Safe::Vector<CryptoPP::byte> out(q.CurrentSize());
		WipeOnExit wipeOutput([&]() noexcept { SecureWipe(out); });
		if (!out.empty())
			q.Get(out.data(), out.size());
		wipeOutput.Release();
		return out;
	}

	Safe::Vector<CryptoPP::byte> EcPrivateToPkcs8Der(const CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey& priv) {
		CryptoPP::ByteQueue q;
		priv.Save(q);
		Safe::Vector<CryptoPP::byte> out(q.CurrentSize());
		WipeOnExit wipeOutput([&]() noexcept { SecureWipe(out); });
		if (!out.empty())
			q.Get(out.data(), out.size());
		wipeOutput.Release();
		return out;
	}

	Safe::Vector<CryptoPP::byte> DsaPrivateToPkcs8Der(const CryptoPP::DSA::PrivateKey& priv) {
		CryptoPP::ByteQueue q;
		priv.Save(q);
		Safe::Vector<CryptoPP::byte> out(q.CurrentSize());
		WipeOnExit wipeOutput([&]() noexcept { SecureWipe(out); });
		if (!out.empty())
			q.Get(out.data(), out.size());
		wipeOutput.Release();
		return out;
	}

	bool DetectTypeFromDer(std::span<const CryptoPP::byte> der, Type& out) noexcept {
		constexpr CryptoPP::byte oid_rsa[]{
			0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01
		};
		constexpr CryptoPP::byte oid_ec[]{
			0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
		};
		constexpr CryptoPP::byte oid_secp256r1[]{
			0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
		};
		constexpr CryptoPP::byte oid_secp384r1[]{
			0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22
		};
		constexpr CryptoPP::byte oid_secp521r1[]{
			0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23
		};
		constexpr CryptoPP::byte oid_dsa[]{
			0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01
		};
		constexpr CryptoPP::byte oid_ed25519[]{
			0x06, 0x03, 0x2B, 0x65, 0x70
		};
		constexpr CryptoPP::byte oid_x25519[]{
			0x06, 0x03, 0x2B, 0x65, 0x6E
		};
		if (ContainsOid(der, oid_rsa)) {
			out = Type::RSA;
			return true;
		}
		if (ContainsOid(der, oid_ed25519)) {
			out = Type::ED25519;
			return true;
		}
		if (ContainsOid(der, oid_x25519)) {
			out = Type::X25519;
			return true;
		}
		if (ContainsOid(der, oid_dsa)) {
			out = Type::DSA;
			return true;
		}
		if (ContainsOid(der, oid_ec)
			|| ContainsOid(der, oid_secp256r1)
			|| ContainsOid(der, oid_secp384r1)
			|| ContainsOid(der, oid_secp521r1)) {
			out = Type::ECC;
			return true;
		}
		{
			CryptoPP::RSA::PrivateKey rsaPriv;
			if (TryLoadRsaPrivate(der, rsaPriv)) {
				out = Type::RSA;
				return true;
			}
		}
		{
			CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey ecPriv;
			if (TryLoadEcPrivate(der, ecPriv)) {
				out = Type::ECC;
				return true;
			}
		}
		try {
			CryptoPP::ArraySource src(der.data(), der.size(), true);
			CryptoPP::ECIES<CryptoPP::ECP>::PublicKey pub;
			pub.Load(src);
			if (pub.Validate(RNG(), 1)) {
				out = Type::ECC;
				return true;
			}
		} catch (...) {}
		return false;
	}

	bool IsRaw32(std::span<const CryptoPP::byte> der) noexcept {
		return der.size() == 32;
	}

	bool ExtractRaw32(std::span<const CryptoPP::byte> der, CryptoPP::SecByteBlock& out) noexcept {
		const CryptoPP::byte* p = der.data();
		const size_t n = der.size();
		for (size_t i = 0; i + 34 <= n; ++i) {
			if (p[i] == 0x04 && p[i + 1] == 0x20) {
				out.Assign(p + i + 2, 32);
				return true;
			}
			if (p[i] == 0x04 && p[i + 1] == 0x22 && p[i + 2] == 0x04 && p[i + 3] == 0x20) {
				out.Assign(p + i + 4, 32);
				return true;
			}
			if (p[i] == 0x03 && p[i + 1] == 0x21 && p[i + 2] == 0x00) {
				out.Assign(p + i + 3, 32);
				return true;
			}
		}
		return false;
	}

	Safe::String PublicDerToStored(std::span<const CryptoPP::byte> der) {
		return Base64Encode(der.data(), der.size());
	}

	Password PrivateDerToPassword(std::span<const CryptoPP::byte> der) {
		CryptoPP::SecByteBlock block(der.data(), der.size());
		Password pwd = StormByte::Crypto::Engine::KeyPair::PasswordFromSecBlock(block);
		SecureWipe(block);
		return pwd;
	}

	Safe::Vector<CryptoPP::byte> PublicStoredToDer(const Safe::String& stored) {
		return Base64Decode(stored);
	}

	Safe::Vector<CryptoPP::byte> PrivatePasswordToDer(const Secure::Password& pwd) {
		const auto* data = PasswordAccess::Data(pwd);
		const size_t n = PasswordAccess::Size(pwd);
		if (!data || n == 0)
			return {};
		return Safe::Vector<CryptoPP::byte>(data, data + n);
	}

	bool DecryptPkcs8EncryptedDer(
		std::span<const CryptoPP::byte> encDer,
		const Secure::Password& password,
		Safe::Vector<CryptoPP::byte>& outPlainPkcs8
	) noexcept {
		CryptoPP::SecByteBlock salt, iv, key, ciphertext;
		try {
			const unsigned char* pass = PasswordAccess::Data(password);
			const size_t passLen = PasswordAccess::Size(password);
			if (!pass || passLen == 0 || encDer.empty())
				return false;
			CryptoPP::ByteQueue queue;
			queue.Put(encDer.data(), encDer.size());
			CryptoPP::BERSequenceDecoder outer(queue);
			CryptoPP::BERSequenceDecoder algId(outer);
			CryptoPP::OID pbesOid;
			pbesOid.BERDecode(algId);
			if (pbesOid != kOidPBES2)
				return false;
			CryptoPP::BERSequenceDecoder pbes2Params(algId);
			CryptoPP::BERSequenceDecoder kdfSeq(pbes2Params);
			CryptoPP::OID kdfOid;
			kdfOid.BERDecode(kdfSeq);
			if (kdfOid != kOidPBKDF2)
				return false;
			CryptoPP::BERSequenceDecoder pbkdf2Params(kdfSeq);
			CryptoPP::BERDecodeOctetString(pbkdf2Params, salt);
			CryptoPP::Integer iterInt;
			iterInt.BERDecode(pbkdf2Params);
			const unsigned int iterations = static_cast<unsigned int>(iterInt.ConvertToLong());
			if (iterations == 0)
				return false;
			bool useSha256 = false;
			while (!pbkdf2Params.EndReached()) {
				CryptoPP::byte tag = 0;
				pbkdf2Params.Peek(tag);
				if ((tag & 0x1f) == CryptoPP::INTEGER) {
					CryptoPP::Integer kl;
					kl.BERDecode(pbkdf2Params);
					(void)kl;
				} else if (tag == static_cast<CryptoPP::byte>(0x30)) {
					CryptoPP::BERSequenceDecoder prf(pbkdf2Params);
					CryptoPP::OID prfOid;
					prfOid.BERDecode(prf);
					if (prfOid == kOidHmacSha256)
						useSha256 = true;
					prf.SkipAll();
					prf.MessageEnd();
				} else {
					pbkdf2Params.SkipAll();
					break;
				}
			}
			pbkdf2Params.MessageEnd();
			kdfSeq.MessageEnd();
			CryptoPP::BERSequenceDecoder encScheme(pbes2Params);
			CryptoPP::OID cipherOid;
			cipherOid.BERDecode(encScheme);
			size_t keyLen = 32;
			if (cipherOid == kOidAes128Cbc)
				keyLen = 16;
			else if (cipherOid == kOidAes192Cbc)
				keyLen = 24;
			else if (cipherOid == kOidAes256Cbc)
				keyLen = 32;
			else
				return false;
			CryptoPP::BERDecodeOctetString(encScheme, iv);
			encScheme.MessageEnd();
			pbes2Params.MessageEnd();
			algId.MessageEnd();
			CryptoPP::BERDecodeOctetString(outer, ciphertext);
			outer.MessageEnd();
			key.CleanNew(keyLen);
			if (useSha256) {
				CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf;
				pbkdf.DeriveKey(key, key.size(), 0, pass, passLen, salt, salt.size(), iterations);
			} else {
				CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA1> pbkdf;
				pbkdf.DeriveKey(key, key.size(), 0, pass, passLen, salt, salt.size(), iterations);
			}
			CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
			dec.SetKeyWithIV(key, key.size(), iv, iv.size());
			CryptoPP::StreamTransformationFilter filter(dec, nullptr, CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING);
			filter.Put(ciphertext.data(), ciphertext.size());
			filter.MessageEnd();
			outPlainPkcs8.resize(filter.MaxRetrievable());
			filter.Get(outPlainPkcs8.data(), outPlainPkcs8.size());
			SecureWipe(salt);
			SecureWipe(iv);
			SecureWipe(key);
			SecureWipe(ciphertext);
			return !outPlainPkcs8.empty();
		} catch (...) {
			SecureWipe(salt);
			SecureWipe(iv);
			SecureWipe(key);
			SecureWipe(ciphertext);
			SecureWipe(outPlainPkcs8);
			return false;
		}
	}

	bool EncryptPkcs8Der(
		std::span<const CryptoPP::byte> plainPkcs8,
		const Secure::Password& password,
		Safe::Vector<CryptoPP::byte>& outEncDer
	) noexcept {
		CryptoPP::SecByteBlock salt, iv, key, ciphertext;
		try {
			const unsigned char* pass = PasswordAccess::Data(password);
			const size_t passLen = PasswordAccess::Size(password);
			if (!pass || passLen == 0 || plainPkcs8.empty())
				return false;
			salt.CleanNew(16);
			iv.CleanNew(16);
			RNG().GenerateBlock(salt, salt.size());
			RNG().GenerateBlock(iv, iv.size());
			key.CleanNew(32);
			CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf;
			pbkdf.DeriveKey(key, key.size(), 0, pass, passLen, salt, salt.size(), kPkcs8Pbkdf2Iterations);
			CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
			enc.SetKeyWithIV(key, key.size(), iv, iv.size());
			CryptoPP::StreamTransformationFilter filter(enc, nullptr, CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING);
			filter.Put(plainPkcs8.data(), plainPkcs8.size());
			filter.MessageEnd();
			ciphertext.CleanNew(filter.MaxRetrievable());
			filter.Get(ciphertext.data(), ciphertext.size());
			CryptoPP::ByteQueue queue;
			{
				CryptoPP::DERSequenceEncoder outer(queue);
				{
					CryptoPP::DERSequenceEncoder algId(outer);
					kOidPBES2.DEREncode(algId);
					{
						CryptoPP::DERSequenceEncoder pbes2(algId);
						{
							CryptoPP::DERSequenceEncoder kdf(pbes2);
							kOidPBKDF2.DEREncode(kdf);
							{
								CryptoPP::DERSequenceEncoder pbkdf2Params(kdf);
								CryptoPP::DEREncodeOctetString(pbkdf2Params, salt, salt.size());
								CryptoPP::DEREncodeUnsigned(pbkdf2Params, kPkcs8Pbkdf2Iterations);
								{
									CryptoPP::DERSequenceEncoder prf(pbkdf2Params);
									kOidHmacSha256.DEREncode(prf);
									const CryptoPP::byte nullParam[2] = {0x05, 0x00};
									prf.Put(nullParam, 2);
									prf.MessageEnd();
								}
								pbkdf2Params.MessageEnd();
							}
							kdf.MessageEnd();
						}
						{
							CryptoPP::DERSequenceEncoder encScheme(pbes2);
							kOidAes256Cbc.DEREncode(encScheme);
							CryptoPP::DEREncodeOctetString(encScheme, iv, iv.size());
							encScheme.MessageEnd();
						}
						pbes2.MessageEnd();
					}
					algId.MessageEnd();
				}
				CryptoPP::DEREncodeOctetString(outer, ciphertext, ciphertext.size());
				outer.MessageEnd();
			}
			outEncDer.resize(queue.CurrentSize());
			if (!outEncDer.empty())
				queue.Get(outEncDer.data(), outEncDer.size());
			SecureWipe(salt);
			SecureWipe(iv);
			SecureWipe(key);
			SecureWipe(ciphertext);
			return !outEncDer.empty();
		} catch (...) {
			SecureWipe(salt);
			SecureWipe(iv);
			SecureWipe(key);
			SecureWipe(ciphertext);
			outEncDer.clear();
			return false;
		}
	}

	bool TryDecryptPrivateDer(
		Safe::Vector<CryptoPP::byte>& privDer,
		bool wasEncrypted,
		const Password* password
	) noexcept {
		if (!wasEncrypted)
			return true;
		if (!password)
			return false;
		Safe::Vector<CryptoPP::byte> plain;
		WipeOnExit wipePlain([&]() noexcept { SecureWipe(plain); });
		if (!DecryptPkcs8EncryptedDer(privDer, *password, plain))
			return false;
		SecureWipe(privDer);
		privDer = std::move(plain);
		return true;
	}

	bool DerivePublicDerFromPrivate(
		Type type,
		std::span<const CryptoPP::byte> privDer,
		Safe::Vector<CryptoPP::byte>& outPubDer
	) noexcept {
		try {
			CryptoPP::ByteQueue pubQueue;
			switch (type) {
				case Type::RSA: {
					CryptoPP::RSA::PrivateKey priv;
					if (!TryLoadRsaPrivate(privDer, priv))
						return false;
					CryptoPP::RSA::PublicKey pub;
					pub.AssignFrom(priv);
					pub.Save(pubQueue);
					break;
				}
				case Type::DSA: {
					CryptoPP::DSA::PrivateKey priv;
					if (!TryLoadDsaPrivate(privDer, priv))
						return false;
					CryptoPP::DSA::PublicKey pub;
					priv.MakePublicKey(pub);
					pub.Save(pubQueue);
					break;
				}
				case Type::ECC:
				case Type::ECDSA:
				case Type::ECDH: {
					CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey priv;
					if (!TryLoadEcPrivate(privDer, priv))
						return false;
					CryptoPP::ECIES<CryptoPP::ECP>::PublicKey pub;
					priv.MakePublicKey(pub);
					pub.Save(pubQueue);
					break;
				}
				case Type::ED25519: {
					CryptoPP::ArraySource src(privDer.data(), privDer.size(), true);
					CryptoPP::ed25519::Signer signer;
					signer.AccessPrivateKey().Load(src);
					CryptoPP::ed25519::Verifier verifier(signer);
					verifier.GetPublicKey().Save(pubQueue);
					break;
				}
				case Type::X25519: {
					if (privDer.size() == 32) {
						CryptoPP::x25519 agreement;
						CryptoPP::SecByteBlock pub(agreement.PublicKeyLength());
						agreement.GeneratePublicKey(RNG(), privDer.data(), pub.data());
						pubQueue.Put(pub.data(), pub.size());
						StormByte::Crypto::Helpers::SecureWipe(pub);
						break;
					}
					CryptoPP::ArraySource src(privDer.data(), privDer.size(), true);
					CryptoPP::x25519 x;
					x.Load(src);
					x.Save(pubQueue);
					break;
				}
				default:
					return false;
			}
			outPubDer.resize(pubQueue.CurrentSize());
			if (!outPubDer.empty())
				pubQueue.Get(outPubDer.data(), outPubDer.size());
			return !outPubDer.empty();
		} catch (...) {
			return false;
		}
	}

	Generic::PointerType MakeKeyPair(Type type, Safe::String pubStored, StormByte::Safe::Optional<Secure::Password> priv) {
		switch (type) {
			case Type::DSA:
				return DSA::MakePointer<DSA>(pubStored, std::move(priv));
			case Type::ECC:
				return ECC::MakePointer<ECC>(pubStored, std::move(priv));
			case Type::ECDH:
				return ECDH::MakePointer<ECDH>(pubStored, std::move(priv));
			case Type::ECDSA:
				return ECDSA::MakePointer<ECDSA>(pubStored, std::move(priv));
			case Type::ED25519:
				return ED25519::MakePointer<ED25519>(pubStored, std::move(priv));
			case Type::RSA:
				return RSA::MakePointer<RSA>(pubStored, std::move(priv));
			case Type::X25519:
				return X25519::MakePointer<X25519>(pubStored, std::move(priv));
			default:
				return nullptr;
		}
	}

	bool IsEcFamily(Type t) noexcept {
		return t == Type::ECC || t == Type::ECDH || t == Type::ECDSA;
	}

	bool TypesCompatible(Type a, Type b) noexcept {
		if (a == b)
			return true;
		if (IsEcFamily(a) && IsEcFamily(b))
			return true;
		return false;
	}

	Generic::PointerType BuildFromMaterial(
		Safe::Optional<Safe::Vector<CryptoPP::byte>> pubDer,
		Safe::Optional<Safe::Vector<CryptoPP::byte>> privDer,
		Type hint
	) noexcept {
		WipeOnExit wipePrivate([&]() noexcept {
			if (privDer)
				SecureWipe(*privDer);
		});
		try {
			auto isRaw32Vec = [](const Safe::Vector<CryptoPP::byte>& v) noexcept {
				return IsRaw32(v);
			};
			Type type = hint;
			bool typeKnown = false;
			if (privDer && !privDer->empty() && isRaw32Vec(*privDer)) {
				if (pubDer && !pubDer->empty() && !isRaw32Vec(*pubDer)) {
					Type pubType = Type::RSA;
					if (DetectTypeFromDer(*pubDer, pubType) && pubType != Type::X25519)
						return nullptr;
				}
				type = Type::X25519;
				typeKnown = true;
			} else if (privDer && !privDer->empty()) {
				if (DetectTypeFromDer(*privDer, type)) {
					typeKnown = true;
				} else if (pubDer && !pubDer->empty() && DetectTypeFromDer(*pubDer, type)) {
					typeKnown = true;
				} else {
					return nullptr;
				}
			} else if (pubDer && !pubDer->empty()) {
				if (isRaw32Vec(*pubDer)) {
					type = Type::X25519;
					typeKnown = true;
				} else if (!DetectTypeFromDer(*pubDer, type)) {
					return nullptr;
				} else {
					typeKnown = true;
				}
			}
			if (!typeKnown)
				type = hint;
			if (pubDer && !pubDer->empty() && privDer && !privDer->empty()) {
				Type pubType = type;
				Type privType = type;
				const bool pubOk = isRaw32Vec(*pubDer)
					? (pubType = Type::X25519, true)
					: DetectTypeFromDer(*pubDer, pubType);
				const bool privOk = isRaw32Vec(*privDer)
					? (privType = Type::X25519, true)
					: DetectTypeFromDer(*privDer, privType);
				if (pubOk && privOk && !TypesCompatible(pubType, privType))
					return nullptr;
			}
			if (type == Type::X25519) {
				CryptoPP::SecByteBlock privRaw(32), pubRaw(32);
				constexpr CryptoPP::byte oid_x25519[]{
					0x06, 0x03, 0x2B, 0x65, 0x6E
				};
				if (privDer && !privDer->empty()) {
					const bool rawPriv = IsRaw32(*privDer);
					const bool oidPriv = ContainsOid(*privDer, oid_x25519);
					if (rawPriv)
						privRaw.Assign(privDer->data(), 32);
					else if (oidPriv && ExtractRaw32(*privDer, privRaw))
						{ }
					else
						return nullptr;
					if (pubDer && !pubDer->empty()) {
						const bool rawPub = IsRaw32(*pubDer);
						const bool oidPub = ContainsOid(*pubDer, oid_x25519);
						if (rawPub)
							pubRaw.Assign(pubDer->data(), 32);
						else if (oidPub && ExtractRaw32(*pubDer, pubRaw))
							{ }
						else {
							CryptoPP::x25519 ag;
							ag.GeneratePublicKey(RNG(), privRaw, pubRaw);
						}
					} else {
						CryptoPP::x25519 ag;
						ag.GeneratePublicKey(RNG(), privRaw, pubRaw);
					}
					Safe::String pubStored = Base64Encode(pubRaw.data(), pubRaw.size());
					Secure::Password privPwd = PrivateDerToPassword(
						std::span<const CryptoPP::byte>(privRaw.data(), privRaw.size())
					);
					SecureWipe(privRaw);
					SecureWipe(pubRaw);
					return MakeKeyPair(Type::X25519, std::move(pubStored), std::move(privPwd));
				}
				if (pubDer && !pubDer->empty()) {
					const bool rawPub = IsRaw32(*pubDer);
					const bool oidPub = ContainsOid(*pubDer, oid_x25519);
					if (rawPub)
						pubRaw.Assign(pubDer->data(), 32);
					else if (oidPub && ExtractRaw32(*pubDer, pubRaw))
						{ }
					else
						return nullptr;
					Safe::String pubStored = Base64Encode(pubRaw.data(), pubRaw.size());
					SecureWipe(pubRaw);
					return MakeKeyPair(Type::X25519, std::move(pubStored), std::nullopt);
				}
				return nullptr;
			}
			if (type == Type::ECC || type == Type::ECDSA || type == Type::ECDH) {
				if (privDer && !privDer->empty()) {
					try {
						CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey priv;
						if (!TryLoadEcPrivate(*privDer, priv))
							return nullptr;
						auto pkcs8 = EcPrivateToPkcs8Der(priv);
						WipeOnExit wipePkcs8([&]() noexcept { SecureWipe(pkcs8); });
						if (pkcs8.empty())
							return nullptr;
						Secure::Password privPwd = PrivateDerToPassword(
							std::span<const CryptoPP::byte>(pkcs8.data(), pkcs8.size())
						);
						SecureWipe(pkcs8);
						Safe::String pubStored;
						if (pubDer && !pubDer->empty()) {
							pubStored = PublicDerToStored(*pubDer);
						} else {
							CryptoPP::ECIES<CryptoPP::ECP>::PublicKey pub;
							priv.MakePublicKey(pub);
							pubStored = StormByte::Crypto::Engine::KeyPair::SerializeKey(pub);
						}
						return MakeKeyPair(type, std::move(pubStored), std::move(privPwd));
					} catch (...) {
						return nullptr;
					}
				}
				if (pubDer && !pubDer->empty()) {
					try {
						CryptoPP::ArraySource src(pubDer->data(), pubDer->size(), true);
						CryptoPP::ECIES<CryptoPP::ECP>::PublicKey pub;
						pub.Load(src);
						if (!pub.Validate(RNG(), 2))
							return nullptr;
						Safe::String pubStored = PublicDerToStored(*pubDer);
						return MakeKeyPair(type, std::move(pubStored), std::nullopt);
					} catch (...) {
						return nullptr;
					}
				}
				return nullptr;
			}
			StormByte::Safe::Optional<Secure::Password> privPwd;
			if (privDer && !privDer->empty()) {
				try {
					bool ok = false;
					Safe::Vector<CryptoPP::byte> normalized;
					WipeOnExit wipeNormalized([&]() noexcept { SecureWipe(normalized); });
					switch (type) {
						case Type::RSA: {
							CryptoPP::RSA::PrivateKey priv;
							ok = TryLoadRsaPrivate(*privDer, priv);
							if (ok)
								normalized = RsaPrivateToPkcs8Der(priv);
							break;
						}
						case Type::DSA: {
							CryptoPP::DSA::PrivateKey priv;
							ok = TryLoadDsaPrivate(*privDer, priv);
							if (ok)
								normalized = DsaPrivateToPkcs8Der(priv);
							break;
						}
						case Type::ED25519: {
							CryptoPP::ArraySource src(privDer->data(), privDer->size(), true);
							CryptoPP::ed25519::Signer signer;
							signer.AccessPrivateKey().Load(src);
							ok = true;
							normalized.assign(privDer->begin(), privDer->end());
							break;
						}
						default:
							ok = false;
							break;
					}
					if (!ok || normalized.empty())
						return nullptr;
					privPwd = PrivateDerToPassword(
						std::span<const CryptoPP::byte>(normalized.data(), normalized.size())
					);
					SecureWipe(normalized);
				} catch (...) {
					return nullptr;
				}
			}
			Safe::String pubStored;
			if (pubDer && !pubDer->empty()) {
				pubStored = PublicDerToStored(*pubDer);
			} else if (privDer && !privDer->empty()) {
				Safe::Vector<CryptoPP::byte> derived;
				if (!DerivePublicDerFromPrivate(type, *privDer, derived))
					return nullptr;
				pubStored = PublicDerToStored(derived);
			} else {
				return nullptr;
			}
			return MakeKeyPair(type, std::move(pubStored), std::move(privPwd));
		} catch (...) {
			return nullptr;
		}
	}

	Generic::PointerType LoadFromBytes(
		std::span<const CryptoPP::byte> data,
		const Password* password
	) {
		if (data.empty())
			return nullptr;
		if (IsPemText(data)) {
			Safe::String text(data.begin(), data.end());
			WipeOnExit wipeText([&]() noexcept { SecureWipe(text); });
			auto blocks = PemDecodeAll(data);
			if (blocks.empty())
				return nullptr;
			Safe::Optional<Safe::Vector<CryptoPP::byte>> pubDer;
			Safe::Optional<Safe::Vector<CryptoPP::byte>> privDer;
			WipeOnExit wipePrivate([&]() noexcept {
				if (privDer)
					SecureWipe(*privDer);
			});
			WipeOnExit wipeBlocks([&]() noexcept {
				for (auto& block : blocks)
					SecureWipe(block.second);
			});
			bool privEncrypted = false;
			Type hint = Type::RSA;
			for (const auto& b : blocks) {
				if (LabelIsPublic(b.first)) {
					pubDer = b.second;
					DetectTypeFromDer(b.second, hint);
				} else if (LabelIsPrivate(b.first)) {
					privEncrypted = LabelIsEncrypted(b.first, text);
					if (privDer)
						SecureWipe(*privDer);
					privDer = b.second;
					if (!privEncrypted)
						DetectTypeFromDer(b.second, hint);
				}
			}
			if (privDer) {
				if (!TryDecryptPrivateDer(*privDer, privEncrypted, password))
					return nullptr;
				if (privEncrypted)
					DetectTypeFromDer(*privDer, hint);
			}
			return BuildFromMaterial(std::move(pubDer), std::move(privDer), hint);
		}
		Safe::Vector<CryptoPP::byte> copy(data.begin(), data.end());
		WipeOnExit wipeCopy([&]() noexcept { SecureWipe(copy); });
		if (password) {
			Safe::Vector<CryptoPP::byte> plain;
			WipeOnExit wipePlain([&]() noexcept { SecureWipe(plain); });
			if (!DecryptPkcs8EncryptedDer(copy, *password, plain))
				return nullptr;
			SecureWipe(copy);
			copy = std::move(plain);
		}
		Type hint = Type::RSA;
		DetectTypeFromDer(copy, hint);
		auto asPriv = BuildFromMaterial(std::nullopt, copy, hint);
		if (asPriv)
			return asPriv;
		Safe::Vector<CryptoPP::byte> copyPub(data.begin(), data.end());
		WipeOnExit wipeCopyPublic([&]() noexcept { SecureWipe(copyPub); });
		DetectTypeFromDer(copyPub, hint);
		return BuildFromMaterial(std::move(copyPub), std::nullopt, hint);
	}

	std::string_view ExtensionFor(StorageFormat format, bool isPublic) {
		if (format == StorageFormat::DER)
			return isPublic ? ".pub.der" : ".der";
		return isPublic ? ".pub.pem" : ".pem";
	}

	bool WritePublicFile(const std::filesystem::path& path, const Safe::String& pubStored, StorageFormat format) {
		auto der = PublicStoredToDer(pubStored);
		if (der.empty())
			return false;
		if (format == StorageFormat::DER)
			return WriteFileBytes(path, der.data(), der.size());
		const Safe::String pem = PemEncode("PUBLIC KEY", der.data(), der.size());
		return WriteFileBytes(path, reinterpret_cast<const CryptoPP::byte*>(pem.data()), static_cast<size_t>(pem.size()));
	}

	bool WritePrivateFile(const std::filesystem::path& path, const Secure::Password& priv, StorageFormat format) {
		auto der = PrivatePasswordToDer(priv);
		WipeOnExit wipeDer([&]() noexcept { SecureWipe(der); });
		if (der.empty())
			return false;
		bool ok = false;
		if (format == StorageFormat::DER) {
			ok = WriteFileBytes(path, der.data(), der.size());
		} else {
			auto pem = PemEncode("PRIVATE KEY", der.data(), der.size());
			WipeOnExit wipePem([&]() noexcept { SecureWipe(pem); });
			ok = WriteFileBytes(path, reinterpret_cast<const CryptoPP::byte*>(pem.data()), static_cast<size_t>(pem.size()));
		}
		SecureWipe(der);
		if (ok)
			RestrictToOwner(path);
		return ok;
	}

	bool WritePrivateFileEncrypted(
		const std::filesystem::path& path,
		const Secure::Password& privMaterial,
		const Secure::Password& encryptPassword,
		StorageFormat format
	) {
		auto plainDer = PrivatePasswordToDer(privMaterial);
		WipeOnExit wipePlain([&]() noexcept { SecureWipe(plainDer); });
		if (plainDer.empty())
			return false;
		Safe::Vector<CryptoPP::byte> encDer;
		WipeOnExit wipeEncrypted([&]() noexcept { SecureWipe(encDer); });
		const bool encrypted = EncryptPkcs8Der(plainDer, encryptPassword, encDer);
		SecureWipe(plainDer);
		if (!encrypted || encDer.empty())
			return false;
		bool ok = false;
		if (format == StorageFormat::DER) {
			ok = WriteFileBytes(path, encDer.data(), encDer.size());
		} else {
			const Safe::String pem = PemEncode("ENCRYPTED PRIVATE KEY", encDer.data(), encDer.size());
			ok = WriteFileBytes(path, reinterpret_cast<const CryptoPP::byte*>(pem.data()), static_cast<size_t>(pem.size()));
		}
		SecureWipe(encDer);
		if (ok)
			RestrictToOwner(path);
		return ok;
	}
}

Generic::Generic(enum Type type, StormByte::Safe::String public_key, StormByte::Safe::Optional<Secure::Password> private_key):
	m_type(type),
	m_public_key(std::move(public_key)),
	m_private_key() {
	if (private_key.has_value())
		m_private_key.emplace(private_key.value());
}

Generic::Generic(const Generic& other) = default;

Generic::Generic(Generic&& other) noexcept = default;

Generic::~Generic() noexcept = default;

Generic& Generic::operator=(const Generic& other) = default;

Generic& Generic::operator=(Generic&& other) noexcept = default;

bool Generic::Save(PathView directoryView, std::string_view baseName, StorageFormat format) const noexcept {
	try {
		const std::filesystem::path directory{directoryView};
		if (!std::filesystem::exists(directory) || !std::filesystem::is_directory(directory))
			return false;
		if (m_public_key.empty())
			return false;
		Safe::String pubName(baseName);
		pubName += ExtensionFor(format, true);
		const auto pubPath = directory / std::filesystem::path(static_cast<std::string_view>(pubName));
		if (!WritePublicFile(pubPath, m_public_key, format))
			return false;
		if (m_private_key.has_value()) {
			Safe::String privName(baseName);
			privName += ExtensionFor(format, false);
			const auto privPath = directory / std::filesystem::path(static_cast<std::string_view>(privName));
			const Secure::Password privateKey = *m_private_key;
			if (!WritePrivateFile(privPath, privateKey, format))
				return false;
		}

		return true;
	} catch (...) {
		return false;
	}
}

bool Generic::Save(
	PathView directoryView,
	std::string_view baseName,
	const Secure::Password& encryptPassword,
	StorageFormat format
) const noexcept {
	try {
		const std::filesystem::path directory{directoryView};
		if (!std::filesystem::exists(directory) || !std::filesystem::is_directory(directory))
			return false;
		if (m_public_key.empty() || !m_private_key.has_value())
			return false;
		Safe::String pubName(baseName);
		pubName += ExtensionFor(format, true);
		const auto pubPath = directory / std::filesystem::path(static_cast<std::string_view>(pubName));
		if (!WritePublicFile(pubPath, m_public_key, format))
			return false;
		Safe::String privName(baseName);
		privName += ExtensionFor(format, false);
		const auto privPath = directory / std::filesystem::path(static_cast<std::string_view>(privName));
		const Secure::Password privateKey = *m_private_key;
		return WritePrivateFileEncrypted(privPath, privateKey, encryptPassword, format);
	} catch (...) {
		return false;
	}
}

bool Generic::SavePublic(PathView filePathView, StorageFormat format) const noexcept {
	try {
		const std::filesystem::path filePath{filePathView};
		if (m_public_key.empty())
			return false;
		return WritePublicFile(filePath, m_public_key, format);
	} catch (...) {
		return false;
	}
}

bool Generic::SavePrivate(PathView filePathView, StorageFormat format) const noexcept {
	try {
		const std::filesystem::path filePath{filePathView};
		if (!m_private_key.has_value())
			return false;
		const Secure::Password privateKey = *m_private_key;
		return WritePrivateFile(filePath, privateKey, format);
	} catch (...) {
		return false;
	}
}

bool Generic::SavePrivate(
	PathView filePathView,
	const Secure::Password& encryptPassword,
	StorageFormat format
) const noexcept {
	try {
		const std::filesystem::path filePath{filePathView};
		if (!m_private_key.has_value())
			return false;
		const Secure::Password privateKey = *m_private_key;
		return WritePrivateFileEncrypted(filePath, privateKey, encryptPassword, format);
	} catch (...) {
		return false;
	}
}

namespace StormByte::Crypto::KeyPair {
	Generic::PointerType Create(Type type, unsigned short bits) noexcept {
		switch (type) {
			case Type::DSA:
				return DSA::Generate(bits);
			case Type::ECC:
				return ECC::Generate(bits);
			case Type::ECDH:
				return ECDH::Generate(bits);
			case Type::ECDSA:
				return ECDSA::Generate(bits);
			case Type::ED25519:
				return ED25519::Generate(bits);
			case Type::RSA:
				return RSA::Generate(bits);
			case Type::X25519:
				return X25519::Generate(bits);
			default:
				return nullptr;
		}
	}

	Generic::PointerType Load(PathView publicKeyPathView, PathView privateKeyPathView) noexcept {
		try {
			const std::filesystem::path publicKeyPath{publicKeyPathView};
			const std::filesystem::path privateKeyPath{privateKeyPathView};
			Safe::Optional<Safe::Vector<CryptoPP::byte>> pubDer;
			Safe::Optional<Safe::Vector<CryptoPP::byte>> privDer;
			bool privEncrypted = false;
			WipeOnExit wipePrivate([&]() noexcept {
				if (privDer)
					SecureWipe(*privDer);
			});
			if (!publicKeyPath.empty() && std::filesystem::exists(publicKeyPath)) {
				auto bytes = ReadFileBytes(publicKeyPath);
				WipeOnExit wipeBytes([&]() noexcept { SecureWipe(bytes); });
				if (bytes.empty())
					return nullptr;
				if (IsPemText(bytes)) {
					auto blocks = PemDecodeAll(bytes);
					WipeOnExit wipeBlocks([&]() noexcept {
						for (auto& block : blocks)
							SecureWipe(block.second);
					});
					for (auto& b : blocks) {
						if (LabelIsPublic(b.first)) {
							pubDer = std::move(b.second);
							break;
						}
					}
					if (!pubDer)
						return nullptr;
				} else {
					pubDer = std::move(bytes);
				}
			}
			if (!privateKeyPath.empty() && std::filesystem::exists(privateKeyPath)) {
				auto bytes = ReadFileBytes(privateKeyPath);
				WipeOnExit wipeBytes([&]() noexcept { SecureWipe(bytes); });
				if (bytes.empty())
					return nullptr;
				if (IsPemText(bytes)) {
					Safe::String text(bytes.begin(), bytes.end());
					WipeOnExit wipeText([&]() noexcept { SecureWipe(text); });
					auto blocks = PemDecodeAll(bytes);
					WipeOnExit wipeBlocks([&]() noexcept {
						for (auto& block : blocks)
							SecureWipe(block.second);
					});
					for (auto& b : blocks) {
						if (LabelIsPrivate(b.first)) {
							privEncrypted = LabelIsEncrypted(b.first, text);
							privDer = std::move(b.second);
							break;
						}
					}
					if (!privDer)
						return nullptr;
				} else {
					privDer = std::move(bytes);
				}
			}
			if (privEncrypted)
				return nullptr;
			Type hint = Type::RSA;
			if (pubDer)
				DetectTypeFromDer(*pubDer, hint);
			else if (privDer)
				DetectTypeFromDer(*privDer, hint);
			return BuildFromMaterial(std::move(pubDer), std::move(privDer), hint);
		} catch (...) {
			return nullptr;
		}
	}

	Generic::PointerType Load(
		PathView publicKeyPathView,
		PathView privateKeyPathView,
		const Secure::Password& password
	) noexcept {
		try {
			const std::filesystem::path publicKeyPath{publicKeyPathView};
			const std::filesystem::path privateKeyPath{privateKeyPathView};
			Safe::Optional<Safe::Vector<CryptoPP::byte>> pubDer;
			Safe::Optional<Safe::Vector<CryptoPP::byte>> privDer;
			bool privEncrypted = false;
			WipeOnExit wipePrivate([&]() noexcept {
				if (privDer)
					SecureWipe(*privDer);
			});
			if (!publicKeyPath.empty() && std::filesystem::exists(publicKeyPath)) {
				auto bytes = ReadFileBytes(publicKeyPath);
				WipeOnExit wipeBytes([&]() noexcept { SecureWipe(bytes); });
				if (bytes.empty())
					return nullptr;
				if (IsPemText(bytes)) {
					auto blocks = PemDecodeAll(bytes);
					WipeOnExit wipeBlocks([&]() noexcept {
						for (auto& block : blocks)
							SecureWipe(block.second);
					});
					for (auto& b : blocks) {
						if (LabelIsPublic(b.first)) {
							pubDer = std::move(b.second);
							break;
						}
					}
					if (!pubDer)
						return nullptr;
				} else {
					pubDer = std::move(bytes);
				}
			}
			if (!privateKeyPath.empty() && std::filesystem::exists(privateKeyPath)) {
				auto bytes = ReadFileBytes(privateKeyPath);
				WipeOnExit wipeBytes([&]() noexcept { SecureWipe(bytes); });
				if (bytes.empty())
					return nullptr;
				if (IsPemText(bytes)) {
					Safe::String text(bytes.begin(), bytes.end());
					WipeOnExit wipeText([&]() noexcept { SecureWipe(text); });
					auto blocks = PemDecodeAll(bytes);
					WipeOnExit wipeBlocks([&]() noexcept {
						for (auto& block : blocks)
							SecureWipe(block.second);
					});
					for (auto& b : blocks) {
						if (LabelIsPrivate(b.first)) {
							privEncrypted = LabelIsEncrypted(b.first, text);
							privDer = std::move(b.second);
							break;
						}
					}
					if (!privDer)
						return nullptr;
				} else {
					privDer = std::move(bytes);
					privEncrypted = true;
				}
			}
			if (!privDer)
				return nullptr;
			if (!TryDecryptPrivateDer(*privDer, privEncrypted, &password)) {
				if (privEncrypted)
					return nullptr;
			}
			Type hint = Type::RSA;
			if (pubDer)
				DetectTypeFromDer(*pubDer, hint);
			else
				DetectTypeFromDer(*privDer, hint);
			return BuildFromMaterial(std::move(pubDer), std::move(privDer), hint);
		} catch (...) {
			return nullptr;
		}
	}

	Generic::PointerType Load(PathView pathView) noexcept {
		try {
			const std::filesystem::path path{pathView};
			if (path.empty() || !std::filesystem::exists(path))
				return nullptr;
			if (std::filesystem::is_directory(path))
				return nullptr;
			auto bytes = ReadFileBytes(path);
			WipeOnExit wipeBytes([&]() noexcept { SecureWipe(bytes); });
			return LoadFromBytes(bytes, nullptr);
		} catch (...) {
			return nullptr;
		}
	}

	Generic::PointerType Load(PathView pathView, const Secure::Password& password) noexcept {
		try {
			const std::filesystem::path path{pathView};
			if (path.empty() || !std::filesystem::exists(path))
				return nullptr;
			if (std::filesystem::is_directory(path))
				return nullptr;
			auto bytes = ReadFileBytes(path);
			WipeOnExit wipeBytes([&]() noexcept { SecureWipe(bytes); });
			return LoadFromBytes(bytes, &password);
		} catch (...) {
			return nullptr;
		}
	}
}
