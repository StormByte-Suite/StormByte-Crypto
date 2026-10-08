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

#include <StormByte/crypto/engine/keypair/api.hxx>
#include <StormByte/crypto/engine/secret/details.hxx>
#include <StormByte/crypto/helpers/password_view.hxx>
#include <StormByte/crypto/random.hxx>

#include <eccrypto.h>
#include <oids.h>
#include <queue.h>
#include <xed25519.h>

using StormByte::Crypto::Helpers::PasswordAccess;
using StormByte::Crypto::Secure::Password;
using StormByte::Crypto::RNG;

namespace StormByte::Crypto::Engine::Secret {
	static void SecureWipe(CryptoPP::SecByteBlock& block) noexcept {
		CryptoPP::SecureWipeBuffer(block.data(), block.size());
	}

	static CryptoPP::OID CurveFromBits(unsigned short bits) noexcept {
		switch (bits) {
			case 256: return CryptoPP::ASN1::secp256r1();
			case 384: return CryptoPP::ASN1::secp384r1();
			case 521: return CryptoPP::ASN1::secp521r1();
			default:  return CryptoPP::OID();
		}
	}

	static bool ExtractX25519Raw32(const CryptoPP::SecByteBlock& in, CryptoPP::SecByteBlock& out) noexcept {
		if (in.size() == 32) {
			out.Assign(in.data(), 32);
			return true;
		}

		const CryptoPP::byte* data = in.data();
		const std::size_t length = in.size();
		for (std::size_t offset = 0; offset < length && length - offset >= 34; ++offset) {
			if (data[offset] == 0x04 && data[offset + 1] == 0x20) {
				out.Assign(data + offset + 2, 32);
				return true;
			}

			if (length - offset >= 35 && data[offset] == 0x03 && data[offset + 1] == 0x21 && data[offset + 2] == 0x00) {
				out.Assign(data + offset + 3, 32);
				return true;
			}

			if (length - offset >= 36 && data[offset] == 0x04 && data[offset + 1] == 0x22 && data[offset + 2] == 0x04 && data[offset + 3] == 0x20) {
				out.Assign(data + offset + 4, 32);
				return true;
			}
		}

		return false;
	}

	Safe::Optional<Secure::Password> ECDHShare(
		const Secure::Password& privateKey,
		std::string_view peerPublicKeyBase64,
		unsigned short bits) {
		CryptoPP::SecByteBlock priv;
		CryptoPP::SecByteBlock pub;
		CryptoPP::SecByteBlock secret;
		try {
			const CryptoPP::OID curve = CurveFromBits(bits);
			if (curve.Empty())
				return std::nullopt;

			CryptoPP::ECDH<CryptoPP::ECP>::Domain domain(curve);

			const unsigned char* privPtr = PasswordAccess::Data(privateKey);
			const std::size_t privLen = PasswordAccess::Size(privateKey);
			if (!privPtr || privLen == 0)
				return std::nullopt;

			priv.Assign(privPtr, privLen);
			pub = KeyPair::DecodeSecBlockBase64(peerPublicKeyBase64);

			if (priv.size() == domain.PrivateKeyLength()
				&& pub.size() == domain.PublicKeyLength()) {
				secret.CleanNew(domain.AgreedValueLength());
				const bool ok = domain.Agree(secret, priv, pub);
				SecureWipe(priv);
				SecureWipe(pub);
				if (!ok) {
					SecureWipe(secret);
					return std::nullopt;
				}

				Password out(secret.data(), StormByte::ByteSize{secret.size()});
				SecureWipe(secret);
				return out;
			}

			CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey privKey;
			{
				CryptoPP::ArraySource src(privPtr, privLen, true);
				privKey.Load(src);
				if (!privKey.Validate(RNG(), 2)) {
					SecureWipe(priv);
					SecureWipe(pub);
					return std::nullopt;
				}
			}

			CryptoPP::ECIES<CryptoPP::ECP>::PublicKey pubKey;
			{
				CryptoPP::SecByteBlock pubDer = pub;
				if (pubDer.empty()) {
					SecureWipe(priv);
					return std::nullopt;
				}

				CryptoPP::ArraySource src(pubDer.data(), pubDer.size(), true);
				pubKey.Load(src);
				if (!pubKey.Validate(RNG(), 2)) {
					SecureWipe(priv);
					SecureWipe(pub);
					SecureWipe(pubDer);
					return std::nullopt;
				}

				SecureWipe(pubDer);
			}

			const std::size_t privLenRaw = domain.PrivateKeyLength();
			const std::size_t pubLenRaw = domain.PublicKeyLength();
			CryptoPP::SecByteBlock privRaw(privLenRaw);
			CryptoPP::SecByteBlock pubRaw(pubLenRaw);

			CryptoPP::Integer exponent = privKey.GetPrivateExponent();
			exponent.Encode(privRaw.data(), privLenRaw);

			CryptoPP::ECP::Point point = pubKey.GetPublicElement();
			const std::size_t coordLen = (pubLenRaw - 1) / 2;
			pubRaw[0] = 0x04;
			point.x.Encode(pubRaw.data() + 1, coordLen);
			point.y.Encode(pubRaw.data() + 1 + coordLen, coordLen);

			SecureWipe(priv);
			SecureWipe(pub);

			secret.CleanNew(domain.AgreedValueLength());
			bool ok = domain.Agree(secret, privRaw, pubRaw);
			if (!ok)
				ok = domain.Agree(secret, pubRaw, privRaw);

			SecureWipe(privRaw);
			SecureWipe(pubRaw);

			if (!ok) {
				SecureWipe(secret);
				return std::nullopt;
			}

			Password out(secret.data(), StormByte::ByteSize{secret.size()});
			SecureWipe(secret);
			return out;
		} catch (...) {
			SecureWipe(priv);
			SecureWipe(pub);
			SecureWipe(secret);
			return std::nullopt;
		}
	}

	Safe::Optional<Secure::Password> X25519Share(
		const Secure::Password& privateKey,
		std::string_view peerPublicKeyBase64) {
		CryptoPP::SecByteBlock privIn;
		CryptoPP::SecByteBlock pubIn;
		CryptoPP::SecByteBlock priv;
		CryptoPP::SecByteBlock pub;
		CryptoPP::SecByteBlock secret;
		try {
			const unsigned char* privPtr = PasswordAccess::Data(privateKey);
			const std::size_t privLen = PasswordAccess::Size(privateKey);
			if (!privPtr || privLen == 0)
				return std::nullopt;

			privIn.Assign(privPtr, privLen);
			pubIn = KeyPair::DecodeSecBlockBase64(peerPublicKeyBase64);

			if (!ExtractX25519Raw32(privIn, priv) || !ExtractX25519Raw32(pubIn, pub)) {
				SecureWipe(privIn);
				SecureWipe(pubIn);
				return std::nullopt;
			}

			SecureWipe(privIn);
			SecureWipe(pubIn);

			CryptoPP::x25519 agreement;
			secret.CleanNew(agreement.AgreedValueLength());
			const bool ok = agreement.Agree(secret, priv, pub);

			SecureWipe(priv);
			SecureWipe(pub);

			if (!ok) {
				SecureWipe(secret);
				return std::nullopt;
			}

			Password out(secret.data(), StormByte::ByteSize{secret.size()});
			SecureWipe(secret);
			return out;
		} catch (...) {
			SecureWipe(privIn);
			SecureWipe(pubIn);
			SecureWipe(priv);
			SecureWipe(pub);
			SecureWipe(secret);
			return std::nullopt;
		}
	}
}
