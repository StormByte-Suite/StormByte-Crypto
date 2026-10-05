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
#include <StormByte/crypto/keypair/ecdh.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/crypto/random.hxx>

#include <eccrypto.h>
#include <oids.h>

using namespace StormByte::Crypto::KeyPair;

ECDH::ECDH(std::string_view publicKey, StormByte::Safe::Optional<Secure::Password> privateKey):
	Generic(Type::ECDH, StormByte::Safe::String{publicKey}, std::move(privateKey)) {}

ECDH::~ECDH() noexcept = default;

ECDH::PointerType ECDH::Clone() const {
	return MakePointer<ECDH>(*this);
}

ECDH::PointerType ECDH::Move() {
	return MakePointer<ECDH>(std::move(*this));
}

ECDH::PointerType ECDH::Generate(unsigned short bits) noexcept {
	try {
		CryptoPP::OID curve;
		switch (bits) {
			case 256:
				curve = CryptoPP::ASN1::secp256r1();
				break;
			case 384:
				curve = CryptoPP::ASN1::secp384r1();
				break;
			case 521:
				curve = CryptoPP::ASN1::secp521r1();
				break;
			default:
				return nullptr;
		}

		CryptoPP::ECDH<CryptoPP::ECP>::Domain domain(curve);
		CryptoPP::SecByteBlock privRaw(domain.PrivateKeyLength());
		CryptoPP::SecByteBlock pubRaw(domain.PublicKeyLength());
		domain.GenerateKeyPair(RNG(), privRaw, pubRaw);
		CryptoPP::Integer x(privRaw.data(), privRaw.size());
		CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey privateKey;
		privateKey.Initialize(curve, x);
		if (!privateKey.Validate(RNG(), 2)) {
			Helpers::SecureWipe(privRaw);
			Helpers::SecureWipe(pubRaw);
			return nullptr;
		}

		CryptoPP::ECIES<CryptoPP::ECP>::PublicKey publicKey;
		privateKey.MakePublicKey(publicKey);
		Helpers::SecureWipe(privRaw);
		Helpers::SecureWipe(pubRaw);
		return MakePointer<ECDH>(
			Engine::KeyPair::SerializeKey(publicKey),
			Engine::KeyPair::SerializeKeyBinary(privateKey)
		);
	} catch (...) {
		return nullptr;
	}
}
