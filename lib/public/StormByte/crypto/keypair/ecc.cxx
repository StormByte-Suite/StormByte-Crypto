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
#include <StormByte/crypto/keypair/ecc.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/crypto/random.hxx>

#include <eccrypto.h>
#include <oids.h>

using namespace StormByte::Crypto::KeyPair;

ECC::ECC(std::string_view publicKey, StormByte::Safe::Optional<Secure::Password> privateKey):
	Generic(Type::ECC, StormByte::Safe::String{publicKey}, std::move(privateKey)) {}

ECC::~ECC() noexcept = default;

ECC::PointerType ECC::Clone() const {
	return MakePointer<ECC>(*this);
}

ECC::PointerType ECC::Move() {
	return MakePointer<ECC>(std::move(*this));
}

ECC::PointerType ECC::Generate(unsigned short bits) noexcept {
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

		CryptoPP::ECIES<CryptoPP::ECP>::Decryptor decryptor(RNG(), curve);
		CryptoPP::ECIES<CryptoPP::ECP>::Encryptor encryptor(decryptor);
		return MakePointer<ECC>(
			Engine::KeyPair::SerializeKey(encryptor.GetPublicKey()),
			Engine::KeyPair::SerializeKeyBinary(decryptor.GetPrivateKey())
		);
	} catch (...) {
		return nullptr;
	}
}
