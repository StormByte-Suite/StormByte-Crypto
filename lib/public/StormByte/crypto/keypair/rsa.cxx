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
#include <StormByte/crypto/keypair/rsa.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/crypto/random.hxx>

#include <rsa.h>

using namespace StormByte::Crypto::KeyPair;

RSA::RSA(std::string_view publicKey, StormByte::Safe::Optional<Secure::Password> privateKey):
	Generic(Type::RSA, StormByte::Safe::String{publicKey}, std::move(privateKey)) {}

RSA::~RSA() noexcept = default;

RSA::PointerType RSA::Clone() const {
	return MakePointer<RSA>(*this);
}

RSA::PointerType RSA::Move() {
	return MakePointer<RSA>(std::move(*this));
}

RSA::PointerType RSA::Generate(unsigned short bits) noexcept {
	if (bits != 1024 && bits != 2048 && bits != 3072 && bits != 4096)
		return nullptr;
	try {
		CryptoPP::RSA::PrivateKey privateKey;
		privateKey.GenerateRandomWithKeySize(RNG(), bits);
		CryptoPP::RSA::PublicKey publicKey;
		publicKey.AssignFrom(privateKey);
		return MakePointer<RSA>(
			Engine::KeyPair::SerializeKey(publicKey),
			Engine::KeyPair::SerializeKeyBinary(privateKey)
		);
	} catch (...) {
		return nullptr;
	}
}
