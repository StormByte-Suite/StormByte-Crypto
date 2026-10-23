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

#include <StormByte/crypto/crypter/symmetric/aes.hxx>
#include <StormByte/crypto/crypter/symmetric/aes_gcm.hxx>
#include <StormByte/crypto/crypter/symmetric/camellia.hxx>
#include <StormByte/crypto/crypter/symmetric/chachapoly.hxx>
#include <StormByte/crypto/crypter/symmetric/generic.hxx>
#include <StormByte/crypto/crypter/symmetric/serpent.hxx>
#include <StormByte/crypto/crypter/symmetric/twofish.hxx>
#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/rng.hxx>
#include <StormByte/crypto/secure/password.hxx>

using namespace StormByte::Crypto::Crypter;
using StormByte::Crypto::Helpers::SecureWipe;

Symmetric::~Symmetric() noexcept = default;

StormByte::Crypto::Secure::Password Symmetric::RandomPassword(std::size_t length) noexcept {
	CryptoPP::SecByteBlock raw(length);
	Randomize({raw.data(), raw.size()});
	StormByte::Crypto::Secure::Password result(raw.data(), StormByte::ByteSize{raw.size()});
	SecureWipe(raw);
	return result;
}

namespace StormByte::Crypto::Crypter {
	Generic::PointerType Create(enum Type type, StormByte::Crypto::Secure::Password password) noexcept {
		switch (type) {
			case Type::AES:
				return AES::MakePointer<AES>(std::move(password));
			case Type::AES_GCM:
				return AES_GCM::MakePointer<AES_GCM>(std::move(password));
			case Type::ChaChaPoly:
				return ChaChaPoly::MakePointer<ChaChaPoly>(std::move(password));
			case Type::Camellia:
				return Camellia::MakePointer<Camellia>(std::move(password));
			case Type::Serpent:
				return Serpent::MakePointer<Serpent>(std::move(password));
			case Type::TwoFish:
				return TwoFish::MakePointer<TwoFish>(std::move(password));
			default:
				return nullptr;
		}
	}
}
