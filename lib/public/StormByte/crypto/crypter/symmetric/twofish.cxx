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

#include <StormByte/crypto/crypter/symmetric/twofish.hxx>
#include <StormByte/crypto/engine/crypter/symmetric/api.hxx>
#include <modes.h>
#include <twofish.h>

using namespace StormByte::Crypto::Crypter;

TwoFish::~TwoFish() noexcept = default;

Generic::PointerType TwoFish::Clone() const noexcept {
	return MakePointer<TwoFish>(*this);
}

Generic::PointerType TwoFish::Move() noexcept {
	return MakePointer<TwoFish>(std::move(*this));
}

bool TwoFish::DoEncrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return Engine::Crypter::Symmetric::EncryptCBC<CryptoPP::Twofish, CryptoPP::CBC_Mode<CryptoPP::Twofish>::Encryption, CryptoPP::SHA256>(input, m_password, output, 16, CryptoPP::Twofish::BLOCKSIZE);
}

StormByte::Buffer::Consumer TwoFish::DoEncrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return Engine::Crypter::Symmetric::EncryptCBC<CryptoPP::Twofish, CryptoPP::CBC_Mode<CryptoPP::Twofish>::Encryption, CryptoPP::SHA256>(consumer, m_password, mode, 16, CryptoPP::Twofish::BLOCKSIZE);
}

bool TwoFish::DoDecrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return Engine::Crypter::Symmetric::DecryptCBC<CryptoPP::Twofish, CryptoPP::CBC_Mode<CryptoPP::Twofish>::Decryption, CryptoPP::SHA256>(input, m_password, output, 16, CryptoPP::Twofish::BLOCKSIZE);
}

StormByte::Buffer::Consumer TwoFish::DoDecrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return Engine::Crypter::Symmetric::DecryptCBC<CryptoPP::Twofish, CryptoPP::CBC_Mode<CryptoPP::Twofish>::Decryption, CryptoPP::SHA256>(consumer, m_password, mode, 16, CryptoPP::Twofish::BLOCKSIZE);
}
