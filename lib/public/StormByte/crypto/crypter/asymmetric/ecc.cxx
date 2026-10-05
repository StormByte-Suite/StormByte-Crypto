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

#include <StormByte/crypto/crypter/asymmetric/ecc.hxx>
#include <StormByte/crypto/engine/crypter/asymmetric/api.hxx>
#include <eccrypto.h>

using ECIES = CryptoPP::ECIES<CryptoPP::ECP>;
using namespace StormByte::Crypto::Crypter;

ECC::~ECC() noexcept = default;

Generic::PointerType ECC::Clone() const noexcept {
	return MakePointer<ECC>(*this);
}

Generic::PointerType ECC::Move() noexcept {
	return MakePointer<ECC>(std::move(*this));
}

bool ECC::DoEncrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return Engine::Crypter::Asymmetric::EncryptAsymmetric<ECIES::Encryptor, ECIES::PublicKey>(input, m_keypair, output);
}

StormByte::Buffer::Consumer ECC::DoEncrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return Engine::Crypter::Asymmetric::EncryptAsymmetric<ECIES::Encryptor, ECIES::PublicKey>(consumer, m_keypair, mode);
}

bool ECC::DoDecrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
	return Engine::Crypter::Asymmetric::DecryptAsymmetric<ECIES::Decryptor, ECIES::PrivateKey>(input, m_keypair, output);
}

StormByte::Buffer::Consumer ECC::DoDecrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept {
	return Engine::Crypter::Asymmetric::DecryptAsymmetric<ECIES::Decryptor, ECIES::PrivateKey>(consumer, m_keypair, mode);
}
