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

#include <StormByte/crypto/engine/signer/api.hxx>
#include <StormByte/crypto/signer/dsa.hxx>

#include <dsa.h>
#include <string_view>

using namespace StormByte::Crypto::Signer;
using StormByte::Buffer::WriteOnly;
using StormByte::Buffer::Consumer;

DSA::~DSA() noexcept = default;

Generic::PointerType DSA::Clone() const noexcept {
	return MakePointer<DSA>(*this);
}

Generic::PointerType DSA::Move() noexcept {
	return MakePointer<DSA>(std::move(*this));
}

bool DSA::DoSign(std::span<const std::byte> data, WriteOnly& output) const noexcept {
	return Engine::Signer::Sign<CryptoPP::DSA::Signer, CryptoPP::DSA::PrivateKey>(
		data, m_keypair, output);
}

Consumer DSA::DoSign(Consumer consumer, ReadMode mode) const noexcept {
	return Engine::Signer::Sign<CryptoPP::DSA::Signer, CryptoPP::DSA::PrivateKey>(
		consumer, m_keypair, mode);
}

bool DSA::DoVerify(std::span<const std::byte> data, std::string_view signature) const noexcept {
	return Engine::Signer::Verify<CryptoPP::DSA::Verifier, CryptoPP::DSA::PublicKey>(
		data, signature, m_keypair);
}

bool DSA::DoVerify(Consumer consumer, std::string_view signature, ReadMode mode) const noexcept {
	return Engine::Signer::Verify<CryptoPP::DSA::Verifier, CryptoPP::DSA::PublicKey>(
		consumer, signature, m_keypair, mode);
}
