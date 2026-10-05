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

#include <StormByte/crypto/hasher/blake2b.hxx>
#include <StormByte/crypto/engine/hasher/api.hxx>
#include <blake2.h>

using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using StormByte::Buffer::WriteOnly;
using namespace StormByte::Crypto::Hasher;

Blake2b::~Blake2b() noexcept = default;

Generic::PointerType Blake2b::Clone() const noexcept {
	return MakePointer<Blake2b>(*this);
}

Generic::PointerType Blake2b::Move() noexcept {
	return MakePointer<Blake2b>(std::move(*this));
}

bool Blake2b::DoHash(std::span<const std::byte> dataSpan, WriteOnly& output) const noexcept {
	return Engine::Hasher::Hash<CryptoPP::BLAKE2b>(dataSpan, output);
}

Consumer Blake2b::DoHash(Consumer consumer, ReadMode mode) const noexcept {
	return Engine::Hasher::Hash<CryptoPP::BLAKE2b>(consumer, mode);
}
