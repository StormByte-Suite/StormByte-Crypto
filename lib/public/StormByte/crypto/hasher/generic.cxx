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
#include <StormByte/crypto/hasher/blake2s.hxx>
#include <StormByte/crypto/hasher/generic.hxx>
#include <StormByte/crypto/hasher/sha256.hxx>
#include <StormByte/crypto/hasher/sha3_256.hxx>
#include <StormByte/crypto/hasher/sha3_512.hxx>
#include <StormByte/crypto/hasher/sha512.hxx>

#include <span>

using namespace StormByte::Crypto::Hasher;

Generic::~Generic() noexcept = default;

bool Generic::DoHash(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept {
	StormByte::Safe::Binary data;
	bool read_ok;
	if (mode == ReadMode::Copy)
		read_ok = input.Read(StormByte::ByteSize{0}, data);
	else
		read_ok = input.Extract(StormByte::ByteSize{0}, data);
	if (!read_ok)
		return false;
	return DoHash(data.span(), output);
}

namespace StormByte::Crypto::Hasher {
	Generic::PointerType Create(Type type) noexcept {
		switch (type) {
			case Type::Blake2b:
				return Blake2b::MakePointer<Blake2b>();
			case Type::Blake2s:
				return Blake2s::MakePointer<Blake2s>();
			case Type::SHA256:
				return SHA256::MakePointer<SHA256>();
			case Type::SHA512:
				return SHA512::MakePointer<SHA512>();
			case Type::SHA3_256:
				return SHA3_256::MakePointer<SHA3_256>();
			case Type::SHA3_512:
				return SHA3_512::MakePointer<SHA3_512>();
			default:
				return nullptr;
		}
	}
}
