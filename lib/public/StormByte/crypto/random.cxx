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

#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/rng.hxx>

#include <secblock.h>

#include <cstddef>
#include <cstring>

StormByte::Safe::SecureBinary StormByte::Crypto::Random::Bytes(ByteSize count) {
	if (count == ByteSize{0})
		throw Exception("Random byte count must be greater than zero");
	try {
		CryptoPP::SecByteBlock bytes(static_cast<std::size_t>(count));
		RNG().GenerateBlock(bytes, bytes.size());
		return Safe::SecureBinary(reinterpret_cast<const std::byte*>(bytes.data()), count);
	} catch (const CryptoPP::Exception& error) {
		throw Exception("Random byte generation failed: {}", error.what());
	}
}

StormByte::Safe::String StormByte::Crypto::Random::Text(Size count) {
	if (count == Size{0})
		throw Exception("Random character count must be greater than zero");
	try {
		CryptoPP::SecByteBlock bytes(static_cast<std::size_t>(count));
		auto& rng = RNG();
		for (std::size_t index = 0; index < bytes.size(); ++index)
			bytes[index] = static_cast<CryptoPP::byte>(rng.GenerateWord32(33, 126));
		Safe::String result(count, '\0');
		std::memcpy(result.data(), bytes.data(), bytes.size());
		return result;
	} catch (const CryptoPP::Exception& error) {
		throw Exception("Random text generation failed: {}", error.what());
	}
}

namespace StormByte::Crypto::Random {
	Exception::Exception(const Exception& other) = default;

	Exception::Exception(Exception&& other) noexcept = default;

	Exception::~Exception() noexcept = default;

	Exception& Exception::operator=(const Exception& other) = default;

	Exception& Exception::operator=(Exception&& other) noexcept = default;
}
