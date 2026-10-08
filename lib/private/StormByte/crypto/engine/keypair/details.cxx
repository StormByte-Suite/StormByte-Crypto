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

#include <StormByte/crypto/engine/keypair/details.hxx>

#include <base64.h>

namespace StormByte::Crypto::Engine::KeyPair {
	Safe::String EncodeSecBlockBase64(const CryptoPP::SecByteBlock& block) {
		CryptoPP::Base64Encoder encoder(nullptr, false);
		encoder.Put(block.data(), block.size());
		encoder.MessageEnd();
		Safe::String output;
		output.resize(encoder.MaxRetrievable());
		if (!output.empty())
			encoder.Get(reinterpret_cast<CryptoPP::byte*>(output.data()), output.size());
		return output;
	}

	CryptoPP::SecByteBlock DecodeSecBlockBase64(std::string_view encoded) {
		CryptoPP::Base64Decoder decoder;
		decoder.Put(reinterpret_cast<const CryptoPP::byte*>(encoded.data()), encoded.size());
		decoder.MessageEnd();
		CryptoPP::SecByteBlock block;
		block.resize(decoder.MaxRetrievable());
		if (!block.empty())
			decoder.Get(block.data(), block.size());
		return block;
	}
}
