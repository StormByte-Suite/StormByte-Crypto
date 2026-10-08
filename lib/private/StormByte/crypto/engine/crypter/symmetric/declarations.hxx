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

#pragma once

#include <StormByte/type_traits.hxx>

/**
 * @namespace StormByte::Crypto::Engine::Crypter::Symmetric
 * @brief Private symmetric crypter implementation.
 */
namespace StormByte::Crypto::Engine::Crypter::Symmetric {
	/**
	 * @class CipherOps
	 * @brief Named symmetric engine allocated and destroyed in its creating module.
	 * @tparam Cipher Crypto++ cipher type.
	 * @tparam Hash PBKDF2 hash type.
	 * @tparam Authenticated Whether the cipher uses authenticated filters.
	 * @tparam Encrypting Whether the engine encrypts rather than decrypts.
	 * @tparam Streaming Whether the filter spans multiple input chunks.
	 */
	template<class Cipher, class Hash, bool Authenticated, bool Encrypting, bool Streaming>
	class CipherOps;
}

/**
 * @brief Certify only the named symmetric engine, not arbitrary Ops derivatives.
 * @tparam Cipher Private Crypto++ cipher type.
 * @tparam Hash Private PBKDF2 hash type.
 * @tparam Authenticated Whether authentication is enabled.
 * @tparam Encrypting Whether encryption is enabled.
 * @tparam Streaming Whether input is streamed.
 * @note The engine never leaves Crypto except behind a Safe owner that records
 * its concrete creator-module destructor. Crypto++ state is strictly private;
 * compatible C++ ABIs and loaded Crypto/Base modules are required throughout
 * ownership. The engine is noncopyable and is never passed by value.
 */
template<class Cipher, class Hash, bool Authenticated, bool Encrypting, bool Streaming>
struct StormByte::Type::IsMaybeSafe<StormByte::Crypto::Engine::Crypter::Symmetric::CipherOps<Cipher, Hash, Authenticated, Encrypting, Streaming>>: std::true_type {};