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

#include <StormByte/binary_data.hxx>
#include <StormByte/safe/string.hxx>

#include <cstddef>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include <secblock.h>

/**
 * @namespace StormByte
 * @brief Root namespace of the StormByte suite.
 */
namespace StormByte {
	/**
	 * @namespace StormByte::Crypto
	 * @brief Crypto module of the StormByte suite.
	 */
	namespace Crypto {
		/**
		 * @namespace StormByte::Crypto::Helpers
		 * @brief Private helpers of the Crypto module.
		 */
		namespace Helpers {
			/**
			 * @brief Zero the existing characters before releasing DLL-safe text storage.
			 * @param value Text to wipe and clear.
			 */
			inline void SecureWipe(StormByte::Safe::String& value) noexcept {
				volatile char* bytes = value.data();
				const std::size_t count = static_cast<std::size_t>(value.size());
				for (std::size_t index = 0; index < count; ++index)
					bytes[index] = 0;
				value.clear();
			}

			/**
			 * @brief Zero and clear a string.
			 * @param s String to wipe.
			 */
			inline void SecureWipe(std::string& s) noexcept {
				if (s.empty())
					return;

				volatile char* p = s.data();
				for (size_t i = 0; i < s.size(); ++i)
					p[i] = 0;
				s.clear();
				s.shrink_to_fit();
			}

			/**
			 * @brief Zero a Crypto++ SecByteBlock.
			 * @param block Block to wipe.
			 */
			inline void SecureWipe(CryptoPP::SecByteBlock& block) noexcept {
				if (block.empty())
					return;
				block.CleanNew(0);
			}

			/**
			 * @brief Zero an optional string.
			 * @param opt Optional to wipe.
			 */
			inline void SecureWipe(std::optional<std::string>& opt) noexcept {
				if (opt.has_value()) {
					SecureWipe(*opt);
					opt.reset();
				}
			}

			/**
			 * @brief Zero a vector of bytes.
			 * @param data Vector to wipe.
			 */
			inline void SecureWipe(std::vector<std::byte>& data) noexcept {
				if (data.empty())
					return;
				volatile std::byte* p = data.data();
				for (size_t i = 0; i < data.size(); ++i)
					p[i] = std::byte{0};
				data.clear();
				data.shrink_to_fit();
			}

			/**
			 * @brief Zero a vector of Crypto++ bytes (`unsigned char`).
			 * @param data Vector to wipe.
			 */
			inline void SecureWipe(std::vector<unsigned char>& data) noexcept {
				if (data.empty())
					return;
				volatile unsigned char* p = data.data();
				for (size_t i = 0; i < data.size(); ++i)
					p[i] = 0;
				data.clear();
				data.shrink_to_fit();
			}

			/**
			 * @brief Zero a StormByte binary buffer.
			 * @param data Buffer to wipe.
			 */
			inline void SecureWipe(StormByte::BinaryData& data) noexcept {
				if (data.empty())
					return;
				volatile std::byte* p = data.data();
				const std::size_t n = static_cast<std::size_t>(data.size());
				for (std::size_t i = 0; i < n; ++i)
					p[i] = std::byte{0};
				data.clear();
			}
		}
	}
}
