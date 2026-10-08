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

#include <StormByte/crypto/visibility.h>
#include <StormByte/safe/vector.hxx>

#include <cstddef>

/**
 * @namespace StormByte::Crypto::Helpers
 * @brief Private helpers of the Crypto module.
 */
namespace StormByte::Crypto::Helpers {
	/**
	 * @class SecureContent
	 * @brief Base-owned byte buffer wiped before releasing its storage.
	 *
	 * Exact size; no terminator. Implementation only.
	 */
	class STORMBYTE_CRYPTO_PRIVATE SecureContent {
		public:
			/**
			 * @brief From raw bytes.
			 * @param data Source, or nullptr if size is 0.
			 * @param size Byte count.
			 */
			SecureContent(const void* data, std::size_t size);

			/**
			 * @brief Copy constructor (deleted).
			 */
			SecureContent(const SecureContent&) = delete;

			/**
			 * @brief Secure storage cannot be moved independently of its shared owner.
			 */
			SecureContent(SecureContent&&) = delete;

			/**
			 * @brief Wipe the bytes before releasing the backing storage.
			 */
			~SecureContent() noexcept;

			/**
			 * @brief Copy assignment (deleted).
			 */
			SecureContent& operator=(const SecureContent&) = delete;

			/**
			 * @brief Secure storage cannot be move-assigned.
			 */
			SecureContent& operator=(SecureContent&&) = delete;

			/**
			 * @brief Zero the buffer.
			 */
			void Wipe() noexcept;

			/**
			 * @brief Stored size.
			 * @return Byte count.
			 */
			std::size_t Size() const noexcept;

			/**
			 * @brief Pointer to the bytes while this object lives.
			 * @return Data pointer.
			 */
			const unsigned char* Data() const noexcept;

			/**
			 * @brief Constant-time equality.
			 * @param other Other buffer.
			 * @return true if length and content match.
			 */
			bool Equal(const SecureContent& other) const noexcept;

		private:
			StormByte::Safe::Vector<unsigned char> m_block;	///< Base-owned wiped storage.
	};
}
