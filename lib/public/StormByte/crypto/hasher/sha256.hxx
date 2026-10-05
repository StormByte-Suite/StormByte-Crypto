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

#include <StormByte/crypto/hasher/generic.hxx>

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
		 * @namespace StormByte::Crypto::Hasher
		 * @brief Hash algorithms of the Crypto module.
		 */
		namespace Hasher {
			/**
			 * @class SHA256
			 * @brief SHA-256 hasher.
			 * @note MaybeSafe inherits all provider requirements of @ref StormByte::Crypto::Hasher::Generic.
			 * This leaf adds no fields; exported Clone/Move bind ownership callbacks in Crypto.
			 */
			class STORMBYTE_CRYPTO_PUBLIC SHA256 final: public Generic {
				public:
					/**
					 * @name Construction
					 * @{
					 */
					/**
					 * @brief Default constructor.
					 */
					inline SHA256():
						Generic(Type::SHA256) {}

					/**
					 * @brief Copy constructor.
					 * @param other Hasher to copy.
					 */
					SHA256(const SHA256& other) = default;

					/**
					 * @brief Move constructor.
					 * @param other Hasher to move.
					 */
					SHA256(SHA256&& other) noexcept = default;

					/**
					 * @brief Destructor.
					 */
					~SHA256() noexcept;

					/**
					 * @brief Copy assignment.
					 * @param other Hasher to copy.
					 * @return Reference to this hasher.
					 */
					SHA256& operator=(const SHA256& other) = default;

					/**
					 * @brief Move assignment.
					 * @param other Hasher to move.
					 * @return Reference to this hasher.
					 */
					SHA256& operator=(SHA256&& other) noexcept = default;
					/** @} */

					/**
					 * @brief Clone this hasher.
					 * @return Shared pointer to the clone.
					 */
					PointerType Clone() const noexcept override;

					/**
					 * @brief Move this hasher into a new instance.
					 * @return Shared pointer to the moved hasher.
					 */
					PointerType Move() noexcept override;

				private:
					/**
					 * @brief Hash a byte span.
					 * @param input Input bytes.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					bool DoHash(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept override;

					/**
					 * @brief Hash a Consumer.
					 * @param consumer Input consumer.
					 * @param mode Copy or move.
					 * @return Consumer with the digest.
					 */
					Buffer::Consumer DoHash(Buffer::Consumer consumer, ReadMode mode) const noexcept override;
			};
		}
	}
}

STORMBYTE_DECLARE_MAYBE_SAFE(StormByte::Crypto::Hasher::SHA256);
