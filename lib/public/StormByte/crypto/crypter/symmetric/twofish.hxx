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

#include <StormByte/crypto/crypter/symmetric/generic.hxx>

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
		 * @namespace StormByte::Crypto::Crypter
		 * @brief Ciphers of the Crypto module.
		 */
		namespace Crypter {
			/**
			 * @class TwoFish
			 * @note MaybeSafe inherits all provider requirements of @ref StormByte::Crypto::Crypter::Symmetric.
			 * This leaf adds no fields; exported Clone/Move bind ownership callbacks in Crypto.
			 * @brief Twofish-CBC crypter.
			 */
			class STORMBYTE_CRYPTO_PUBLIC TwoFish final: public Symmetric {
				public:
					/**
					 * @name Construction
					 * @{
					 */
					/**
					 * @brief Construct with a password.
					 * @param password Password.
					 */
					inline TwoFish(Secure::Password password):
						Symmetric(Type::TwoFish, std::move(password)) {}

					/**
					 * @brief Copy constructor.
					 * @param other Crypter to copy.
					 */
					TwoFish(const TwoFish& other) = default;

					/**
					 * @brief Move constructor.
					 * @param other Crypter to move.
					 */
					TwoFish(TwoFish&& other) noexcept = default;

					/**
					 * @brief Destructor.
					 */
					~TwoFish() noexcept;

					/**
					 * @brief Copy assignment.
					 * @param other Crypter to copy.
					 * @return Reference to this crypter.
					 */
					TwoFish& operator=(const TwoFish& other) = default;

					/**
					 * @brief Move assignment.
					 * @param other Crypter to move.
					 * @return Reference to this crypter.
					 */
					TwoFish& operator=(TwoFish&& other) noexcept = default;
					/** @} */

					/**
					 * @brief Clone this crypter.
					 * @return Shared pointer to the clone.
					 */
					PointerType Clone() const noexcept override;

					/**
					 * @brief Move this crypter into a new instance.
					 * @return Shared pointer to the moved crypter.
					 */
					PointerType Move() noexcept override;

				private:
					/**
					 * @brief Encrypt a byte span.
					 * @param input Input bytes.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					bool DoEncrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept override;

					/**
					 * @brief Encrypt a Consumer.
					 * @param consumer Input consumer.
					 * @param mode Copy or move.
					 * @return Consumer with ciphertext.
					 */
					Buffer::Consumer DoEncrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept override;

					/**
					 * @brief Decrypt a byte span.
					 * @param input Input bytes.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					bool DoDecrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept override;

					/**
					 * @brief Decrypt a Consumer.
					 * @param consumer Input consumer.
					 * @param mode Copy or move.
					 * @return Consumer with plaintext.
					 */
					Buffer::Consumer DoDecrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept override;
			};
		}
	}
}

STORMBYTE_DECLARE_MAYBE_SAFE(StormByte::Crypto::Crypter::TwoFish);
