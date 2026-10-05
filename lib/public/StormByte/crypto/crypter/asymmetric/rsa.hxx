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

#include <StormByte/crypto/crypter/asymmetric/generic.hxx>
#include <StormByte/crypto/keypair/rsa.hxx>

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
			 * @class RSA
			 * @note MaybeSafe inherits all provider requirements of @ref StormByte::Crypto::Crypter::Asymmetric.
			 * This leaf adds no fields; exported Clone/Move bind ownership callbacks in Crypto.
			 * @brief RSA crypter.
			 */
			class STORMBYTE_CRYPTO_PUBLIC RSA final: public Asymmetric {
				public:
					/**
					 * @name Construction
					 * @{
					 */
					/**
					 * @brief Construct from a keypair pointer.
					 * @param keypair Keypair.
					 */
					inline RSA(KeyPair::Generic::PointerType keypair):
						Asymmetric(Type::RSA, keypair) {}

					/**
					 * @brief Construct by cloning an RSA keypair.
					 * @param keypair Keypair.
					 */
					inline RSA(const KeyPair::RSA& keypair):
						Asymmetric(Type::RSA, keypair) {}

					/**
					 * @brief Construct by moving an RSA keypair.
					 * @param keypair Keypair.
					 */
					inline RSA(KeyPair::RSA&& keypair):
						Asymmetric(Type::RSA, std::forward<KeyPair::RSA>(keypair)) {}

					/**
					 * @brief Copy constructor.
					 * @param other Crypter to copy.
					 */
					RSA(const RSA& other) = default;

					/**
					 * @brief Move constructor.
					 * @param other Crypter to move.
					 */
					RSA(RSA&& other) noexcept = default;

					/**
					 * @brief Destructor.
					 */
					~RSA() noexcept;

					/**
					 * @brief Copy assignment.
					 * @param other Crypter to copy.
					 * @return Reference to this crypter.
					 */
					RSA& operator=(const RSA& other) = default;

					/**
					 * @brief Move assignment.
					 * @param other Crypter to move.
					 * @return Reference to this crypter.
					 */
					RSA& operator=(RSA&& other) noexcept = default;
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

STORMBYTE_DECLARE_MAYBE_SAFE(StormByte::Crypto::Crypter::RSA);
