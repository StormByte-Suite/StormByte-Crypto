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

#include <StormByte/crypto/keypair/ecdsa.hxx>
#include <StormByte/crypto/signer/generic.hxx>

#include <string_view>

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
		 * @namespace StormByte::Crypto::Signer
		 * @brief Signers of the Crypto module.
		 */
		namespace Signer {
			/**
			 * @class ECDSA
			 * @note MaybeSafe inherits all provider requirements of @ref StormByte::Crypto::Signer::Generic.
			 * This leaf adds no fields; exported Clone/Move bind ownership callbacks in Crypto.
			 * @brief ECDSA signer.
			 */
			class STORMBYTE_CRYPTO_PUBLIC ECDSA final: public Generic {
				public:
					/**
					 * @name Construction
					 * @{
					 */
					/**
					 * @brief Construct from a keypair pointer.
					 * @param keypair Keypair.
					 */
					inline ECDSA(KeyPair::Generic::PointerType keypair):
						Generic(Type::ECDSA, keypair) {}

					/**
					 * @brief Construct by cloning an ECDSA keypair.
					 * @param keypair Keypair.
					 */
					inline ECDSA(const KeyPair::ECDSA& keypair):
						Generic(Type::ECDSA, keypair) {}

					/**
					 * @brief Construct by moving an ECDSA keypair.
					 * @param keypair Keypair.
					 */
					inline ECDSA(KeyPair::ECDSA&& keypair):
						Generic(Type::ECDSA, keypair) {}

					/**
					 * @brief Copy constructor.
					 * @param other Signer to copy.
					 */
					ECDSA(const ECDSA& other) = default;

					/**
					 * @brief Move constructor.
					 * @param other Signer to move.
					 */
					ECDSA(ECDSA&& other) noexcept = default;

					/**
					 * @brief Destructor.
					 */
					~ECDSA() noexcept;

					/**
					 * @brief Copy assignment.
					 * @param other Signer to copy.
					 * @return Reference to this signer.
					 */
					ECDSA& operator=(const ECDSA& other) = default;

					/**
					 * @brief Move assignment.
					 * @param other Signer to move.
					 * @return Reference to this signer.
					 */
					ECDSA& operator=(ECDSA&& other) noexcept = default;
					/** @} */

					/**
					 * @brief Clone this signer.
					 * @return Shared pointer to the clone.
					 */
					PointerType Clone() const noexcept override;

					/**
					 * @brief Move this signer into a new instance.
					 * @return Shared pointer to the moved signer.
					 */
					PointerType Move() noexcept override;

				private:
					/**
					 * @brief Sign a byte span.
					 * @param input Input bytes.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					bool DoSign(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept override;

					/**
					 * @brief Sign a Consumer.
					 * @param consumer Input consumer.
					 * @param mode Copy or move.
					 * @return Consumer with the signature.
					 */
					Buffer::Consumer DoSign(Buffer::Consumer consumer, ReadMode mode) const noexcept override;

					/**
					 * @brief Verify a byte span.
					 * @param input Input bytes.
					 * @param signature Signature.
					 * @return true if valid.
					 */
					bool DoVerify(std::span<const std::byte> input, std::string_view signature) const noexcept override;

					/**
					 * @brief Verify a Consumer.
					 * @param consumer Input consumer.
					 * @param signature Signature.
					 * @param mode Copy or move.
					 * @return true if valid.
					 */
					bool DoVerify(Buffer::Consumer consumer, std::string_view signature, ReadMode mode) const noexcept override;
			};
		}
	}
}

STORMBYTE_DECLARE_MAYBE_SAFE(StormByte::Crypto::Signer::ECDSA);
