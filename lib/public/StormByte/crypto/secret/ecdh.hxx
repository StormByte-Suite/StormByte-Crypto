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

#include <StormByte/crypto/keypair/ecdh.hxx>
#include <StormByte/crypto/secret/generic.hxx>

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
		 * @namespace StormByte::Crypto::Secret
		 * @brief Key agreement of the Crypto module.
		 */
		namespace Secret {
			/**
			 * @class ECDH
			 * @note MaybeSafe inherits all provider requirements of @ref StormByte::Crypto::Secret::Generic.
			 * The added arithmetic curve-size field is Safe; exported Clone/Move preserve it and
			 * bind ownership callbacks in Crypto.
			 * @brief ECDH shared-secret derivation.
			 */
			class STORMBYTE_CRYPTO_PUBLIC ECDH final: public Generic {
				public:
					/**
					 * @name Construction
					 * @{
					 */
					/**
					 * @brief Construct from a keypair pointer.
					 * @param keypair Must be @ref KeyPair::Type::ECDH.
					 * @param bits Curve size in bits. Must match the keypair.
					 */
					inline ECDH(KeyPair::Generic::PointerType keypair, unsigned short bits = 256) noexcept:
						Generic(Type::ECDH, keypair), m_bits(bits) {}

					/**
					 * @brief Construct by cloning an ECDH keypair.
					 * @param keypair Keypair.
					 * @param bits Curve size in bits.
					 */
					inline ECDH(const KeyPair::ECDH& keypair, unsigned short bits = 256) noexcept:
						Generic(Type::ECDH, keypair.Clone()), m_bits(bits) {}

					/**
					 * @brief Construct by moving an ECDH keypair.
					 * @param keypair Keypair.
					 * @param bits Curve size in bits.
					 */
					inline ECDH(KeyPair::ECDH&& keypair, unsigned short bits = 256) noexcept:
						Generic(Type::ECDH, keypair.Move()), m_bits(bits) {}

					/**
					 * @brief Copy constructor.
					 * @param other Object to copy.
					 */
					ECDH(const ECDH& other) = default;

					/**
					 * @brief Move constructor.
					 * @param other Object to move.
					 */
					ECDH(ECDH&& other) noexcept = default;

					/**
					 * @brief Destructor.
					 */
					~ECDH() noexcept;

					/**
					 * @brief Copy assignment.
					 * @param other Object to copy.
					 * @return Reference to this object.
					 */
					ECDH& operator=(const ECDH& other) = default;

					/**
					 * @brief Move assignment.
					 * @param other Object to move.
					 * @return Reference to this object.
					 */
					ECDH& operator=(ECDH&& other) noexcept = default;
					/** @} */

					/**
					 * @brief Clone this object.
					 * @return Shared pointer to the clone.
					 */
					PointerType Clone() const noexcept override;

					/**
					 * @brief Move this object into a new instance.
					 * @return Shared pointer to the moved object.
					 */
					PointerType Move() noexcept override;

					/**
					 * @brief Derive a shared secret.
					 * @param peerPublicKey Peer public key as Base64. Accepts String and std::string via string_view.
					 * @return Password on success, or empty.
					 */
					StormByte::Safe::Optional<Secure::Password> Share(std::string_view peerPublicKey) const override;

				private:
					unsigned short m_bits;	///< Curve size in bits
			};
		}
	}
}

STORMBYTE_DECLARE_MAYBE_SAFE(StormByte::Crypto::Secret::ECDH);
