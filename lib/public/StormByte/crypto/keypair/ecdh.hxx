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

#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/safe/string.hxx>

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
		 * @namespace StormByte::Crypto::KeyPair
		 * @brief Keypairs of the Crypto module.
		 */
		namespace KeyPair {
			/**
			 * @class ECDH
			 * @note Conditional DLL safety follows Generic's provider requirements.
			 *       Material construction, Clone/Move and destruction are provided by
			 *       Crypto; defaulted value operations delegate to exported Generic operations.
			 * @brief ECDH keypair.
			 */
			class STORMBYTE_CRYPTO_PUBLIC ECDH final: public Generic {
				public:
					/**
					 * @name Construction
					 * @{
					 */
					/**
					 * @brief Construct from public material and optional private Password.
					 * @param publicKey Public key. Accepts String and std::string via string_view.
					 * @param privateKey Optional private key.
					 */
					ECDH(std::string_view publicKey, StormByte::Safe::Optional<Secure::Password> privateKey = std::nullopt);

					/**
					 * @brief Copy constructor.
					 * @param other Keypair to copy.
					 */
					ECDH(const ECDH& other) = default;

					/**
					 * @brief Move constructor.
					 * @param other Keypair to move.
					 */
					ECDH(ECDH&& other) noexcept = default;

					/**
					 * @brief Destructor.
					 */
					~ECDH() noexcept;

					/**
					 * @brief Copy assignment.
					 * @param other Keypair to copy.
					 * @return Reference to this keypair.
					 */
					ECDH& operator=(const ECDH& other) = default;

					/**
					 * @brief Move assignment.
					 * @param other Keypair to move.
					 * @return Reference to this keypair.
					 */
					ECDH& operator=(ECDH&& other) noexcept = default;
					/** @} */

					/**
					 * @brief Clone this keypair.
					 * @return Shared pointer to the clone.
					 */
					PointerType Clone() const override;

					/**
					 * @brief Move this keypair into a new instance.
					 * @return Shared pointer to the moved keypair.
					 */
					PointerType Move() override;

					/**
					 * @brief Generate an ECDH keypair.
					 * @param bits Curve size in bits.
					 * @return Keypair pointer, or nullptr.
					 */
					static PointerType Generate(unsigned short bits) noexcept;
			};
		}
	}
}

STORMBYTE_DECLARE_MAYBE_SAFE(StormByte::Crypto::KeyPair::ECDH);
