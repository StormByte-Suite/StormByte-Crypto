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

#include <StormByte/safe/clonable.hxx>
#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/crypto/visibility.h>

#include <optional>
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
			 * @enum Type
			 * @brief Available agreement algorithms.
			 */
			enum class Type {
				ECDH,		///< ECDH
				X25519,		///< X25519
			};

			/**
			 * @class Generic
			 * @brief Abstract key-agreement object.
			 *
			 * Holds a local keypair and derives a shared secret from a peer public key.
			 */
			class STORMBYTE_CRYPTO_PUBLIC Generic: public StormByte::Safe::Clonable<Generic> {
				public:
					/**
					 * @name Construction
					 * @{
					 */
					/**
					 * @brief Copy constructor.
					 * @param other Object to copy.
					 */
					Generic(const Generic& other) = default;

					/**
					 * @brief Move constructor.
					 * @param other Object to move.
					 */
					Generic(Generic&& other) noexcept = default;

					/**
					 * @brief Destructor.
					 */
					virtual ~Generic() noexcept;

					/**
					 * @brief Copy assignment.
					 * @param other Object to copy.
					 * @return Reference to this object.
					 */
					Generic& operator=(const Generic& other) = default;

					/**
					 * @brief Move assignment.
					 * @param other Object to move.
					 * @return Reference to this object.
					 */
					Generic& operator=(Generic&& other) noexcept = default;
					/** @} */

					/**
					 * @brief Algorithm of this instance.
					 * @return Agreement type.
					 */
					inline Type Type() const noexcept {
						return m_type;
					}

					/**
					 * @brief Derive a shared secret from a peer public key.
					 * @param peerPublicKey Peer public key as Base64. Accepts String and std::string via string_view.
					 * @return Password on success, or empty.
					 */
					virtual std::optional<Secure::Password> Share(std::string_view peerPublicKey) const noexcept = 0;

				protected:
					enum Type m_type;							///< Algorithm
					KeyPair::Generic::PointerType m_keypair;	///< Local keypair (needs private key)

					/**
					 * @brief Construct with algorithm and keypair.
					 * @param type Algorithm.
					 * @param keypair Local keypair.
					 */
					inline Generic(enum Type type, KeyPair::Generic::PointerType keypair) noexcept
						: m_type(type), m_keypair(std::move(keypair)) {}
			};

			/**
			 * @brief Create an agreement object.
			 * @param type Algorithm.
			 * @param keypair Matching keypair.
			 * @return Object pointer, or nullptr if the pair is null or mismatched.
			 * @note ECDH defaults to 256 bits. For secp384r1/secp521r1 construct @ref ECDH with the bit size.
			 */
			STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(Type type, KeyPair::Generic::PointerType keypair) noexcept;
		}
	}
}
