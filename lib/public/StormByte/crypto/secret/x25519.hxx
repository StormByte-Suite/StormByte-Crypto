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

#include <StormByte/crypto/keypair/x25519.hxx>
#include <StormByte/crypto/secret/generic.hxx>

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
			 * @class X25519
			 * @note MaybeSafe inherits all provider requirements of @ref StormByte::Crypto::Secret::Generic.
			 * This leaf adds no fields; exported Clone/Move bind ownership callbacks in Crypto.
			 * @brief X25519 shared-secret derivation.
			 */
			class STORMBYTE_CRYPTO_PUBLIC X25519 final: public Generic {
				public:
					/**
					 * @name Construction
					 * @{
					 */
					/**
					 * @brief Construct from an X25519 keypair (needs private key).
					 * @param keypair Keypair.
					 */
					inline explicit X25519(KeyPair::Generic::PointerType keypair) noexcept:
						Generic(Type::X25519, std::move(keypair)) {}

					/**
					 * @brief Copy constructor.
					 * @param other Object to copy.
					 */
					X25519(const X25519& other) = default;

					/**
					 * @brief Move constructor.
					 * @param other Object to move.
					 */
					X25519(X25519&& other) noexcept = default;

					/**
					 * @brief Destructor.
					 */
					~X25519() noexcept;

					/**
					 * @brief Copy assignment.
					 * @param other Object to copy.
					 * @return Reference to this object.
					 */
					X25519& operator=(const X25519& other) = default;

					/**
					 * @brief Move assignment.
					 * @param other Object to move.
					 * @return Reference to this object.
					 */
					X25519& operator=(X25519&& other) noexcept = default;
					/** @} */

					/**
					 * @brief Clone this object.
					 * @return Shared pointer to the clone.
					 */
					Generic::PointerType Clone() const override;

					/**
					 * @brief Move this object into a new instance.
					 * @return Shared pointer to the moved object.
					 */
					Generic::PointerType Move() override;

					/**
					 * @brief Derive a shared secret.
					 * @param peerPublicKey Peer public key as Base64, borrowed for this call.
					 * @return Password on success, or empty.
					 * @throws StormByte::Exception If Safe result storage cannot be created.
					 */
					StormByte::Safe::Optional<Secure::Password> Share(const StormByte::Safe::String& peerPublicKey) const override;

					/**
					 * @brief Derive a shared secret without an instance.
					 * @param keypair Local keypair (needs private key).
					 * @param peerPublicKey Peer public key as Base64, borrowed for this call.
					 * @return Password on success, or empty.
					 * @throws StormByte::Exception If Safe result storage cannot be created.
					 */
					static StormByte::Safe::Optional<Secure::Password> DeriveSharedSecret(
						KeyPair::Generic::PointerType keypair,
						const StormByte::Safe::String& peerPublicKey);
			};
		}
	}
}

STORMBYTE_DECLARE_MAYBE_SAFE(StormByte::Crypto::Secret::X25519);
