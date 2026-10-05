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

#include <StormByte/crypto/crypter/generic.hxx>
#include <StormByte/crypto/secure/password.hxx>

/**
 * @brief Ciphers of the Crypto module.
 */
namespace StormByte::Crypto::Crypter {
	/**
	 * @class Symmetric
	 * @brief Password-based symmetric crypter.
	 *
	 * Copies share the same @ref StormByte::Crypto::Secure::Password. The buffer is
	 * wiped when the last owner is destroyed.
	 * @note MaybeSafe inherits all requirements of @ref StormByte::Crypto::Crypter::Generic,
	 * including ABI-compatible toolchains and keeping all provider modules loaded.
	 * The Password field is Safe and delegates ownership to exported Password/Safe operations;
	 * inline construction, copying, assignment and movement do not own local heap storage.
	 * Destruction is exported. Derived providers must preserve these guarantees for every added
	 * field and bind owning Clone/Move creator/deleter callbacks in their provider module.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Symmetric: public Generic {
		public:
			/**
			 * @name Construction
			 * @{
			 */
			/**
			 * @brief Copy constructor.
			 * @param other Crypter to copy.
			 */
			Symmetric(const Symmetric& other) = default;

			/**
			 * @brief Move constructor.
			 * @param other Crypter to move.
			 */
			Symmetric(Symmetric&& other) noexcept = default;

			/**
			 * @brief Destructor.
			 */
			virtual ~Symmetric() noexcept override;

			/**
			 * @brief Copy assignment.
			 * @param other Crypter to copy.
			 * @return Reference to this crypter.
			 */
			Symmetric& operator=(const Symmetric& other) = default;

			/**
			 * @brief Move assignment.
			 * @param other Crypter to move.
			 * @return Reference to this crypter.
			 */
			Symmetric& operator=(Symmetric&& other) noexcept = default;
			/** @} */

			/**
			 * @brief Password used by this crypter.
			 * @return Shared password.
			 * @note Shares ownership of the underlying bytes.
			 */
			inline const Secure::Password& Password() const noexcept {
				return m_password;
			}

			/**
			 * @brief Random password of raw bytes (not text).
			 * @param length Number of bytes.
			 * @return Password.
			 */
			static Secure::Password RandomPassword(size_t length = 32) noexcept;

		protected:
			Secure::Password m_password;	///< Shared password

			/**
			 * @brief Construct with a cipher and a password.
			 * @param type Cipher.
			 * @param password Password.
			 */
			inline Symmetric(enum Type type, Secure::Password password):
				Generic(type), m_password(std::move(password)) {}
	};

	/**
	 * @brief Factory for a symmetric crypter.
	 * @param type Cipher.
	 * @param password Password.
	 * @return Crypter pointer, or nullptr on failure.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(enum Type type, Secure::Password password) noexcept;
}

STORMBYTE_DECLARE_MAYBE_SAFE(StormByte::Crypto::Crypter::Symmetric);
