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

#include <StormByte/crypto/secure/exception.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/crypto/visibility.h>
#include <StormByte/expected.hxx>
#include <StormByte/safe/pointers.hxx>
#include <StormByte/size.hxx>

#include <string_view>
#include <utility>

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
		 * @namespace StormByte::Crypto::Secure
		 * @brief Wiped secrets of the Crypto module (Password, Vault).
		 */
		namespace Secure {
			/**
			 * @brief Password or a vault error.
			 */
			using ExpectedPassword = StormByte::Expected<Password, VaultException>;

			/**
			 * @class Vault
			 * @brief Named collection of @ref Password objects.
			 *
			 * Move-only. Destroying the vault, or calling Clear()/Remove(), drops
			 * the last owner of each password and triggers the wipe.
			 */
			class STORMBYTE_CRYPTO_PUBLIC Vault {
				public:
					/**
					 * @name Construction
					 * @{
					 */
					/**
					 * @brief Empty vault.
					 */
					Vault();

					Vault(const Vault&) = delete;

					/**
					 * @brief Move constructor.
					 * @param other Vault to move.
					 */
					Vault(Vault&& other) noexcept;

					/**
					 * @brief Destructor. Releases every stored password.
					 */
					~Vault() noexcept;

					Vault& operator=(const Vault&) = delete;

					/**
					 * @brief Move assignment.
					 * @param other Vault to move.
					 * @return Reference to this vault.
					 */
					Vault& operator=(Vault&& other) noexcept;
					/** @} */

					/**
					 * @brief Store or overwrite a named password.
					 * @param name Identifier.
					 * @param password Password to share.
					 */
					void Store(std::string_view name, Password password) noexcept;

					/**
					 * @brief Look up a password.
					 * @param name Identifier.
					 * @return Password, or an error if the name is missing.
					 * @note The returned Password shares the buffer.
					 */
					ExpectedPassword Get(std::string_view name) const noexcept;

					/**
					 * @brief Whether a name exists.
					 * @param name Identifier.
					 * @return true if present.
					 */
					bool Contains(std::string_view name) const noexcept;

					/**
					 * @brief Drop one password.
					 * @param name Identifier.
					 */
					void Remove(std::string_view name) noexcept;

					/**
					 * @brief Drop every password.
					 */
					void Clear() noexcept;

					/**
					 * @brief Number of stored passwords.
					 * @return Count.
					 */
					StormByte::Size Size() const noexcept;

					/**
					 * @brief Whether the vault is empty.
					 * @return true if Size() is 0.
					 */
					bool Empty() const noexcept;

				private:
					/** @brief Named-password storage constructed and destroyed inside Crypto. */
					struct Storage;
					StormByte::Safe::Unique<Storage> m_storage;	///< DLL-safe owner of named passwords
			};
		}
	}
}
