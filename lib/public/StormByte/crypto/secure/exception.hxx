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

#include <StormByte/crypto/exception.hxx>
#include <StormByte/crypto/visibility.h>

#include <format>
#include <string>
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
			 * @class Exception
			 * @brief Root exception for Secure. `what()` is `StormByte.Crypto.Secure: message`.
			 *
			 * Forwards the format and the arguments. Does not format.
			 * A child segment is prepended under `Secure`.
			 */
			class STORMBYTE_CRYPTO_PUBLIC Exception: public Crypto::Exception {
				public:
					/**
					 * @name Construction
					 * @{
					 */
					/**
					 * @brief Format under `StormByte.Crypto.Secure`.
					 * @tparam Args Format argument types.
					 * @param fmt Format string.
					 * @param args Format arguments.
					 */
					template<typename... Args>
					explicit Exception(std::format_string<Args...> fmt, Args&&... args)
						: Crypto::Exception(Path{"Secure"}, fmt, std::forward<Args>(args)...) {}

					/**
					 * @brief Plain message under `StormByte.Crypto.Secure`.
					 * @param message Exception text. Not a format string.
					 */
					explicit Exception(std::string_view message)
						: Crypto::Exception(Path{"Secure"}, message) {}

					/**
					 * @brief Copy constructor.
					 * @param other Exception to copy.
					 */
					Exception(const Exception& other);

					/**
					 * @brief Move constructor.
					 * @param other Exception to move.
					 */
					Exception(Exception&& other) noexcept;

					/**
					 * @brief Destructor. Defined in this module so `catch` matches across a DLL.
					 */
					~Exception() noexcept override;

					/**
					 * @brief Copy assignment.
					 * @param other Exception to copy.
					 * @return Reference to this exception.
					 */
					Exception& operator=(const Exception& other);

					/**
					 * @brief Move assignment.
					 * @param other Exception to move.
					 * @return Reference to this exception.
					 */
					Exception& operator=(Exception&& other) noexcept;
					/** @} */

				protected:
					/**
					 * @brief Format under StormByte.Crypto.Secure plus the child segment.
					 * @tparam Args Format argument types.
					 * @param child Segment under `Secure`.
					 * @param fmt Format string.
					 * @param args Format arguments.
					 */
					template<typename... Args>
					explicit Exception(Path child, std::format_string<Args...> fmt, Args&&... args)
						: Crypto::Exception(
							Path{std::string("Secure.") + std::string(child.text)},
							fmt,
							std::forward<Args>(args)...) {}

					/**
					 * @brief Plain message under StormByte.Crypto.Secure plus the child segment.
					 * @param child Segment under `Secure`.
					 * @param message Exception text. Not a format string.
					 */
					explicit Exception(Path child, std::string_view message)
						: Crypto::Exception(
							Path{std::string("Secure.") + std::string(child.text)},
							message) {}
			};

			/**
			 * @class VaultException
			 * @brief Exception from the vault. `what()` is `StormByte.Crypto.Secure.Vault: message`.
			 */
			class STORMBYTE_CRYPTO_PUBLIC VaultException: public Exception {
				public:
					/**
					 * @name Construction
					 * @{
					 */
					/**
					 * @brief Format under `StormByte.Crypto.Secure.Vault`.
					 * @tparam Args Format argument types.
					 * @param fmt Format string.
					 * @param args Format arguments.
					 */
					template<typename... Args>
					explicit VaultException(std::format_string<Args...> fmt, Args&&... args)
						: Exception(Path{"Vault"}, fmt, std::forward<Args>(args)...) {}

					/**
					 * @brief Plain message under `StormByte.Crypto.Secure.Vault`.
					 * @param message Exception text. Not a format string.
					 */
					explicit VaultException(std::string_view message)
						: Exception(Path{"Vault"}, message) {}

					/**
					 * @brief Copy constructor.
					 * @param other Exception to copy.
					 */
					VaultException(const VaultException& other);

					/**
					 * @brief Move constructor.
					 * @param other Exception to move.
					 */
					VaultException(VaultException&& other) noexcept;

					/**
					 * @brief Destructor. Defined in this module so `catch` matches across a DLL.
					 */
					~VaultException() noexcept override;

					/**
					 * @brief Copy assignment.
					 * @param other Exception to copy.
					 * @return Reference to this exception.
					 */
					VaultException& operator=(const VaultException& other);

					/**
					 * @brief Move assignment.
					 * @param other Exception to move.
					 * @return Reference to this exception.
					 */
					VaultException& operator=(VaultException&& other) noexcept;
					/** @} */
			};
		}
	}
}
