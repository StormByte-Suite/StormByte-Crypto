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
		 * @namespace StormByte::Crypto::Random
		 * @brief Cryptographically secure random bytes and printable text.
		 */
		namespace Random {
			/**
			 * @class Exception
			 * @brief Invalid random request or provider failure under `StormByte.Crypto.Random`.
			 */
			class STORMBYTE_CRYPTO_PUBLIC Exception: public Crypto::Exception {
				public:
					/**
					 * @brief Replace literal `{}` in a random failure message.
					 * @tparam Args Arguments accepted by Safe::String::ReplaceToken.
					 * @param pattern Message with literal `{}` tokens.
					 * @param args Replacements in order.
					 */
					template<typename... Args>
						requires (sizeof...(Args) >= 1)
					explicit Exception(std::string_view pattern, Args&&... args)
						: Crypto::Exception(StormByte::Exception::Path{"Random"}, pattern, std::forward<Args>(args)...) {}

					/**
					 * @brief Construct a plain random failure message.
					 * @param message Exception body.
					 */
					explicit Exception(std::string_view message)
						: Crypto::Exception(Path{"Random"}, message) {}

					/**
					 * @brief Copy an exception.
					 * @param other Source exception.
					 */
					Exception(const Exception& other);

					/**
					 * @brief Move an exception.
					 * @param other Source exception.
					 */
					Exception(Exception&& other) noexcept;

					/**
					 * @brief Destroy in this module so catches match across a DLL.
					 */
					~Exception() noexcept override;

					/**
					 * @brief Copy-assign an exception.
					 * @param other Source exception.
					 * @return This exception.
					 */
					Exception& operator=(const Exception& other);

					/**
					 * @brief Move-assign an exception.
					 * @param other Source exception.
					 * @return This exception.
					 */
					Exception& operator=(Exception&& other) noexcept;
			};
		}
	}
}

STORMBYTE_DECLARE_MAYBE_SAFE(StormByte::Crypto::Random::Exception);
