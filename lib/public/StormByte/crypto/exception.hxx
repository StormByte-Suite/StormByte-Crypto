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

#include <StormByte/crypto/visibility.h>
#include <StormByte/exception.hxx>
#include <StormByte/safe/string.hxx>
#include <StormByte/type_traits/safe.hxx>

#include <format>
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
		 * @class Exception
		 * @brief Root exception for Crypto. `what()` is `StormByte.Crypto: message`.
		 *
		 * Forwards the format and the arguments. Does not format.
		 * A child segment is prepended under `Crypto`.
		 */
		class STORMBYTE_CRYPTO_PUBLIC Exception: public StormByte::Exception {
			public:
				/**
				 * @name Construction
				 * @{
				 */
				/**
				 * @brief Format under `StormByte.Crypto`.
				 * @tparam Args Format argument types.
				 * @param fmt Format string.
				 * @param args Format arguments.
				 */
				template<typename... Args>
				explicit Exception(std::format_string<Args...> fmt, Args&&... args)
					: StormByte::Exception(Path{"Crypto"}, fmt, std::forward<Args>(args)...) {}

				/**
				 * @brief Plain message under `StormByte.Crypto`.
				 * @param message Exception text. Not a format string.
				 */
				explicit Exception(std::string_view message)
					: StormByte::Exception(Path{"Crypto"}, "{}", message) {}

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
				 * @brief Format under StormByte.Crypto plus the child segment.
				 * @tparam Args Format argument types.
				 * @param child Segment under `Crypto`.
				 * @param fmt Format string.
				 * @param args Format arguments.
				 */
				template<typename... Args>
				explicit Exception(Path child, std::format_string<Args...> fmt, Args&&... args)
					: StormByte::Exception(
						Path{Safe::String{"Crypto."}.append(child.text)},
						fmt,
						std::forward<Args>(args)...) {}

				/**
				 * @brief Plain message under StormByte.Crypto plus the child segment.
				 * @param child Segment under `Crypto`.
				 * @param message Exception text. Not a format string.
				 */
				explicit Exception(Path child, std::string_view message)
					: StormByte::Exception(
						Path{Safe::String{"Crypto."}.append(child.text)},
						"{}",
						message) {}
		};
	}
}

STORMBYTE_DECLARE_MAYBE_SAFE(StormByte::Crypto::Exception);
