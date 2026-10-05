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

#include <StormByte/byte_size.hxx>
#include <StormByte/crypto/visibility.h>
#include <StormByte/platform.h>
#include <StormByte/safe/pointers.hxx>
#include <StormByte/safe/string.hxx>
#include <StormByte/size.hxx>
#include <StormByte/type_traits/safe.hxx>

#include <string>
#include <utility>

namespace StormByte::Crypto::Helpers {
	class SecureContent;
	struct PasswordAccess;
}

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
			 * @class Password
			 * @brief Shared, wiped container for passwords and raw key material.
			 *
			 * Bytes live in Crypto-owned secure storage behind a Safe::Shared owner and are wiped
			 * when the last owner is destroyed. Copies share the same buffer. There
			 * is no public view of the raw bytes: once ingested, the secret only
			 * exists inside this object (and any @ref StormByte::Crypto::Secure::Vault
			 * that still holds a share).
			 * @note MaybeSafe requires compatible compiler ABI and the Crypto module to remain loaded
			 * while passwords exist. Copy, move, assignment and destruction run out of line in Crypto;
			 * secure storage is released by its owning module. No caller allocation is adopted.
			 *
			 * ## Why ingest is a non-const reference, not a view and not a move
			 *
			 * A password that stays in the caller's `std::string`
			 * after construction is a leftover secret. `std::string_view` cannot wipe
			 * that source (it does not own it) and would encourage keeping the
			 * original buffer alive. Passing `std::string` by value or by move across
			 * a DLL boundary is also unsafe: the string's buffer is allocated by the
			 * caller's CRT/heap, and destroying or moving it inside this library can
			 * free the wrong heap.
			 *
			 * Therefore the caller *cedes* a non-const `std::string&` or `Safe::String&`.
			 * Construction copies the bytes into wiped storage and then overwrites and clears the
			 * source. The std::string overload is force-inlined so its storage operations
			 * remain in the caller's CRT. After return the argument is empty; the only remaining
			 * copy is the one Password owns.
			 *
			 * String literals (`Password("secret")`) use `const char*`. They are
			 * copied and the source is not wiped: a literal lives in read-only
			 * storage. That form is for tests and non-secret placeholders, not for
			 * production secrets typed in source.
			 *
			 * Raw bytes (`const void*` + @ref StormByte::ByteSize) are copied and
			 * not wiped; the caller is responsible for the source buffer.
			 */
			class STORMBYTE_CRYPTO_PUBLIC Password {
				public:
					/**
					 * @name Construction
					 * @{
					 */
					/**
					 * @brief Empty password, suitable for Safe collections.
					 */
					Password() noexcept;

					/**
					 * @brief From a std::string. Copies into secure storage and wipes @p value in the caller's CRT.
					 * @param value Password characters. Emptied and zeroed on return.
					 */
					STORMBYTE_FORCE_INLINE explicit Password(std::string& value) noexcept
						: Password(value.data(), StormByte::ByteSize{value.size()}) {
						volatile char* bytes = value.data();
						for (std::size_t index = 0; index < value.size(); ++index)
							bytes[index] = 0;
						value.clear();
						value.shrink_to_fit();
					}

					/**
					 * @brief From DLL-safe text. Copies into secure storage and wipes @p value.
					 * @param value Password characters. Emptied and zeroed on return.
					 * @note Copies and wipes the full stored length, including embedded NUL bytes.
					 */
					explicit Password(StormByte::Safe::String& value) noexcept;

					/**
					 * @brief From a C string up to the terminator. The source is not wiped.
					 * @param value Null-terminated password (including literals).
					 */
					explicit Password(const char* value) noexcept;

					/**
					 * @brief From raw bytes. Exact size; no terminator is added. The source is not wiped.
					 * @param data Bytes, or nullptr if size is 0.
					 * @param size Number of bytes.
					 */
					Password(const void* data, StormByte::ByteSize size) noexcept;

					/**
					 * @brief Copy constructor. Shares the buffer.
					 * @param other Password to copy.
					 */
					Password(const Password& other);

					/**
					 * @brief Move constructor.
					 * @param other Password to move.
					 */
					Password(Password&& other) noexcept;

					/**
					 * @brief Destructor. Wipes the buffer if this is the last owner.
					 */
					~Password();

					/**
					 * @brief Copy assignment.
					 * @param other Password to copy.
					 * @return Reference to this password.
					 */
					Password& operator=(const Password& other);

					/**
					 * @brief Move assignment.
					 * @param other Password to move.
					 * @return Reference to this password.
					 */
					Password& operator=(Password&& other) noexcept;
					/** @} */

					/**
					 * @brief Stored size in bytes.
					 * @return Byte count.
					 */
					StormByte::ByteSize Size() const noexcept;

					/**
					 * @brief Whether Size() is 0.
					 * @return true if empty.
					 */
					bool Empty() const noexcept;

					/**
					 * @brief true if the password is not empty.
					 */
					explicit operator bool() const noexcept;

					/**
					 * @brief Constant-time equality.
					 * @param other Other password.
					 * @return true if length and content match.
					 */
					bool operator==(const Password& other) const noexcept;

					/**
					 * @brief Inequality.
					 * @param other Other password.
					 * @return true if not equal.
					 */
					bool operator!=(const Password& other) const noexcept;

				private:
					friend struct Helpers::PasswordAccess;

					StormByte::Safe::Shared<Helpers::SecureContent> m_data;	///< DLL-safe shared owner of wiped storage
			};
		}
	}
}

STORMBYTE_DECLARE_MAYBE_SAFE(StormByte::Crypto::Secure::Password);
