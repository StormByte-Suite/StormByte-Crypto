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

#include <StormByte/crypto/engine/crypter/details.hxx>
#include <StormByte/crypto/helpers/password_view.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/safe/vector.hxx>

#include <pwdbased.h>
#include <secblock.h>

#include <cstddef>
#include <cstdint>

/**
 * @namespace StormByte::Crypto::Engine::Crypter::Symmetric
 * @brief Private symmetric crypter implementation.
 */
namespace StormByte::Crypto::Engine::Crypter::Symmetric {
#ifdef STORMBYTE_CRYPTO_INSECURE_PBKDF2_ITERATIONS_FOR_CI
	/**
	 * @brief Reduced PBKDF2 work factor for explicitly insecure CI configurations.
	 */
	inline constexpr unsigned int Pbkdf2Iterations = 1000;
#else
	/**
	 * @brief Production PBKDF2 work factor.
	 */
	inline constexpr unsigned int Pbkdf2Iterations = 600000;
#endif

	/**
	 * @brief Derive a key with PBKDF2-HMAC.
	 * @tparam CryptoHMAC HMAC hash.
	 * @param key Pre-sized output.
	 * @param salt Salt.
	 * @param password Password.
	 * @return Crypto++ DeriveKey result, or 0.
	 */
	template<class CryptoHMAC>
	std::size_t DeriveKey(Safe::Vector<unsigned char>& key,
					const Safe::Vector<unsigned char>& salt,
					const Secure::Password& password) noexcept {
		try {
			CryptoPP::PKCS5_PBKDF2_HMAC<CryptoHMAC> pbkdf2;
			const unsigned char* pwdData = Helpers::PasswordAccess::Data(password);
			const std::size_t pwdSize = Helpers::PasswordAccess::Size(password);
			return pbkdf2.DeriveKey(
				key.data(),
				static_cast<std::size_t>(key.size()),
				0,
				pwdData ? pwdData : reinterpret_cast<const std::uint8_t*>(""),
				pwdSize,
				salt.data(),
				static_cast<std::size_t>(salt.size()),
				Pbkdf2Iterations
			);
		} catch (...) {
			return 0;
		}
	}

	/**
	 * @brief Set key and IV on a Crypto++ cipher.
	 * @tparam CryptorT Crypto++ cipher type.
	 * @param cryptor Cipher to initialize.
	 * @param key Derived key.
	 * @param keylen Key length in bytes.
	 * @param iv Initialization vector.
	 * @param ivlen Initialization vector length in bytes.
	 */
	template<typename CryptorT>
	void SetKeyIV(CryptorT& cryptor,
				const Safe::Vector<unsigned char>& key, std::size_t keylen,
				const Safe::Vector<unsigned char>& iv, std::size_t ivlen) {
		if constexpr (requires { cryptor.SetKeyWithIV(key.data(), keylen, iv.data(), ivlen); })
			cryptor.SetKeyWithIV(key.data(), keylen, iv.data(), ivlen);
		else {
			cryptor.SetKeyWithoutResync(key.data(), keylen, CryptoPP::g_nullNameValuePairs);
			cryptor.Resync(iv.data(), static_cast<int>(ivlen));
		}
	}
}
