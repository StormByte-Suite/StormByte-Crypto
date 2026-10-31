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

#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/crypto/visibility.h>
#include <StormByte/expected.hxx>
#include <StormByte/safe/binary.hxx>
#include <StormByte/safe/secure_binary.hxx>

#include <cstddef>
#include <cstdint>
#include <span>

namespace StormByte::Crypto::AEAD {
	/**
	 * @brief Supported raw-key authenticated encryption algorithms.
	 */
	enum class Algorithm {
		AES128GCM,	///< AES-GCM with an exactly 16-byte key.
		AES256GCM	///< AES-GCM with an exactly 32-byte key.
	};

	/**
	 * @brief Typed validation, authentication and backend failures.
	 */
	enum class Error {
		UnsupportedAlgorithm,
		InvalidKeySize,
		InvalidNonceSize,
		InvalidTagSize,
		InputTooLong,
		AuthenticationFailed,
		BackendFailure
	};

	inline constexpr std::size_t NonceSize = 12;	///< Only 96-bit nonces are accepted.
	inline constexpr std::size_t TagSize = 16;	///< Only full 128-bit tags are accepted.
	inline constexpr std::uint64_t MaxMessageSize = (std::uint64_t{1} << 36) - 32;	///< GCM byte limit.
	inline constexpr std::uint64_t MaxAADSize = (std::uint64_t{1} << 61) - 1;	///< GCM AAD byte limit.

	/**
	 * @brief Detached public ciphertext and full-length authentication tag.
	 *
	 * Safe::Binary owns each allocation through Base; no backend state or secret
	 * buffer escapes. Compatible ABIs and loaded Crypto/Base modules are required.
	 */
	struct Sealed {
		StormByte::Safe::Binary ciphertext;
		StormByte::Safe::Binary tag;
	};
}

STORMBYTE_DECLARE_MAYBE_SAFE(StormByte::Crypto::AEAD::Sealed);

namespace StormByte::Crypto::AEAD {
	using ExpectedSealed = StormByte::Expected<Sealed, Error>;
	using ExpectedPlaintext = StormByte::Expected<StormByte::Safe::SecureBinary, Error>;

	/**
	 * @brief Encrypt binary plaintext with a raw AES key and detached full tag.
	 * @param algorithm AES128GCM or AES256GCM.
	 * @param key Immutable wiped raw key storage, not a password to derive.
	 * @param nonce Borrowed exactly 12-byte nonce.
	 * @param plaintext Borrowed binary plaintext, possibly empty.
	 * @param aad Borrowed binary additional authenticated data, possibly empty.
	 * @return Ciphertext of exactly plaintext length and a 16-byte tag, or a typed error.
	 * @note The caller MUST ensure nonce uniqueness for each key, across all calls
	 *       and processes. This API generates no nonce, salt, envelope or TLS record.
	 *       Borrowed inputs are copied/consumed synchronously and are never wiped.
	 */
	STORMBYTE_CRYPTO_PUBLIC ExpectedSealed Seal(
		Algorithm algorithm,
		const Secure::Password& key,
		std::span<const std::byte> nonce,
		std::span<const std::byte> plaintext,
		std::span<const std::byte> aad = {}
	);

	/**
	 * @brief Authenticate the entire ciphertext before returning any plaintext.
	 * @param algorithm AES128GCM or AES256GCM.
	 * @param key Immutable wiped raw key storage.
	 * @param nonce Borrowed exactly 12-byte nonce.
	 * @param ciphertext Borrowed binary ciphertext, possibly empty.
	 * @param tag Borrowed exactly 16-byte authentication tag.
	 * @param aad Borrowed binary additional authenticated data, possibly empty.
	 * @return Independently owned wiped plaintext bytes or a typed error; never partial plaintext.
	 * @note A same-length wrong key, nonce, tag, ciphertext or AAD produces
	 *       AuthenticationFailed. Private tentative plaintext is wiped on failure.
	 *       SecureBinary copies own independent buffers. Borrowed views and copies
	 *       into plain Binary are the caller's responsibility. No Crypto++ types escape.
	 */
	STORMBYTE_CRYPTO_PUBLIC ExpectedPlaintext Open(
		Algorithm algorithm,
		const Secure::Password& key,
		std::span<const std::byte> nonce,
		std::span<const std::byte> ciphertext,
		std::span<const std::byte> tag,
		std::span<const std::byte> aad = {}
	);
}
