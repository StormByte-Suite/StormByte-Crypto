/*
 * Copyright (C) 2024-2026 David C. Manuelda (StormBytePP)
 *
 * This file is part of StormByte-Crypto.
 *
 * StormByte-Crypto original source is dual-licensed:
 *
 * 1. GNU Lesser General Public License v3.0 (or later)
 *    You may redistribute and/or modify this file under the terms of the
 *    GNU Lesser General Public License version 3 (or later).
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

#include <cstddef>
#include <span>

namespace StormByte::Crypto::HKDF {
	/**
	 * @brief Supported HKDF hash functions.
	 */
	enum class Algorithm {
		SHA256,	///< HKDF-SHA-256 (32-byte PRK)
		SHA384	///< HKDF-SHA-384 (48-byte PRK)
	};

	/**
	 * @brief Errors returned by HKDF operations.
	 */
	enum class Error {
		UnsupportedAlgorithm,		///< The supplied algorithm value is not supported.
		InvalidPseudorandomKeySize,	///< The PRK is shorter than the hash output size.
		OutputTooLong,				///< The output exceeds 255 times the hash output size.
		BackendFailure				///< The cryptographic backend could not complete the operation.
	};

	/**
	 * @brief Expected secret key material or a typed HKDF error.
	 */
	using ExpectedKey = StormByte::Expected<Secure::Password, Error>;

	/**
	 * @brief HKDF-Extract: derive a pseudorandom key from binary salt and input key material.
	 * @param algorithm HKDF-SHA-256 or HKDF-SHA-384.
	 * @param salt Borrowed salt bytes. An empty salt is treated as HashLen zero bytes.
	 * @param inputKeyMaterial Secret input key material in wiped storage; empty input is valid.
	 * @return PRK in wiped storage, or a typed error.
	 * @note Salt is not considered secret and is not copied into secure storage.
	 */
	STORMBYTE_CRYPTO_PUBLIC ExpectedKey Extract(
		Algorithm algorithm,
		std::span<const std::byte> salt,
		const Secure::Password& inputKeyMaterial
	);

	/**
	 * @brief HKDF-Expand: derive binary secret output from a PRK and context information.
	 * @param algorithm HKDF-SHA-256 or HKDF-SHA-384.
	 * @param pseudorandomKey Wiped PRK, at least HashLen bytes long.
	 * @param info Borrowed context bytes; empty information is valid.
	 * @param outputSize Exact requested output size, including zero.
	 * @return Derived key in wiped storage, or a typed error.
	 * @note The maximum output is 255 times HashLen bytes, as required by RFC 5869.
	 *       Info is not considered secret and is not copied into secure storage.
	 */
	STORMBYTE_CRYPTO_PUBLIC ExpectedKey Expand(
		Algorithm algorithm,
		const Secure::Password& pseudorandomKey,
		std::span<const std::byte> info,
		std::size_t outputSize
	);
}
