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

#include <cstddef>
#include <span>

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
		 * @namespace StormByte::Crypto::HMAC
		 * @brief One-shot message authentication codes.
		 */
		namespace HMAC {
			/**
			 * @enum Algorithm
			 * @brief Supported HMAC hash functions.
			 */
			enum class Algorithm {
				SHA256,	///< HMAC-SHA-256 (32-byte tag)
				SHA384	///< HMAC-SHA-384 (48-byte tag)
			};

			/**
			 * @enum Error
			 * @brief Errors returned by HMAC operations.
			 */
			enum class Error {
				UnsupportedAlgorithm,	///< The supplied algorithm value is not supported.
				InvalidTagSize,			///< The supplied verification tag is not full length.
				BackendFailure			///< The cryptographic backend could not complete the operation.
			};

			/**
			 * @brief Expected full-length binary HMAC tag or a typed error.
			 */
			using ExpectedTag = StormByte::Expected<StormByte::Safe::Binary, Error>;

			/**
			 * @brief Expected verification result or a typed error.
			 */
			using ExpectedVerification = StormByte::Expected<bool, Error>;

			/**
			 * @brief Compute a full-length HMAC over binary input.
			 * @param algorithm HMAC-SHA-256 or HMAC-SHA-384.
			 * @param key Wiped key storage; an empty key follows HMAC semantics.
			 * @param message Borrowed message bytes, including any NUL bytes.
			 * @return Exact-size binary tag, or an error.
			 * @note Keys longer than the hash block size are normalized by HMAC as specified.
			 *       The key's raw bytes and Crypto++ backend types are not exposed publicly.
			 */
			STORMBYTE_CRYPTO_PUBLIC ExpectedTag Compute(
				Algorithm algorithm,
				const Secure::Password& key,
				std::span<const std::byte> message
			);

			/**
			 * @brief Verify a full-length binary HMAC in constant time with respect to tag bytes.
			 * @param algorithm HMAC-SHA-256 or HMAC-SHA-384.
			 * @param key Wiped key storage; an empty key follows HMAC semantics.
			 * @param message Borrowed message bytes, including any NUL bytes.
			 * @param tag Candidate binary tag; truncated or oversized tags are rejected.
			 * @return true for a matching tag, false for a full-length nonmatching tag, or an error.
			 */
			STORMBYTE_CRYPTO_PUBLIC ExpectedVerification Verify(
				Algorithm algorithm,
				const Secure::Password& key,
				std::span<const std::byte> message,
				std::span<const std::byte> tag
			);
		}
	}
}
