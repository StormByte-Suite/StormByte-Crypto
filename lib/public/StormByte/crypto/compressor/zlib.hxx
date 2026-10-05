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

#include <StormByte/crypto/compressor/generic.hxx>

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
		 * @namespace StormByte::Crypto::Compressor
		 * @brief Compressors of the Crypto module.
		 */
		namespace Compressor {
			/**
			 * @class Zlib
			 * @note MaybeSafe inherits all provider requirements of @ref StormByte::Crypto::Compressor::Generic.
			 * This leaf adds no fields; exported Clone/Move bind ownership callbacks in Crypto.
			 * @brief zlib compressor.
			 */
			class STORMBYTE_CRYPTO_PUBLIC Zlib final: public Generic {
				public:
					/**
					 * @name Construction
					 * @{
					 */
					/**
					 * @brief Construct with a compression level.
					 * @param level Compression level.
					 */
					Zlib(unsigned short level = 5);

					/**
					 * @brief Copy constructor.
					 * @param other Compressor to copy.
					 */
					Zlib(const Zlib& other) = default;

					/**
					 * @brief Move constructor.
					 * @param other Compressor to move.
					 */
					Zlib(Zlib&& other) noexcept = default;

					/**
					 * @brief Destructor.
					 */
					~Zlib() noexcept;

					/**
					 * @brief Copy assignment.
					 * @param other Compressor to copy.
					 * @return Reference to this compressor.
					 */
					Zlib& operator=(const Zlib& other) = default;

					/**
					 * @brief Move assignment.
					 * @param other Compressor to move.
					 * @return Reference to this compressor.
					 */
					Zlib& operator=(Zlib&& other) noexcept = default;
					/** @} */

					/**
					 * @brief Clone this compressor.
					 * @return Shared pointer to the clone.
					 */
					PointerType Clone() const override;

					/**
					 * @brief Move this compressor into a new instance.
					 * @return Shared pointer to the moved compressor.
					 */
					PointerType Move() noexcept override;

				private:
					/**
					 * @brief Compress a byte span.
					 * @param input Input bytes.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					bool DoCompress(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept override;

					/**
					 * @brief Compress a Consumer.
					 * @param consumer Input consumer.
					 * @param mode Copy or move.
					 * @return Consumer with compressed data.
					 */
					Buffer::Consumer DoCompress(Buffer::Consumer consumer, ReadMode mode) const noexcept override;

					/**
					 * @brief Decompress a byte span.
					 * @param input Input bytes.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					bool DoDecompress(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept override;

					/**
					 * @brief Decompress a Consumer.
					 * @param consumer Input consumer.
					 * @param mode Copy or move.
					 * @return Consumer with decompressed data.
					 */
					Buffer::Consumer DoDecompress(Buffer::Consumer consumer, ReadMode mode) const noexcept override;
			};
		}
	}
}

STORMBYTE_DECLARE_MAYBE_SAFE(StormByte::Crypto::Compressor::Zlib);
