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

#include <StormByte/buffer/consumer.hxx>
#include <StormByte/safe/clonable.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>
#include <StormByte/type_traits.hxx>

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
		 * @namespace StormByte::Crypto::Compressor
		 * @brief Compressors of the Crypto module.
		 */
		namespace Compressor {
			/**
			 * @enum Type
			 * @brief Available compressors.
			 */
			enum class Type {
				Bzip2,	///< bzip2
				Zlib	///< zlib
			};

			/**
			 * @class Generic
			 * @brief Abstract compressor. Concrete codecs derive from this.
			 */
			class STORMBYTE_CRYPTO_PUBLIC Generic: public StormByte::Safe::Clonable<Generic> {
				public:
					/**
					 * @name Construction
					 * @{
					 */
					/**
					 * @brief Copy constructor.
					 * @param other Compressor to copy.
					 */
					Generic(const Generic& other) = default;

					/**
					 * @brief Move constructor.
					 * @param other Compressor to move.
					 */
					Generic(Generic&& other) noexcept = default;

					/**
					 * @brief Destructor.
					 */
					virtual ~Generic() noexcept;

					/**
					 * @brief Copy assignment.
					 * @param other Compressor to copy.
					 * @return Reference to this compressor.
					 */
					Generic& operator=(const Generic& other) = default;

					/**
					 * @brief Move assignment.
					 * @param other Compressor to move.
					 * @return Reference to this compressor.
					 */
					Generic& operator=(Generic&& other) noexcept = default;
					/** @} */

					/**
					 * @name Compress
					 * @{
					 */
					/**
					 * @brief Compress a byte span.
					 * @param input Input bytes.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					inline bool Compress(const std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
						return DoCompress(input, output);
					}

					/**
					 * @brief Compress an input range of byte-convertible values.
					 * @tparam Range Input range type.
					 * @param input Input values.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					template<StormByte::Type::ByteInputRange Range>
					bool Compress(const Range& input, Buffer::WriteOnly& output) const {
						StormByte::BinaryData data;
						for (const auto value: input) {
							data.emplace_back(static_cast<std::byte>(value));
						}
						return Compress(std::span<const std::byte>(data), output);
					}

					/**
					 * @brief Compress a read-only buffer (copy).
					 * @param input Input buffer.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					inline bool Compress(const Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
						return DoCompress(const_cast<Buffer::ReadOnly&>(input), output, ReadMode::Copy);
					}

					/**
					 * @brief Compress a buffer, consuming it.
					 * @param input Input buffer.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					inline bool Compress(Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
						return DoCompress(input, output, ReadMode::Move);
					}

					/**
					 * @brief Compress a Consumer into another Consumer.
					 * @param consumer Input consumer.
					 * @param mode Copy or move.
					 * @return Consumer with compressed data.
					 */
					inline Buffer::Consumer Compress(Buffer::Consumer consumer, ReadMode mode = ReadMode::Move) const noexcept {
						return DoCompress(consumer, mode);
					}
					/** @} */

					/**
					 * @name Decompress
					 * @{
					 */
					/**
					 * @brief Decompress a byte span.
					 * @param input Input bytes.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					inline bool Decompress(const std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
						return DoDecompress(input, output);
					}

					/**
					 * @brief Decompress an input range of byte-convertible values.
					 * @tparam Range Input range type.
					 * @param input Input values.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					template<StormByte::Type::ByteInputRange Range>
					bool Decompress(const Range& input, Buffer::WriteOnly& output) const {
						StormByte::BinaryData data;
						for (const auto value: input) {
							data.emplace_back(static_cast<std::byte>(value));
						}
						return Decompress(std::span<const std::byte>(data), output);
					}

					/**
					 * @brief Decompress a read-only buffer (copy).
					 * @param input Input buffer.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					inline bool Decompress(const Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
						return DoDecompress(const_cast<Buffer::ReadOnly&>(input), output, ReadMode::Copy);
					}

					/**
					 * @brief Decompress a buffer, consuming it.
					 * @param input Input buffer.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					inline bool Decompress(Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
						return DoDecompress(input, output, ReadMode::Move);
					}

					/**
					 * @brief Decompress a Consumer into another Consumer.
					 * @param consumer Input consumer.
					 * @param mode Copy or move.
					 * @return Consumer with decompressed data.
					 */
					inline Buffer::Consumer Decompress(Buffer::Consumer consumer, ReadMode mode = ReadMode::Move) const noexcept {
						return DoDecompress(consumer, mode);
					}
					/** @} */

					/**
					 * @brief Compression level.
					 * @return Level.
					 */
					unsigned short Level() const noexcept {
						return m_level;
					}

					/**
					 * @brief Codec of this compressor.
					 * @return Compressor type.
					 */
					inline enum Type Type() const noexcept {
						return m_type;
					}

				protected:
					enum Type m_type;			///< Codec
					unsigned short m_level = 0;	///< Compression level

					/**
					 * @brief Construct with a codec and level.
					 * @param type Codec.
					 * @param level Compression level.
					 */
					inline Generic(enum Type type, unsigned short level = 5):
						m_type(type), m_level(level) {}

				private:
					/**
					 * @brief Compress a byte span.
					 * @param input Input bytes.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					virtual bool DoCompress(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept = 0;

					/**
					 * @brief Compress a buffer with an explicit read mode.
					 * @param input Input buffer.
					 * @param output Destination buffer.
					 * @param mode Copy or move.
					 * @return true on success.
					 */
					bool DoCompress(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept;

					/**
					 * @brief Compress a Consumer.
					 * @param consumer Input consumer.
					 * @param mode Copy or move.
					 * @return Consumer with compressed data.
					 */
					virtual Buffer::Consumer DoCompress(Buffer::Consumer consumer, ReadMode mode) const noexcept = 0;

					/**
					 * @brief Decompress a byte span.
					 * @param input Input bytes.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					virtual bool DoDecompress(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept = 0;

					/**
					 * @brief Decompress a buffer with an explicit read mode.
					 * @param input Input buffer.
					 * @param output Destination buffer.
					 * @param mode Copy or move.
					 * @return true on success.
					 */
					bool DoDecompress(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept;

					/**
					 * @brief Decompress a Consumer.
					 * @param consumer Input consumer.
					 * @param mode Copy or move.
					 * @return Consumer with decompressed data.
					 */
					virtual Buffer::Consumer DoDecompress(Buffer::Consumer consumer, ReadMode mode) const noexcept = 0;
			};

			/**
			 * @brief Factory for a compressor.
			 * @param type Codec.
			 * @param level Compression level.
			 * @return Compressor pointer.
			 */
			STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(Type type, unsigned short level) noexcept;
		}
	}
}
