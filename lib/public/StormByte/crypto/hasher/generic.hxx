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
		 * @namespace StormByte::Crypto::Hasher
		 * @brief Hash algorithms of the Crypto module.
		 */
		namespace Hasher {
			/**
			 * @enum Type
			 * @brief Available hash algorithms.
			 */
			enum class Type {
				Blake2b,	///< BLAKE2b
				Blake2s,	///< BLAKE2s
				SHA3_256,	///< SHA3-256
				SHA3_512,	///< SHA3-512
				SHA256,		///< SHA-256
				SHA512		///< SHA-512
			};

			/**
			 * @class Generic
			 * @brief Abstract hasher. Concrete algorithms derive from this.
			 */
			class STORMBYTE_CRYPTO_PUBLIC Generic: public StormByte::Safe::Clonable<Generic> {
				public:
					/**
					 * @name Construction
					 * @{
					 */
					/**
					 * @brief Copy constructor.
					 * @param other Hasher to copy.
					 */
					Generic(const Generic& other) = default;

					/**
					 * @brief Move constructor.
					 * @param other Hasher to move.
					 */
					Generic(Generic&& other) noexcept = default;

					/**
					 * @brief Destructor.
					 */
					virtual ~Generic() noexcept;

					/**
					 * @brief Copy assignment.
					 * @param other Hasher to copy.
					 * @return Reference to this hasher.
					 */
					Generic& operator=(const Generic& other) = default;

					/**
					 * @brief Move assignment.
					 * @param other Hasher to move.
					 * @return Reference to this hasher.
					 */
					Generic& operator=(Generic&& other) noexcept = default;
					/** @} */

					/**
					 * @name Hash
					 * @{
					 */
					/**
					 * @brief Hash a byte span into an output buffer.
					 * @param input Input bytes.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					inline bool Hash(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
						return DoHash(input, output);
					}

					/**
					 * @brief Hash an input range of byte-convertible values.
					 * @tparam Range Input range type.
					 * @param input Input values.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					template<StormByte::Type::ByteInputRange Range>
					bool Hash(const Range& input, Buffer::WriteOnly& output) const {
						StormByte::BinaryData data;
						for (const auto value: input) {
							data.emplace_back(static_cast<std::byte>(value));
						}
						return Hash(std::span<const std::byte>(data), output);
					}

					/**
					 * @brief Hash a read-only buffer (copy).
					 * @param input Input buffer.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					inline bool Hash(const Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
						return DoHash(const_cast<Buffer::ReadOnly&>(input), output, ReadMode::Copy);
					}

					/**
					 * @brief Hash a buffer, consuming it.
					 * @param input Input buffer.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					inline bool Hash(Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
						return DoHash(input, output, ReadMode::Move);
					}

					/**
					 * @brief Hash a Consumer into another Consumer.
					 * @param consumer Input consumer.
					 * @param mode Copy or move.
					 * @return Consumer with the digest.
					 */
					inline Buffer::Consumer Hash(Buffer::Consumer consumer, ReadMode mode = ReadMode::Move) const noexcept {
						return DoHash(consumer, mode);
					}

					/**
					 * @brief Algorithm of this hasher.
					 * @return Hasher type.
					 */
					inline enum Type Type() const noexcept {
						return m_type;
					}
					/** @} */

				protected:
					enum Type m_type;	///< Algorithm

					/**
					 * @brief Construct with an algorithm.
					 * @param type Algorithm.
					 */
					inline Generic(enum Type type):
						m_type(type) {}

				private:
					/**
					 * @brief Hash a buffer with an explicit read mode.
					 * @param input Input buffer.
					 * @param output Destination buffer.
					 * @param mode Copy or move.
					 * @return true on success.
					 */
					bool DoHash(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept;

					/**
					 * @brief Hash a byte span.
					 * @param input Input bytes.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					virtual bool DoHash(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept = 0;

					/**
					 * @brief Hash a Consumer.
					 * @param consumer Input consumer.
					 * @param mode Copy or move.
					 * @return Consumer with the digest.
					 */
					virtual Buffer::Consumer DoHash(Buffer::Consumer consumer, ReadMode mode) const noexcept = 0;
			};

			/**
			 * @brief Factory for a hasher.
			 * @param type Algorithm.
			 * @return Hasher pointer.
			 */
			STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(Type type) noexcept;
		}
	}
}
