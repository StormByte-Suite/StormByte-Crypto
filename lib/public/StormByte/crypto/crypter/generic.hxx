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
		 * @namespace StormByte::Crypto::Crypter
		 * @brief Ciphers of the Crypto module.
		 */
		namespace Crypter {
			/**
			 * @enum Type
			 * @brief Available ciphers.
			 */
			enum class Type {
				AES_GCM,	///< AES-GCM
				AES,		///< AES-CBC
				Camellia,	///< Camellia-CBC
				ChaChaPoly,	///< ChaCha20-Poly1305
				ECC,		///< Elliptic-curve encryption
				Serpent,	///< Serpent-CBC
				RSA,		///< RSA
				TwoFish		///< Twofish-CBC
			};

			/**
			 * @class Generic
			 * @brief Abstract crypter. Concrete ciphers derive from this.
			 */
			class STORMBYTE_CRYPTO_PUBLIC Generic: public StormByte::Safe::Clonable<Generic> {
				public:
					/**
					 * @name Construction
					 * @{
					 */
					/**
					 * @brief Copy constructor.
					 * @param other Crypter to copy.
					 */
					Generic(const Generic& other) = default;

					/**
					 * @brief Move constructor.
					 * @param other Crypter to move.
					 */
					Generic(Generic&& other) noexcept = default;

					/**
					 * @brief Destructor.
					 */
					virtual ~Generic() noexcept;

					/**
					 * @brief Copy assignment.
					 * @param other Crypter to copy.
					 * @return Reference to this crypter.
					 */
					Generic& operator=(const Generic& other) = default;

					/**
					 * @brief Move assignment.
					 * @param other Crypter to move.
					 * @return Reference to this crypter.
					 */
					Generic& operator=(Generic&& other) noexcept = default;
					/** @} */

					/**
					 * @name Encrypt
					 * @{
					 */
					/**
					 * @brief Encrypt a byte span.
					 * @param input Input bytes.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					inline bool Encrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
						return DoEncrypt(input, output);
					}

					/**
					 * @brief Encrypt an input range of byte-convertible values.
					 * @tparam Range Input range type.
					 * @param input Input values.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					template<StormByte::Type::ByteInputRange Range>
					bool Encrypt(const Range& input, Buffer::WriteOnly& output) const {
						StormByte::BinaryData data;
						for (const auto value: input) {
							data.emplace_back(static_cast<std::byte>(value));
						}
						return Encrypt(std::span<const std::byte>(data), output);
					}

					/**
					 * @brief Encrypt a read-only buffer (copy).
					 * @param input Input buffer.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					inline bool Encrypt(const Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
						return DoEncrypt(const_cast<Buffer::ReadOnly&>(input), output, ReadMode::Copy);
					}

					/**
					 * @brief Encrypt a buffer, consuming it.
					 * @param input Input buffer.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					inline bool Encrypt(Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
						return DoEncrypt(input, output, ReadMode::Move);
					}

					/**
					 * @brief Encrypt a Consumer into another Consumer.
					 * @param consumer Input consumer.
					 * @param mode Copy or move.
					 * @return Consumer with ciphertext.
					 */
					inline Buffer::Consumer Encrypt(Buffer::Consumer consumer, ReadMode mode = ReadMode::Move) const noexcept {
						return DoEncrypt(consumer, mode);
					}
					/** @} */

					/**
					 * @name Decrypt
					 * @{
					 */
					/**
					 * @brief Decrypt a byte span.
					 * @param input Input bytes.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					inline bool Decrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
						return DoDecrypt(input, output);
					}

					/**
					 * @brief Decrypt an input range of byte-convertible values.
					 * @tparam Range Input range type.
					 * @param input Input values.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					template<StormByte::Type::ByteInputRange Range>
					bool Decrypt(const Range& input, Buffer::WriteOnly& output) const {
						StormByte::BinaryData data;
						for (const auto value: input) {
							data.emplace_back(static_cast<std::byte>(value));
						}
						return Decrypt(std::span<const std::byte>(data), output);
					}

					/**
					 * @brief Decrypt a read-only buffer (copy).
					 * @param input Input buffer.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					inline bool Decrypt(const Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
						return DoDecrypt(const_cast<Buffer::ReadOnly&>(input), output, ReadMode::Copy);
					}

					/**
					 * @brief Decrypt a buffer, consuming it.
					 * @param input Input buffer.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					inline bool Decrypt(Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
						return DoDecrypt(input, output, ReadMode::Move);
					}

					/**
					 * @brief Decrypt a Consumer into another Consumer.
					 * @param consumer Input consumer.
					 * @param mode Copy or move.
					 * @return Consumer with plaintext.
					 */
					inline Buffer::Consumer Decrypt(Buffer::Consumer consumer, ReadMode mode = ReadMode::Move) const noexcept {
						return DoDecrypt(consumer, mode);
					}
					/** @} */

					/**
					 * @brief Cipher of this crypter.
					 * @return Crypter type.
					 */
					inline enum Type Type() const noexcept {
						return m_type;
					}

				protected:
					enum Type m_type;	///< Cipher

					/**
					 * @brief Construct with a cipher.
					 * @param type Cipher.
					 */
					inline Generic(enum Type type):
						m_type(type) {}

					/**
					 * @brief Encrypt a byte span.
					 * @param input Input bytes.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					virtual bool DoEncrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept = 0;

					/**
					 * @brief Encrypt a Consumer.
					 * @param consumer Input consumer.
					 * @param mode Copy or move.
					 * @return Consumer with ciphertext.
					 */
					virtual Buffer::Consumer DoEncrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept = 0;

					/**
					 * @brief Decrypt a byte span.
					 * @param input Input bytes.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					virtual bool DoDecrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept = 0;

					/**
					 * @brief Decrypt a Consumer.
					 * @param consumer Input consumer.
					 * @param mode Copy or move.
					 * @return Consumer with plaintext.
					 */
					virtual Buffer::Consumer DoDecrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept = 0;

				private:
					/**
					 * @brief Encrypt a buffer with an explicit read mode.
					 * @param input Input buffer.
					 * @param output Destination buffer.
					 * @param mode Copy or move.
					 * @return true on success.
					 */
					bool DoEncrypt(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept;

					/**
					 * @brief Decrypt a buffer with an explicit read mode.
					 * @param input Input buffer.
					 * @param output Destination buffer.
					 * @param mode Copy or move.
					 * @return true on success.
					 */
					bool DoDecrypt(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept;
			};
		}
	}
}
