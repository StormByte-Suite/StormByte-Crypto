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
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>
#include <StormByte/safe/binary.hxx>
#include <StormByte/safe/pointers.hxx>

#include <cstddef>
#include <cstdint>
#include <secblock.h>
#include <span>

/**
 * @namespace StormByte::Crypto::Engine::Crypter::Asymmetric
 * @brief Private asymmetric crypter implementation.
 */
namespace StormByte::Crypto::Engine::Crypter::Asymmetric {
	inline constexpr std::size_t SymKeyLen = 32;	///< AES-256 key in hybrid envelopes.
	inline constexpr std::size_t IvLen = 12;		///< GCM IV in hybrid envelopes.

					/**
					 * @struct PkBox
					 * @brief Type-erased public/private transform.
					 */
					struct PkBox {
		/**
		 * @brief Construct a type-erased key transform.
		 */
		PkBox() = default;

		/**
		 * @brief Disable copying a key transform.
		 * @param other Source transform.
		 */
		PkBox(const PkBox& other) = delete;

		/**
		 * @brief Disable moving a key transform.
		 * @param other Source transform.
		 */
		PkBox(PkBox&& other) = delete;

		/**
		 * @brief Destroy the concrete key transform.
		 */
		virtual ~PkBox() = default;

		/**
		 * @brief Disable copy assignment.
		 * @param other Source transform.
		 * @return This transform.
		 */
		PkBox& operator=(const PkBox& other) = delete;

		/**
		 * @brief Disable move assignment.
		 * @param other Source transform.
		 * @return This transform.
		 */
		PkBox& operator=(PkBox&& other) = delete;

						/**
						 * @brief Transform raw bytes with the key.
						 * @param in Input.
						 * @param out Destination.
						 * @return true on success.
						 */
		virtual bool Transform(std::span<const std::byte> in, Safe::Binary& out) = 0;
					};

					/**
					 * @brief Write hybrid header: eskLen(4 BE) || esk || iv.
					 * @param esk Encrypted session key.
					 * @param iv IV.
					 * @param out Destination.
					 * @return true on success.
					 */
	bool WriteEnvelopeHeader(const Safe::Binary& esk, const CryptoPP::SecByteBlock& iv, Safe::Binary& out) noexcept;

					/**
					 * @brief Parse eskLen (4 bytes, big-endian).
					 * @param lenBytes Length field.
					 * @return Length, or 0 if size is not 4.
					 */
	std::uint32_t ParseEskLength(const Safe::Binary& lenBytes) noexcept;

					/**
					 * @brief One-shot native PK transform.
					 * @param data Input.
					 * @param output Destination.
					 * @param box Engine.
					 * @return true on success.
					 */
	bool NativeProcessSpan(std::span<const std::byte> data, Buffer::WriteOnly& output, Safe::Unique<PkBox> box) noexcept;

					/**
					 * @brief Streaming native PK. Each chunk is independent.
					 * @param consumer Input consumer.
					 * @param mode Copy or move.
					 * @param box Engine.
					 * @return Consumer with the result.
					 */
	Buffer::Consumer NativeProcessStream(Buffer::Consumer consumer, ReadMode mode, Safe::Unique<PkBox> box) noexcept;

					/**
					 * @brief One-shot hybrid encrypt. box wraps the session key.
					 * @param data Input.
					 * @param output Destination.
					 * @param box Public-key box.
					 * @return true on success.
					 */
	bool HybridEncryptSpan(std::span<const std::byte> data, Buffer::WriteOnly& output, Safe::Unique<PkBox> box) noexcept;

					/**
					 * @brief Streaming hybrid encrypt.
					 * @param consumer Input consumer.
					 * @param mode Copy or move.
					 * @param box Public-key box.
					 * @return Consumer with the envelope.
					 */
	Buffer::Consumer HybridEncryptStream(Buffer::Consumer consumer, ReadMode mode, Safe::Unique<PkBox> box) noexcept;

					/**
					 * @brief One-shot hybrid decrypt. box unwraps the session key.
					 * @param data Input.
					 * @param output Destination.
					 * @param box Private-key box.
					 * @return true on success.
					 */
	bool HybridDecryptSpan(std::span<const std::byte> data, Buffer::WriteOnly& output, Safe::Unique<PkBox> box) noexcept;

					/**
					 * @brief Streaming hybrid decrypt.
					 * @param consumer Input consumer.
					 * @param mode Copy or move.
					 * @param box Private-key box.
					 * @return Consumer with the plaintext.
					 */
	Buffer::Consumer HybridDecryptStream(Buffer::Consumer consumer, ReadMode mode, Safe::Unique<PkBox> box) noexcept;
}
