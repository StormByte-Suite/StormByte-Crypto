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

#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>
#include <StormByte/safe/binary.hxx>
#include <StormByte/safe/pointers.hxx>

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
		 * @namespace StormByte::Crypto::Engine
		 * @brief Private implementation of the Crypto module.
		 */
		namespace Engine {
			/**
			 * @namespace StormByte::Crypto::Engine::Crypter
			 * @brief Private crypter implementation.
			 */
			namespace Crypter {
				/**
				 * @struct Ops
				 * @brief Chunk encrypt/decrypt engine (symmetric and asymmetric).
				 */
				struct Ops {
					/**
					 * @brief Construct a chunk engine interface.
					 */
					Ops() = default;

					/**
					 * @brief Copy the engine interface.
					 * @param other Source interface.
					 */
					Ops(const Ops& other) = default;

					/**
					 * @brief Move the engine interface.
					 * @param other Source interface.
					 */
					Ops(Ops&& other) noexcept = default;

					/**
					 * @brief Destroy the concrete chunk engine.
					 */
					virtual ~Ops() = default;

					/**
					 * @brief Copy-assign the engine interface.
					 * @param other Source interface.
					 * @return This interface.
					 */
					Ops& operator=(const Ops& other) = default;

					/**
					 * @brief Move-assign the engine interface.
					 * @param other Source interface.
					 * @return This interface.
					 */
					Ops& operator=(Ops&& other) noexcept = default;

					/**
					 * @brief Optional header write (salt||IV, hybrid envelope).
					 * @param outChunk Destination.
					 * @return true on success.
					 */
					virtual bool WriteHeader(Safe::Binary& outChunk) {
						outChunk.clear();
						return true;
					}

					/**
					 * @brief Optional header read from a span (one-shot decrypt).
					 * @param in Input; advanced past the header.
					 * @return true on success.
					 */
					virtual bool ReadHeader(std::span<const std::byte>& /*in*/) {
						return true;
					}

					/**
					 * @brief Optional header read from a Consumer (streaming decrypt).
					 * @param consumer Input consumer.
					 * @return true on success.
					 */
					virtual bool ReadHeader(Buffer::Consumer& /*consumer*/) {
						return true;
					}

					/**
					 * @brief Process one chunk.
					 * @param in Input bytes.
					 * @param outChunk Output chunk.
					 * @return true on success.
					 */
					virtual bool Process(std::span<const std::byte> in, Safe::Binary& outChunk) = 0;

					/**
					 * @brief Finish and emit padding/tag.
					 * @param outChunk Output chunk.
					 * @return true on success.
					 */
					virtual bool Finalize(Safe::Binary& outChunk) = 0;
				};

				/**
				 * @brief One-shot encrypt/decrypt.
				 * @param data Input.
				 * @param output Destination.
				 * @param ops Crypto-created engine owner, consumed by this call.
				 * @return true on success.
				 */
				STORMBYTE_CRYPTO_PRIVATE bool ProcessSpan(std::span<const std::byte> data, Buffer::WriteOnly& output, Safe::Unique<Ops> ops) noexcept;

				/**
				 * @brief Streaming encrypt/decrypt.
				 * @param consumer Input consumer.
				 * @param mode Copy or move.
				 * @param ops Crypto-created engine owner, transferred to the worker.
				 * @return Consumer with the result or a permanent error.
				 */
				STORMBYTE_CRYPTO_PRIVATE Buffer::Consumer Stream(Buffer::Consumer consumer, ReadMode mode, Safe::Unique<Ops> ops) noexcept;
			}
		}
	}
}
