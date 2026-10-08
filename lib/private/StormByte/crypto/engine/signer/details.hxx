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
#include <string_view>

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
			 * @brief Private engines of the Crypto module.
		 */
		namespace Engine {
			/**
			 * @namespace StormByte::Crypto::Engine::Signer
			 * @brief Private signer implementation.
			 */
			namespace Signer {
				/**
				 * @struct SignBox
				 * @brief Type-erased streaming signer.
				 */
				struct SignBox {
					/**
					 * @brief Construct the erased signing interface.
					 */
					SignBox() = default;

					/**
					 * @brief Erased signing state cannot be copied.
					 * @param other Source backend.
					 */
					SignBox(const SignBox& other) = delete;

					/**
					 * @brief Erased signing state cannot be moved.
					 * @param other Source backend.
					 */
					SignBox(SignBox&& other) = delete;

					/**
					 * @brief Destroy the concrete signer in its creating module.
					 */
					virtual ~SignBox() = default;

					/**
					 * @brief Erased signing state cannot be copy-assigned.
					 * @param other Source backend.
					 * @return This backend.
					 */
					SignBox& operator=(const SignBox& other) = delete;

					/**
					 * @brief Erased signing state cannot be move-assigned.
					 * @param other Source backend.
					 * @return This backend.
					 */
					SignBox& operator=(SignBox&& other) = delete;

					/**
					 * @brief Feed one message chunk.
					 * @param in Input bytes.
					 * @return true on success.
					 */
					virtual bool Update(std::span<const std::byte> in) = 0;

					/**
					 * @brief Finish and write the signature.
					 * @param out Destination.
					 * @return true on success.
					 */
					virtual bool Finalize(Safe::Binary& out) = 0;
				};

				/**
				 * @struct VerifyBox
				 * @brief Type-erased streaming verifier. Call Begin first.
				 */
				struct VerifyBox {
					/**
					 * @brief Construct the erased verification interface.
					 */
					VerifyBox() = default;

					/**
					 * @brief Erased verification state cannot be copied.
					 * @param other Source backend.
					 */
					VerifyBox(const VerifyBox& other) = delete;

					/**
					 * @brief Erased verification state cannot be moved.
					 * @param other Source backend.
					 */
					VerifyBox(VerifyBox&& other) = delete;

					/**
					 * @brief Destroy the concrete verifier in its creating module.
					 */
					virtual ~VerifyBox() = default;

					/**
					 * @brief Erased verification state cannot be copy-assigned.
					 * @param other Source backend.
					 * @return This backend.
					 */
					VerifyBox& operator=(const VerifyBox& other) = delete;

					/**
					 * @brief Erased verification state cannot be move-assigned.
					 * @param other Source backend.
					 * @return This backend.
					 */
					VerifyBox& operator=(VerifyBox&& other) = delete;

					/**
					 * @brief Supply the signature before any Update.
					 * @param signature Signature.
					 * @return true on success.
					 */
					virtual bool Begin(std::string_view signature) = 0;

					/**
					 * @brief Feed one message chunk.
					 * @param in Input bytes.
					 * @return true on success.
					 */
					virtual bool Update(std::span<const std::byte> in) = 0;

					/**
					 * @brief Finish verification.
					 * @return true if valid.
					 */
					virtual bool Finalize() = 0;
				};

				/**
				 * @brief One-shot sign.
				 * @param data Input.
				 * @param output Destination.
				 * @param box Engine.
				 * @return true on success.
				 */
				bool SignSpan(std::span<const std::byte> data, Buffer::WriteOnly& output, Safe::Unique<SignBox> box) noexcept;

				/**
				 * @brief Streaming sign.
				 * @param consumer Input consumer.
				 * @param mode Copy or move.
				 * @param box Engine.
				 * @return Consumer with the signature.
				 */
				Buffer::Consumer SignStream(Buffer::Consumer consumer, ReadMode mode, Safe::Unique<SignBox> box) noexcept;

				/**
				 * @brief One-shot verify.
				 * @param data Input.
				 * @param signature Signature.
				 * @param box Engine.
				 * @return true if valid.
				 */
				bool VerifySpan(std::span<const std::byte> data, std::string_view signature, Safe::Unique<VerifyBox> box) noexcept;

				/**
				 * @brief Streaming verify.
				 * @param consumer Input consumer.
				 * @param mode Copy or move.
				 * @param signature Signature.
				 * @param box Engine.
				 * @return true if valid.
				 */
				bool VerifyStream(Buffer::Consumer consumer, ReadMode mode, std::string_view signature, Safe::Unique<VerifyBox> box) noexcept;
			}
		}
	}
}
