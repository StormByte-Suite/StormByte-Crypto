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

#include <StormByte/crypto/engine/hasher/details.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

#include <hex.h>
#include <secblock.h>
#include <span>
#include <utility>

/**
 * @namespace StormByte::Crypto::Engine::Hasher
 * @brief Private hasher implementation.
 */
namespace StormByte::Crypto::Engine::Hasher {
	/**
	 * @class ConcreteOps
	 * @brief Private Crypto++ backend with Crypto-owned construction and destruction.
	 * @tparam HasherT Crypto++ hash implementation, retained only inside Crypto.
	 */
	template<class HasherT>
	class ConcreteOps final: public Ops {
		public:
			/**
			 * @brief Construct the private hash backend.
			 */
			ConcreteOps() = default;

			/**
			 * @brief Private backend state cannot be copied.
			 * @param other Source backend.
			 */
			ConcreteOps(const ConcreteOps&) = delete;

			/**
			 * @brief Private backend state cannot be moved.
			 * @param other Source backend.
			 */
			ConcreteOps(ConcreteOps&&) = delete;

			/**
			 * @brief Release Crypto++ state in Crypto.
			 */
			~ConcreteOps() override = default;

			/**
			 * @brief Private backend state cannot be copy-assigned.
			 * @param other Source backend.
			 * @return This backend.
			 */
			ConcreteOps& operator=(const ConcreteOps&) = delete;

			/**
			 * @brief Private backend state cannot be move-assigned.
			 * @param other Source backend.
			 * @return This backend.
			 */
			ConcreteOps& operator=(ConcreteOps&&) = delete;

			/**
			 * @brief Feed a borrowed chunk to Crypto++.
			 * @param input Bytes consumed synchronously.
			 */
			void Update(std::span<const std::byte> input) override {
				m_hash.Update(reinterpret_cast<const CryptoPP::byte*>(input.data()), input.size_bytes());
			}

			/**
			 * @brief Finish the hash and retrieve its uppercase hexadecimal encoding.
			 * @param output Base-owned digest destination.
			 * @return Whether finalization and retrieval succeeded.
			 */
			bool Finalize(Safe::Binary& output) override {
				try {
					const std::size_t digestSize = m_hash.DigestSize();
					CryptoPP::SecByteBlock digest(digestSize);
					m_hash.Final(digest);

					CryptoPP::HexEncoder encoder;
					encoder.Put(digest, digestSize);
					encoder.MessageEnd();
					output.resize(ByteSize{digestSize} * 2);
					const std::size_t outputSize = static_cast<std::size_t>(output.size());
					return encoder.Get(reinterpret_cast<CryptoPP::byte*>(output.data()), outputSize) == outputSize;
				} catch (...) {
					return false;
				}
			}

		private:
			HasherT m_hash;		///< Crypto++ owning backend, never published outside Crypto.
	};

	/**
	 * @brief One-shot hash using a Crypto-created backend.
	 * @tparam HasherT Crypto++ hash type.
	 * @param dataSpan Borrowed input bytes.
	 * @param output Hexadecimal digest destination.
	 * @return Whether hashing and writing succeeded.
	 */
	template<class HasherT>
	STORMBYTE_CRYPTO_PRIVATE bool Hash(std::span<const std::byte> dataSpan, Buffer::WriteOnly& output) noexcept;

	/**
	 * @brief Streaming hash using a Crypto-created backend.
	 * @tparam HasherT Crypto++ hash type.
	 * @param consumer Input consumer.
	 * @param mode Copy or move.
	 * @return Consumer with the hexadecimal digest or a permanent error.
	 */
	template<class HasherT>
	STORMBYTE_CRYPTO_PRIVATE Buffer::Consumer Hash(Buffer::Consumer consumer, ReadMode mode) noexcept;
}

/**
 * @brief Register only the exact private backend specialization.
 * @tparam HasherT Crypto++ hash type owned and destroyed exclusively in Crypto.
 * @note Safe factories retain the concrete Crypto destructor; Crypto++ allocations
 *       remain private. Crypto must stay loaded while any backend owner exists.
 */
template<class HasherT>
struct StormByte::Type::IsMaybeSafe<StormByte::Crypto::Engine::Hasher::ConcreteOps<HasherT>>: std::true_type {};

/**
 * @brief Allocate the private backend on Base's heap and hash borrowed input.
 * @tparam HasherT Crypto++ hash type.
 * @param dataSpan Borrowed input bytes.
 * @param output Hexadecimal digest destination.
 * @return Whether allocation, hashing and writing succeeded.
 */
template<class HasherT>
bool StormByte::Crypto::Engine::Hasher::Hash(std::span<const std::byte> dataSpan, Buffer::WriteOnly& output) noexcept {
	try {
		return ProcessSpan(dataSpan, output, Safe::MakeShared<ConcreteOps<HasherT>>());
	} catch (...) {
		return false;
	}
}

/**
 * @brief Allocate the private backend on Base's heap and start streaming.
 * @tparam HasherT Crypto++ hash type.
 * @param consumer Input consumer.
 * @param mode Copy or move.
 * @return Consumer with the hexadecimal digest or a permanent error.
 */
template<class HasherT>
StormByte::Buffer::Consumer StormByte::Crypto::Engine::Hasher::Hash(Buffer::Consumer consumer, ReadMode mode) noexcept {
	try {
		return Stream(std::move(consumer), mode, Safe::MakeShared<ConcreteOps<HasherT>>());
	} catch (...) {
		return Stream(std::move(consumer), mode, {});
	}
}
