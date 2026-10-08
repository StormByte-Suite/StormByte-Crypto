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

#include <StormByte/crypto/engine/crypter/symmetric/declarations.hxx>
#include <StormByte/crypto/engine/crypter/symmetric/details.hxx>
#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/random.hxx>
#include <StormByte/safe/binary.hxx>
#include <StormByte/safe/pointers.hxx>
#include <StormByte/safe/vector.hxx>

#include <filters.h>
#include <secblock.h>

#include <cstddef>
#include <cstring>
#include <span>
#include <type_traits>
#include <utility>

/**
 * @namespace StormByte::Crypto::Engine::Crypter::Symmetric
 * @brief Private symmetric crypter implementation.
 */
namespace StormByte::Crypto::Engine::Crypter::Symmetric {
	/**
	 * @class CipherOps
	 * @brief CBC or authenticated engine with Base-owned state and private backend queues.
	 * @tparam Cipher Crypto++ cipher type.
	 * @tparam Hash PBKDF2 hash type.
	 * @tparam Authenticated Whether authenticated filters are used.
	 * @tparam Encrypting Whether this engine encrypts.
	 * @tparam Streaming Whether processing spans multiple input chunks.
	 */
	template<class Cipher, class Hash, bool Authenticated, bool Encrypting, bool Streaming>
	class CipherOps final: public Crypter::Ops {
		public:
			/**
			 * @brief Size key material and copy additional authenticated data.
			 * @param password Password material.
			 * @param saltSize Salt byte count.
			 * @param ivSize Initialization vector byte count.
			 * @param keySize Key byte count.
			 * @param aad Additional authenticated data.
			 */
			CipherOps(Secure::Password password, ByteSize saltSize, ByteSize ivSize,
				ByteSize keySize, std::span<const std::byte> aad = {}):
				m_password(std::move(password)), m_salt_size(saltSize), m_iv_size(ivSize),
				m_key_size(keySize), m_aad(aad), m_salt(Size{static_cast<std::size_t>(saltSize)}),
				m_iv(Size{static_cast<std::size_t>(ivSize)}), m_key(Size{static_cast<std::size_t>(keySize)}) {}

			/**
			 * @brief Engines cannot duplicate live cipher state.
			 * @param other Source engine.
			 */
			CipherOps(const CipherOps& other) = delete;

			/**
			 * @brief Engines remain at the address borrowed by their filter.
			 * @param other Source engine.
			 */
			CipherOps(CipherOps&& other) = delete;

			/**
			 * @brief Release the filter before wiping key material.
			 */
			~CipherOps() noexcept override {
				m_filter.reset();
				Helpers::SecureWipe(m_key);
				Helpers::SecureWipe(m_salt);
				Helpers::SecureWipe(m_iv);
			}

			/**
			 * @brief Live cipher state cannot be copy-assigned.
			 * @param other Source engine.
			 * @return This engine.
			 */
			CipherOps& operator=(const CipherOps& other) = delete;

			/**
			 * @brief Live cipher state cannot be move-assigned.
			 * @param other Source engine.
			 * @return This engine.
			 */
			CipherOps& operator=(CipherOps&& other) = delete;

			/**
			 * @brief Emit salt and IV and initialize an encryption filter.
			 * @param output Header destination; empty for decryption.
			 * @return Whether initialization succeeded.
			 */
			bool WriteHeader(Safe::Binary& output) override {
				output.clear();
				if constexpr (!Encrypting)
					return true;
				try {
					RNG().GenerateBlock(m_salt.data(), static_cast<std::size_t>(m_salt.size()));
					RNG().GenerateBlock(m_iv.data(), static_cast<std::size_t>(m_iv.size()));
					if (!Initialize())
						return false;
					output.reserve(m_salt_size + m_iv_size);
					output.append(reinterpret_cast<const std::byte*>(m_salt.data()), m_salt_size);
					output.append(reinterpret_cast<const std::byte*>(m_iv.data()), m_iv_size);
					Helpers::SecureWipe(m_salt);
					return true;
				} catch (...) {
					return false;
				}
			}

			/**
			 * @brief Consume salt and IV from one-shot ciphertext.
			 * @param input Input advanced past the header on success.
			 * @return Whether initialization succeeded.
			 */
			bool ReadHeader(std::span<const std::byte>& input) override {
				if constexpr (Encrypting)
					return true;
				const auto saltSize = static_cast<std::size_t>(m_salt_size);
				const auto ivSize = static_cast<std::size_t>(m_iv_size);
				if (saltSize > input.size_bytes() || ivSize > input.size_bytes() - saltSize)
					return false;
				try {
					std::memcpy(m_salt.data(), input.data(), saltSize);
					std::memcpy(m_iv.data(), input.data() + saltSize, ivSize);
					input = input.subspan(saltSize + ivSize);
					return Initialize();
				} catch (...) {
					return false;
				}
			}

			/**
			 * @brief Extract salt and IV from streaming ciphertext.
			 * @param consumer Ciphertext source.
			 * @return Whether initialization succeeded.
			 */
			bool ReadHeader(Buffer::Consumer& consumer) override {
				if constexpr (Encrypting)
					return true;
				try {
					Safe::Binary salt;
					Safe::Binary iv;
					if (!consumer.Extract(m_salt_size, salt) || !consumer.Extract(m_iv_size, iv))
						return false;
					std::memcpy(m_salt.data(), salt.data(), static_cast<std::size_t>(m_salt_size));
					std::memcpy(m_iv.data(), iv.data(), static_cast<std::size_t>(m_iv_size));
					return Initialize();
				} catch (...) {
					return false;
				}
			}

			/**
			 * @brief Process bytes and drain output from the private backend queue.
			 * @param input Message bytes.
			 * @param output Output destination.
			 * @return Whether processing succeeded, including one-shot authentication.
			 */
			bool Process(std::span<const std::byte> input, Safe::Binary& output) override {
				if (!m_filter || m_finished)
					return false;
				try {
					m_filter->Put(reinterpret_cast<const CryptoPP::byte*>(input.data()), input.size_bytes());
					if constexpr (!Streaming) {
						m_filter->MessageEnd();
						m_finished = true;
					}
					Drain(output);
					return true;
				} catch (...) {
					return false;
				}
			}

			/**
			 * @brief Finish padding or authentication and drain remaining output.
			 * @param output Remaining output destination.
			 * @return Whether completion and authentication succeeded.
			 */
			bool Finalize(Safe::Binary& output) override {
				if (!m_filter)
					return false;
				try {
					if (!m_finished) {
						m_filter->MessageEnd();
						m_finished = true;
					}
					Drain(output);
					m_filter.reset();
					return true;
				} catch (...) {
					return false;
				}
			}

		private:
			/**
			 * @brief Select the private backend filter for this engine.
			 */
			using Filter = std::conditional_t<Authenticated,
				std::conditional_t<Encrypting, CryptoPP::AuthenticatedEncryptionFilter,
					CryptoPP::AuthenticatedDecryptionFilter>, CryptoPP::StreamTransformationFilter>;

			/**
			 * @brief Derive the key, initialize the cipher and feed AAD.
			 * @return Whether key derivation succeeded.
			 */
			bool Initialize() {
				if (!DeriveKey<Hash>(m_key, m_salt, m_password))
					return false;
				SetKeyIV(m_cipher, m_key, static_cast<std::size_t>(m_key_size),
					m_iv, static_cast<std::size_t>(m_iv_size));
				m_filter = Safe::Unique<Filter>::template MakePointer<Filter>(m_cipher);
				if constexpr (Authenticated) {
					if (!m_aad.empty())
						m_filter->ChannelPut("AAD", reinterpret_cast<const CryptoPP::byte*>(m_aad.data()),
							static_cast<std::size_t>(m_aad.size()));
					m_filter->ChannelMessageEnd("AAD");
				}
				return true;
			}

			/**
			 * @brief Drain the Crypto++ queue without transferring a sink's ownership.
			 * @param output Destination bytes.
			 */
			void Drain(Safe::Binary& output) {
				const ByteSize count{m_filter->MaxRetrievable()};
				output.resize(count);
				if (!output.empty())
					m_filter->Get(reinterpret_cast<CryptoPP::byte*>(output.data()), static_cast<std::size_t>(count));
			}

			Secure::Password m_password;	///< Password material.
			ByteSize m_salt_size;		///< Salt byte count.
			ByteSize m_iv_size;			///< Initialization vector byte count.
			ByteSize m_key_size;			///< Key byte count.
			Safe::Binary m_aad;			///< Owned additional authenticated data.
			Safe::Vector<unsigned char> m_salt;	///< Base-owned salt wiped at destruction.
			Safe::Vector<unsigned char> m_iv;	///< Base-owned IV wiped at destruction.
			Safe::Vector<unsigned char> m_key;	///< Base-owned derived key wiped at destruction.
			Cipher m_cipher;				///< Private backend cipher, outlives its filter.
			Safe::Unique<Filter> m_filter;	///< Base-allocated filter with creator-module destruction.
			bool m_finished = false;		///< Whether MessageEnd has succeeded.
	};
}