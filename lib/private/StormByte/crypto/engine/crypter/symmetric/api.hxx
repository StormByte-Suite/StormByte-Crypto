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
#include <StormByte/crypto/engine/crypter/symmetric/ops.hxx>

#include <cstddef>
#include <span>
#include <utility>

/**
 * @namespace StormByte::Crypto::Engine::Crypter::Symmetric
 * @brief Private symmetric crypter implementation.
 */
namespace StormByte::Crypto::Engine::Crypter::Symmetric {
	/**
	 * @brief Allocate a named engine and process a complete message.
	 * @tparam Engine Exact certified symmetric engine.
	 * @param input Message bytes.
	 * @param password Password material.
	 * @param output Destination buffer.
	 * @param saltSize Salt byte count.
	 * @param ivSize Initialization vector byte count.
	 * @param keySize Key byte count.
	 * @param aad Additional authenticated data.
	 * @return Whether allocation and processing succeeded.
	 */
	template<class Engine>
	bool ProcessMessage(std::span<const std::byte> input, const Secure::Password& password,
		Buffer::WriteOnly& output, ByteSize saltSize, ByteSize ivSize, ByteSize keySize,
		std::span<const std::byte> aad = {}) noexcept {
		try {
			return Crypter::ProcessSpan(input, output,
				Safe::Unique<Crypter::Ops>::template MakePointer<Engine>(password, saltSize, ivSize, keySize, aad));
		} catch (...) {
			return false;
		}
	}

	/**
	 * @brief Allocate a named engine and process a streaming message.
	 * @tparam Engine Exact certified symmetric engine.
	 * @param consumer Message source.
	 * @param password Password material.
	 * @param mode Input ownership mode.
	 * @param saltSize Salt byte count.
	 * @param ivSize Initialization vector byte count.
	 * @param keySize Key byte count.
	 * @param aad Additional authenticated data.
	 * @return Output consumer, with its error flag set on engine allocation failure.
	 */
	template<class Engine>
	Buffer::Consumer ProcessMessage(Buffer::Consumer consumer, Secure::Password password,
		ReadMode mode, ByteSize saltSize, ByteSize ivSize, ByteSize keySize,
		std::span<const std::byte> aad = {}) noexcept {
		try {
			auto engine = Safe::Unique<Crypter::Ops>::template MakePointer<Engine>(
				std::move(password), saltSize, ivSize, keySize, aad);
			return Crypter::Stream(std::move(consumer), mode, std::move(engine));
		} catch (...) {
			consumer.Producer().SetError();
			return consumer;
		}
	}

	/**
	 * @brief Encrypt a complete CBC message.
	 * @tparam AlgoT Algorithm traits providing DEFAULT_KEYLENGTH.
	 * @tparam CryptorT Crypto++ CBC encryption type.
	 * @tparam CryptoHMAC PBKDF2 hash type.
	 * @param input Plaintext bytes.
	 * @param password Password material.
	 * @param output Envelope destination.
	 * @param saltSize Salt byte count.
	 * @param ivSize Initialization vector byte count.
	 * @param keySize Key byte count.
	 * @return Whether encryption succeeded.
	 */
	template<class AlgoT, class CryptorT, class CryptoHMAC>
	bool EncryptCBC(std::span<const std::byte> input, const Secure::Password& password,
		Buffer::WriteOnly& output, const std::size_t& saltSize, const std::size_t& ivSize,
		const std::size_t& keySize = AlgoT::DEFAULT_KEYLENGTH) noexcept {
		return ProcessMessage<CipherOps<CryptorT, CryptoHMAC, false, true, false>>(
			input, password, output, ByteSize{saltSize}, ByteSize{ivSize}, ByteSize{keySize});
	}

	/**
	 * @brief Encrypt a streaming CBC message.
	 * @tparam AlgoT Algorithm traits providing DEFAULT_KEYLENGTH.
	 * @tparam CryptorT Crypto++ CBC encryption type.
	 * @tparam CryptoHMAC PBKDF2 hash type.
	 * @param consumer Plaintext source.
	 * @param password Password material.
	 * @param mode Input ownership mode.
	 * @param saltSize Salt byte count.
	 * @param ivSize Initialization vector byte count.
	 * @param keySize Key byte count.
	 * @return Consumer containing salt, IV and ciphertext.
	 */
	template<class AlgoT, class CryptorT, class CryptoHMAC>
	Buffer::Consumer EncryptCBC(Buffer::Consumer consumer, Secure::Password password,
		ReadMode mode, const std::size_t& saltSize, const std::size_t& ivSize,
		const std::size_t& keySize = AlgoT::DEFAULT_KEYLENGTH) noexcept {
		return ProcessMessage<CipherOps<CryptorT, CryptoHMAC, false, true, true>>(
			std::move(consumer), std::move(password), mode, ByteSize{saltSize}, ByteSize{ivSize}, ByteSize{keySize});
	}

	/**
	 * @brief Decrypt a complete CBC envelope.
	 * @tparam AlgoT Algorithm traits providing DEFAULT_KEYLENGTH.
	 * @tparam DecryptorT Crypto++ CBC decryption type.
	 * @tparam CryptoHMAC PBKDF2 hash type.
	 * @param input Salt, IV and ciphertext.
	 * @param password Password material.
	 * @param output Plaintext destination.
	 * @param saltSize Salt byte count.
	 * @param ivSize Initialization vector byte count.
	 * @param keySize Key byte count.
	 * @return Whether decryption succeeded.
	 */
	template<class AlgoT, class DecryptorT, class CryptoHMAC>
	bool DecryptCBC(std::span<const std::byte> input, const Secure::Password& password,
		Buffer::WriteOnly& output, const std::size_t& saltSize, const std::size_t& ivSize,
		const std::size_t& keySize = AlgoT::DEFAULT_KEYLENGTH) noexcept {
		return ProcessMessage<CipherOps<DecryptorT, CryptoHMAC, false, false, false>>(
			input, password, output, ByteSize{saltSize}, ByteSize{ivSize}, ByteSize{keySize});
	}

	/**
	 * @brief Decrypt a streaming CBC envelope.
	 * @tparam AlgoT Algorithm traits providing DEFAULT_KEYLENGTH.
	 * @tparam DecryptorT Crypto++ CBC decryption type.
	 * @tparam CryptoHMAC PBKDF2 hash type.
	 * @param consumer Envelope source.
	 * @param password Password material.
	 * @param mode Input ownership mode.
	 * @param saltSize Salt byte count.
	 * @param ivSize Initialization vector byte count.
	 * @param keySize Key byte count.
	 * @return Consumer containing plaintext.
	 */
	template<class AlgoT, class DecryptorT, class CryptoHMAC>
	Buffer::Consumer DecryptCBC(Buffer::Consumer consumer, Secure::Password password,
		ReadMode mode, const std::size_t& saltSize, const std::size_t& ivSize,
		const std::size_t& keySize = AlgoT::DEFAULT_KEYLENGTH) noexcept {
		return ProcessMessage<CipherOps<DecryptorT, CryptoHMAC, false, false, true>>(
			std::move(consumer), std::move(password), mode, ByteSize{saltSize}, ByteSize{ivSize}, ByteSize{keySize});
	}

	/**
	 * @brief Encrypt a complete authenticated message.
	 * @tparam AlgoT Algorithm traits providing DEFAULT_KEYLENGTH.
	 * @tparam CryptorT Crypto++ authenticated encryption type.
	 * @tparam CryptoHMAC PBKDF2 hash type.
	 * @param input Plaintext bytes.
	 * @param password Password material.
	 * @param output Envelope destination.
	 * @param saltSize Salt byte count.
	 * @param ivSize Initialization vector byte count.
	 * @param keySize Key byte count.
	 * @param aad Additional authenticated data.
	 * @return Whether encryption succeeded.
	 */
	template<class AlgoT, class CryptorT, class CryptoHMAC>
	bool EncryptGCM(std::span<const std::byte> input, const Secure::Password& password,
		Buffer::WriteOnly& output, const std::size_t& saltSize, const std::size_t& ivSize,
		const std::size_t& keySize = AlgoT::DEFAULT_KEYLENGTH, std::span<const std::byte> aad = {}) noexcept {
		return ProcessMessage<CipherOps<CryptorT, CryptoHMAC, true, true, false>>(
			input, password, output, ByteSize{saltSize}, ByteSize{ivSize}, ByteSize{keySize}, aad);
	}

	/**
	 * @brief Encrypt a streaming authenticated message.
	 * @tparam AlgoT Algorithm traits providing DEFAULT_KEYLENGTH.
	 * @tparam CryptorT Crypto++ authenticated encryption type.
	 * @tparam CryptoHMAC PBKDF2 hash type.
	 * @param consumer Plaintext source.
	 * @param password Password material.
	 * @param mode Input ownership mode.
	 * @param saltSize Salt byte count.
	 * @param ivSize Initialization vector byte count.
	 * @param keySize Key byte count.
	 * @param aad Additional authenticated data.
	 * @return Consumer containing salt, IV, ciphertext and authentication tag.
	 */
	template<class AlgoT, class CryptorT, class CryptoHMAC>
	Buffer::Consumer EncryptGCM(Buffer::Consumer consumer, Secure::Password password,
		ReadMode mode, const std::size_t& saltSize, const std::size_t& ivSize,
		const std::size_t& keySize = AlgoT::DEFAULT_KEYLENGTH, std::span<const std::byte> aad = {}) noexcept {
		return ProcessMessage<CipherOps<CryptorT, CryptoHMAC, true, true, true>>(
			std::move(consumer), std::move(password), mode, ByteSize{saltSize}, ByteSize{ivSize}, ByteSize{keySize}, aad);
	}

	/**
	 * @brief Decrypt a complete authenticated envelope without AAD.
	 * @tparam AlgoT Algorithm traits providing DEFAULT_KEYLENGTH.
	 * @tparam DecryptorT Crypto++ authenticated decryption type.
	 * @tparam CryptoHMAC PBKDF2 hash type.
	 * @param input Salt, IV, ciphertext and authentication tag.
	 * @param password Password material.
	 * @param output Plaintext destination.
	 * @param saltSize Salt byte count.
	 * @param ivSize Initialization vector byte count.
	 * @param keySize Key byte count.
	 * @return Whether decryption and authentication succeeded.
	 */
	template<class AlgoT, class DecryptorT, class CryptoHMAC>
	bool DecryptGCM(std::span<const std::byte> input, const Secure::Password& password,
		Buffer::WriteOnly& output, const std::size_t& saltSize, const std::size_t& ivSize,
		const std::size_t& keySize = AlgoT::DEFAULT_KEYLENGTH) noexcept {
		return ProcessMessage<CipherOps<DecryptorT, CryptoHMAC, true, false, false>>(
			input, password, output, ByteSize{saltSize}, ByteSize{ivSize}, ByteSize{keySize});
	}

	/**
	 * @brief Decrypt a streaming authenticated envelope.
	 * @tparam AlgoT Algorithm traits providing DEFAULT_KEYLENGTH.
	 * @tparam DecryptorT Crypto++ authenticated decryption type.
	 * @tparam CryptoHMAC PBKDF2 hash type.
	 * @param consumer Envelope source.
	 * @param password Password material.
	 * @param mode Input ownership mode.
	 * @param saltSize Salt byte count.
	 * @param ivSize Initialization vector byte count.
	 * @param keySize Key byte count.
	 * @param aad Additional authenticated data.
	 * @return Consumer containing plaintext, with errors reported by the parent stream.
	 */
	template<class AlgoT, class DecryptorT, class CryptoHMAC>
	Buffer::Consumer DecryptGCM(Buffer::Consumer consumer, Secure::Password password,
		ReadMode mode, const std::size_t& saltSize, const std::size_t& ivSize,
		const std::size_t& keySize = AlgoT::DEFAULT_KEYLENGTH, std::span<const std::byte> aad = {}) noexcept {
		return ProcessMessage<CipherOps<DecryptorT, CryptoHMAC, true, false, true>>(
			std::move(consumer), std::move(password), mode, ByteSize{saltSize}, ByteSize{ivSize}, ByteSize{keySize}, aad);
	}

	/**
	 * @brief Encrypt a complete AEAD message using the authenticated engine.
	 * @tparam AlgoT Algorithm traits providing DEFAULT_KEYLENGTH.
	 * @tparam CryptorT Crypto++ AEAD encryption type.
	 * @tparam CryptoHMAC PBKDF2 hash type.
	 * @param input Plaintext bytes.
	 * @param password Password material.
	 * @param output Envelope destination.
	 * @param saltSize Salt byte count.
	 * @param ivSize Initialization vector byte count.
	 * @param keySize Key byte count.
	 * @param aad Additional authenticated data.
	 * @return Whether encryption succeeded.
	 */
	template<class AlgoT, class CryptorT, class CryptoHMAC>
	bool EncryptAEAD(std::span<const std::byte> input, const Secure::Password& password,
		Buffer::WriteOnly& output, const std::size_t& saltSize, const std::size_t& ivSize,
		const std::size_t& keySize = AlgoT::DEFAULT_KEYLENGTH, std::span<const std::byte> aad = {}) noexcept {
		return EncryptGCM<AlgoT, CryptorT, CryptoHMAC>(input, password, output, saltSize, ivSize, keySize, aad);
	}

	/**
	 * @brief Encrypt a streaming AEAD message using the authenticated engine.
	 * @tparam AlgoT Algorithm traits providing DEFAULT_KEYLENGTH.
	 * @tparam CryptorT Crypto++ AEAD encryption type.
	 * @tparam CryptoHMAC PBKDF2 hash type.
	 * @param consumer Plaintext source.
	 * @param password Password material.
	 * @param mode Input ownership mode.
	 * @param saltSize Salt byte count.
	 * @param ivSize Initialization vector byte count.
	 * @param keySize Key byte count.
	 * @param aad Additional authenticated data.
	 * @return Consumer containing the authenticated envelope.
	 */
	template<class AlgoT, class CryptorT, class CryptoHMAC>
	Buffer::Consumer EncryptAEAD(Buffer::Consumer consumer, Secure::Password password,
		ReadMode mode, const std::size_t& saltSize, const std::size_t& ivSize,
		const std::size_t& keySize = AlgoT::DEFAULT_KEYLENGTH, std::span<const std::byte> aad = {}) noexcept {
		return EncryptGCM<AlgoT, CryptorT, CryptoHMAC>(std::move(consumer), std::move(password), mode,
			saltSize, ivSize, keySize, aad);
	}

	/**
	 * @brief Decrypt a complete AEAD envelope with AAD.
	 * @tparam AlgoT Algorithm traits providing DEFAULT_KEYLENGTH.
	 * @tparam DecryptorT Crypto++ AEAD decryption type.
	 * @tparam CryptoHMAC PBKDF2 hash type.
	 * @param input Salt, IV, ciphertext and authentication tag.
	 * @param password Password material.
	 * @param output Plaintext destination.
	 * @param saltSize Salt byte count.
	 * @param ivSize Initialization vector byte count.
	 * @param keySize Key byte count.
	 * @param aad Additional authenticated data.
	 * @return Whether decryption and authentication succeeded.
	 */
	template<class AlgoT, class DecryptorT, class CryptoHMAC>
	bool DecryptAEAD(std::span<const std::byte> input, const Secure::Password& password,
		Buffer::WriteOnly& output, const std::size_t& saltSize, const std::size_t& ivSize,
		const std::size_t& keySize = AlgoT::DEFAULT_KEYLENGTH, std::span<const std::byte> aad = {}) noexcept {
		return ProcessMessage<CipherOps<DecryptorT, CryptoHMAC, true, false, false>>(
			input, password, output, ByteSize{saltSize}, ByteSize{ivSize}, ByteSize{keySize}, aad);
	}

	/**
	 * @brief Decrypt a streaming AEAD envelope using the authenticated engine.
	 * @tparam AlgoT Algorithm traits providing DEFAULT_KEYLENGTH.
	 * @tparam DecryptorT Crypto++ AEAD decryption type.
	 * @tparam CryptoHMAC PBKDF2 hash type.
	 * @param consumer Envelope source.
	 * @param password Password material.
	 * @param mode Input ownership mode.
	 * @param saltSize Salt byte count.
	 * @param ivSize Initialization vector byte count.
	 * @param keySize Key byte count.
	 * @param aad Additional authenticated data.
	 * @return Consumer containing plaintext.
	 */
	template<class AlgoT, class DecryptorT, class CryptoHMAC>
	Buffer::Consumer DecryptAEAD(Buffer::Consumer consumer, Secure::Password password,
		ReadMode mode, const std::size_t& saltSize, const std::size_t& ivSize,
		const std::size_t& keySize = AlgoT::DEFAULT_KEYLENGTH, std::span<const std::byte> aad = {}) noexcept {
		return DecryptGCM<AlgoT, DecryptorT, CryptoHMAC>(std::move(consumer), std::move(password), mode,
			saltSize, ivSize, keySize, aad);
	}
}
