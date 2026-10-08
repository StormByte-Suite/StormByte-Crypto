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

#include <StormByte/crypto/engine/crypter/asymmetric/details.hxx>
#include <StormByte/crypto/engine/keypair/api.hxx>
#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/exception.hxx>

#include <exception>
#include <filters.h>
#include <limits>
#include <span>
#include <utility>

/**
 * @namespace StormByte::Crypto::Engine::Crypter::Asymmetric
 * @brief Private asymmetric crypter implementation.
 */
namespace StormByte::Crypto::Engine::Crypter::Asymmetric {
	/**
	 * @class TransformBox
	 * @brief Safe-owned key and Crypto++ public-key transform.
	 * @tparam TransformT Crypto++ encryptor or decryptor.
	 * @tparam KeyT Crypto++ key type.
	 * @tparam Encrypt Whether to load the public rather than private key.
	 */
	template<typename TransformT, typename KeyT, bool Encrypt>
	class TransformBox final : public PkBox {
		public:
			/**
			 * @brief Load and validate the required key from a keypair.
			 * @param keypair Keypair containing the required key.
			 * @throws StormByte::Exception Safe allocation failed.
			 * @throws CryptoPP::Exception Backend validation failed.
			 */
			explicit TransformBox(StormByte::Crypto::KeyPair::Generic::PointerType keypair) {
				if (!keypair)
					return;
				if constexpr (Encrypt)
					Load(keypair->PublicKey());
				else if (keypair->HasPrivateKey())
					Load(*keypair->PrivateKey());
			}

			/**
			 * @brief Load and validate a private DER key.
			 * @param privateKey DER key stored in a password.
			 * @throws StormByte::Exception Safe allocation failed.
			 * @throws CryptoPP::Exception Backend validation failed.
			 */
			explicit TransformBox(const Secure::Password& privateKey) requires (!Encrypt) {
				Load(privateKey);
			}

			/**
			 * @brief Disable copying key ownership.
			 * @param other Source transform.
			 */
			TransformBox(const TransformBox& other) = delete;

			/**
			 * @brief Disable moving a transform with backend state.
			 * @param other Source transform.
			 */
			TransformBox(TransformBox&& other) = delete;

			/**
			 * @brief Destroy the key through its Safe owner.
			 */
			~TransformBox() override = default;

			/**
			 * @brief Disable copy assignment.
			 * @param other Source transform.
			 * @return This transform.
			 */
			TransformBox& operator=(const TransformBox& other) = delete;

			/**
			 * @brief Disable move assignment.
			 * @param other Source transform.
			 * @return This transform.
			 */
			TransformBox& operator=(TransformBox&& other) = delete;

			/**
			 * @brief Transform one blob and append the result only after success.
			 * @param input Borrowed input bytes.
			 * @param output Safe destination.
			 * @return Whether the key and transformation succeeded.
			 */
			bool Transform(std::span<const std::byte> input, Safe::Binary& output) override {
				if (!m_key)
					return false;
				try {
					TransformT transform(*m_key);
					if constexpr (Encrypt) {
						CryptoPP::PK_EncryptorFilter filter(RNG(), transform);
						filter.Put(reinterpret_cast<const CryptoPP::byte*>(input.data()), input.size_bytes());
						filter.MessageEnd();
						return Drain(filter, output);
					}
					else {
						CryptoPP::PK_DecryptorFilter filter(RNG(), transform);
						filter.Put(reinterpret_cast<const CryptoPP::byte*>(input.data()), input.size_bytes());
						filter.MessageEnd();
						return Drain(filter, output);
					}
				} catch (const StormByte::Exception&) {
					return false;
				} catch (const std::exception&) {
					return false;
				} catch (...) {
					return false;
				}
			}

		private:
			/**
			 * @brief Deserialize and validate a backend key on Base's heap.
			 * @tparam MaterialT Serialized key representation.
			 * @param material Serialized key bytes or text.
			 * @throws StormByte::Exception Safe allocation failed.
			 * @throws CryptoPP::Exception Backend validation failed.
			 */
			template<typename MaterialT>
			void Load(const MaterialT& material) {
				auto key = KeyPair::DeserializeKey<KeyT>(material);
				if (!key || !key->Validate(RNG(), 3))
					return;
				m_key = Safe::Unique<KeyT>::template MakePointer<KeyT>(std::move(*key));
			}

			/**
			 * @brief Drain the backend-owned queue without transferring attachment ownership.
			 * @param filter Completed Crypto++ filter.
			 * @param output Safe destination to append to.
			 * @return Whether the queued length fits in the destination.
			 * @throws StormByte::Exception Safe allocation failed.
			 * @throws CryptoPP::Exception Reading the backend queue failed.
			 */
			static bool Drain(CryptoPP::BufferedTransformation& filter, Safe::Binary& output) {
				const auto length = filter.MaxRetrievable();
				const std::size_t offset = output.size();
				if (length > std::numeric_limits<std::size_t>::max() - offset)
					return false;
				output.resize(ByteSize{offset + static_cast<std::size_t>(length)});
				if (length != 0)
					filter.Get(reinterpret_cast<CryptoPP::byte*>(output.data() + offset), static_cast<std::size_t>(length));
				return true;
			}

			Safe::Unique<KeyT> m_key;	///< Loaded and validated backend key.
	};

	/**
	 * @brief Public-key encryptor with Safe key ownership.
	 * @tparam CryptorT Crypto++ encryptor type.
	 * @tparam KeyT Crypto++ public key type.
	 */
	template<typename CryptorT, typename KeyT>
	using EncryptBox = TransformBox<CryptorT, KeyT, true>;

	/**
	 * @brief Private-key decryptor with Safe key ownership.
	 * @tparam DecryptorT Crypto++ decryptor type.
	 * @tparam KeyT Crypto++ private key type.
	 */
	template<typename DecryptorT, typename KeyT>
	using DecryptBox = TransformBox<DecryptorT, KeyT, false>;

	/**
	 * @brief Allocate a concrete transform through the base Safe owner.
	 * @tparam BoxT Concrete public-key transform.
	 * @tparam Args Constructor argument types.
	 * @param args Constructor arguments.
	 * @return Owned transform, or an empty owner on failure.
	 */
	template<typename BoxT, typename... Args>
	Safe::Unique<PkBox> MakeBox(Args&&... args) noexcept {
		try {
			return Safe::Unique<PkBox>::template MakePointer<BoxT>(std::forward<Args>(args)...);
		} catch (const StormByte::Exception&) {
			return {};
		} catch (const std::exception&) {
			return {};
		} catch (...) {
			return {};
		}
	}

	/**
	 * @brief Native one-shot encrypt.
	 * @tparam CryptorT Crypto++ encryptor type.
	 * @tparam PublicKeyT Crypto++ public key type.
	 * @param data Input bytes.
	 * @param keypair Keypair containing a public key.
	 * @param output Destination.
	 * @return Whether encryption succeeded.
	 */
	template<typename CryptorT, typename PublicKeyT>
	bool EncryptAsymmetric(std::span<const std::byte> data, StormByte::Crypto::KeyPair::Generic::PointerType keypair, Buffer::WriteOnly& output) noexcept {
		return NativeProcessSpan(data, output, MakeBox<EncryptBox<CryptorT, PublicKeyT>>(std::move(keypair)));
	}

	/**
	 * @brief Native streaming encrypt with independently transformed chunks.
	 * @tparam CryptorT Crypto++ encryptor type.
	 * @tparam PublicKeyT Crypto++ public key type.
	 * @param consumer Input consumer.
	 * @param keypair Keypair containing a public key.
	 * @param mode Copy or move input bytes.
	 * @return Consumer with ciphertext or an error.
	 */
	template<typename CryptorT, typename PublicKeyT>
	Buffer::Consumer EncryptAsymmetric(Buffer::Consumer consumer, StormByte::Crypto::KeyPair::Generic::PointerType keypair, ReadMode mode) noexcept {
		return NativeProcessStream(std::move(consumer), mode, MakeBox<EncryptBox<CryptorT, PublicKeyT>>(std::move(keypair)));
	}

	/**
	 * @brief Hybrid one-shot encrypt using AES-GCM and a wrapped session key.
	 * @tparam EncryptorT Crypto++ encryptor type.
	 * @tparam PublicKeyT Crypto++ public key type.
	 * @param data Input bytes.
	 * @param keypair Keypair containing a public key.
	 * @param output Destination.
	 * @return Whether encryption succeeded.
	 */
	template<typename EncryptorT, typename PublicKeyT>
	bool EncryptAsymmetricBlockEnvelope(std::span<const std::byte> data, StormByte::Crypto::KeyPair::Generic::PointerType keypair, Buffer::WriteOnly& output) noexcept {
		return HybridEncryptSpan(data, output, MakeBox<EncryptBox<EncryptorT, PublicKeyT>>(std::move(keypair)));
	}

	/**
	 * @brief Hybrid streaming encrypt.
	 * @tparam EncryptorT Crypto++ encryptor type.
	 * @tparam PublicKeyT Crypto++ public key type.
	 * @param consumer Input consumer.
	 * @param keypair Keypair containing a public key.
	 * @param mode Copy or move input bytes.
	 * @return Consumer with an encrypted envelope or an error.
	 */
	template<typename EncryptorT, typename PublicKeyT>
	Buffer::Consumer EncryptAsymmetricBlockEnvelope(Buffer::Consumer consumer, StormByte::Crypto::KeyPair::Generic::PointerType keypair, ReadMode mode) noexcept {
		return HybridEncryptStream(std::move(consumer), mode, MakeBox<EncryptBox<EncryptorT, PublicKeyT>>(std::move(keypair)));
	}

	/**
	 * @brief Native one-shot decrypt.
	 * @tparam DecryptorT Crypto++ decryptor type.
	 * @tparam PrivateKeyT Crypto++ private key type.
	 * @param data Ciphertext bytes.
	 * @param keypair Keypair containing a private key.
	 * @param output Destination.
	 * @return Whether decryption succeeded.
	 */
	template<typename DecryptorT, typename PrivateKeyT>
	bool DecryptAsymmetric(std::span<const std::byte> data, StormByte::Crypto::KeyPair::Generic::PointerType keypair, Buffer::WriteOnly& output) noexcept {
		return NativeProcessSpan(data, output, MakeBox<DecryptBox<DecryptorT, PrivateKeyT>>(std::move(keypair)));
	}

	/**
	 * @brief Native streaming decrypt with independently transformed chunks.
	 * @tparam DecryptorT Crypto++ decryptor type.
	 * @tparam PrivateKeyT Crypto++ private key type.
	 * @param consumer Input consumer.
	 * @param keypair Keypair containing a private key.
	 * @param mode Copy or move input bytes.
	 * @return Consumer with plaintext or an error.
	 */
	template<typename DecryptorT, typename PrivateKeyT>
	Buffer::Consumer DecryptAsymmetric(Buffer::Consumer consumer, StormByte::Crypto::KeyPair::Generic::PointerType keypair, ReadMode mode) noexcept {
		if (!keypair || !keypair->HasPrivateKey())
			return NativeProcessStream(std::move(consumer), mode, {});
		return NativeProcessStream(std::move(consumer), mode, MakeBox<DecryptBox<DecryptorT, PrivateKeyT>>(*keypair->PrivateKey()));
	}

	/**
	 * @brief Hybrid one-shot decrypt.
	 * @tparam DecryptorT Crypto++ decryptor type.
	 * @tparam PrivateKeyT Crypto++ private key type.
	 * @param data Encrypted envelope bytes.
	 * @param keypair Keypair containing a private key.
	 * @param output Destination.
	 * @return Whether decryption succeeded.
	 */
	template<typename DecryptorT, typename PrivateKeyT>
	bool DecryptAsymmetricBlockEnvelope(std::span<const std::byte> data, StormByte::Crypto::KeyPair::Generic::PointerType keypair, Buffer::WriteOnly& output) noexcept {
		return HybridDecryptSpan(data, output, MakeBox<DecryptBox<DecryptorT, PrivateKeyT>>(std::move(keypair)));
	}

	/**
	 * @brief Hybrid streaming decrypt.
	 * @tparam DecryptorT Crypto++ decryptor type.
	 * @tparam PrivateKeyT Crypto++ private key type.
	 * @param consumer Input consumer.
	 * @param keypair Keypair containing a private key.
	 * @param mode Copy or move input bytes.
	 * @return Consumer with plaintext or an error.
	 */
	template<typename DecryptorT, typename PrivateKeyT>
	Buffer::Consumer DecryptAsymmetricBlockEnvelope(Buffer::Consumer consumer, StormByte::Crypto::KeyPair::Generic::PointerType keypair, ReadMode mode) noexcept {
		if (!keypair || !keypair->HasPrivateKey())
			return HybridDecryptStream(std::move(consumer), mode, {});
		return HybridDecryptStream(std::move(consumer), mode, MakeBox<DecryptBox<DecryptorT, PrivateKeyT>>(*keypair->PrivateKey()));
	}
}
