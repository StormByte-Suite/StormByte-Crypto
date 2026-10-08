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

#include <StormByte/crypto/engine/keypair/api.hxx>
#include <StormByte/crypto/engine/signer/details.hxx>
#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>
#include <StormByte/safe/string.hxx>

#include <filters.h>
#include <span>
#include <string_view>
#include <utility>

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
				 * @namespace StormByte::Crypto::Engine::Signer::Detail
				 * @brief Concrete signer backends owned and destroyed inside Crypto.
				 */
				namespace Detail {
					/**
					 * @struct ConcreteSignBox
					 * @brief Crypto++ SignerFilter wrapped as SignBox.
					 * @tparam SignerT Crypto++ signer type.
					 * @tparam PrivateKeyT Crypto++ private key type.
					 */
					template<typename SignerT, typename PrivateKeyT>
					struct ConcreteSignBox final : SignBox {
						/**
						 * @brief Load the private key and build the filter.
						 * @param privKey DER private key.
						 */
						explicit ConcreteSignBox(const Secure::Password& privKey) {
							auto loadedKey = KeyPair::DeserializeKey<PrivateKeyT>(privKey);
							if (!loadedKey)
								return;
							m_key = std::move(loadedKey);
							if (!m_key->Validate(RNG(), 3)) {
								m_key.reset();
								return;
							}
							m_signer = Safe::Unique<SignerT>::template MakePointer<SignerT>(*m_key);
							m_filter = Safe::Unique<CryptoPP::SignerFilter>::MakePointer<CryptoPP::SignerFilter>(RNG(), *m_signer);
						}

						/**
						 * @brief Native signing state cannot be copied.
						 * @param other Source backend.
						 */
						ConcreteSignBox(const ConcreteSignBox& other) = delete;

						/**
						 * @brief Native signing state cannot be moved.
						 * @param other Source backend.
						 */
						ConcreteSignBox(ConcreteSignBox&& other) = delete;

						/**
						 * @brief Destroy the filter before the signer and private key in Crypto.
						 */
						~ConcreteSignBox() override = default;

						/**
						 * @brief Native signing state cannot be copy-assigned.
						 * @param other Source backend.
						 * @return This backend.
						 */
						ConcreteSignBox& operator=(const ConcreteSignBox& other) = delete;

						/**
						 * @brief Native signing state cannot be move-assigned.
						 * @param other Source backend.
						 * @return This backend.
						 */
						ConcreteSignBox& operator=(ConcreteSignBox&& other) = delete;

						/**
						 * @brief Feed one message chunk.
						 * @param input Input bytes borrowed until the update returns.
						 * @return true on success.
						 */
						bool Update(std::span<const std::byte> input) override {
							if (!m_filter)
								return false;
							try {
								m_filter->Put(reinterpret_cast<const CryptoPP::byte*>(input.data()), input.size_bytes());
								return true;
							} catch (...) {
								return false;
							}
						}

						/**
						 * @brief Finish signing and move the signature out.
						 * @param output Safe signature destination.
						 * @return true on success.
						 */
						bool Finalize(Safe::Binary& output) override {
							if (!m_filter)
								return false;
							try {
								m_filter->MessageEnd();
								output.resize(ByteSize{m_filter->MaxRetrievable()});
								const std::size_t outputSize = static_cast<std::size_t>(output.size());
								if (m_filter->Get(reinterpret_cast<CryptoPP::byte*>(output.data()), outputSize) != outputSize)
									return false;
								m_filter.reset();
								return true;
							} catch (...) {
								return false;
							}
						}
						private:
							Safe::Shared<PrivateKeyT> m_key;			///< Loaded private key, destroyed in Crypto.
							Safe::Unique<SignerT> m_signer;			///< Private Crypto++ signer.
							Safe::Unique<CryptoPP::SignerFilter> m_filter;	///< Native filter with secure queued output.
					};

					/**
					 * @struct ConcreteVerifyBox
					 * @brief Crypto++ SignatureVerificationFilter wrapped as VerifyBox.
					 * @tparam VerifierT Crypto++ verifier type.
					 * @tparam PublicKeyT Crypto++ public key type.
					 */
					template<typename VerifierT, typename PublicKeyT>
					struct ConcreteVerifyBox final : VerifyBox {
						/**
						 * @brief Load the public key.
						 * @param pubKey Base64 public key.
						 */
						explicit ConcreteVerifyBox(std::string_view pubKey) {
							auto loadedKey = KeyPair::DeserializeKey<PublicKeyT>(pubKey);
							if (!loadedKey)
								return;
							m_key = std::move(loadedKey);
							if (!m_key->Validate(RNG(), 3)) {
								m_key.reset();
								return;
							}
							m_verifier = Safe::Unique<VerifierT>::template MakePointer<VerifierT>(*m_key);
						}

						/**
						 * @brief Load the public key from a @ref StormByte::Safe::String.
						 * @param pubKey Base64 public key.
						 */
						explicit ConcreteVerifyBox(const StormByte::Safe::String& pubKey):
							ConcreteVerifyBox(static_cast<std::string_view>(pubKey)) {}

						/**
						 * @brief Native verification state cannot be copied.
						 * @param other Source backend.
						 */
						ConcreteVerifyBox(const ConcreteVerifyBox& other) = delete;

						/**
						 * @brief Native verification state cannot be moved.
						 * @param other Source backend.
						 */
						ConcreteVerifyBox(ConcreteVerifyBox&& other) = delete;

						/**
						 * @brief Destroy the filter before the verifier and public key in Crypto.
						 */
						~ConcreteVerifyBox() override = default;

						/**
						 * @brief Native verification state cannot be copy-assigned.
						 * @param other Source backend.
						 * @return This backend.
						 */
						ConcreteVerifyBox& operator=(const ConcreteVerifyBox& other) = delete;

						/**
						 * @brief Native verification state cannot be move-assigned.
						 * @param other Source backend.
						 * @return This backend.
						 */
						ConcreteVerifyBox& operator=(ConcreteVerifyBox&& other) = delete;

						/**
						 * @brief Push the signature before message bytes.
						 * @param signature Signature.
						 * @return true on success.
						 */
						bool Begin(std::string_view signature) override {
							if (!m_verifier)
								return false;
							try {
								m_filter = Safe::Unique<CryptoPP::SignatureVerificationFilter>::MakePointer<CryptoPP::SignatureVerificationFilter>(
									*m_verifier,
									nullptr,
									CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_BEGIN
								);
								m_filter->Put(
									reinterpret_cast<const CryptoPP::byte*>(signature.data()),
									signature.size());
								return true;
							} catch (...) {
								return false;
							}
						}

						/**
						 * @brief Feed one message chunk.
						 * @param input Input bytes borrowed until the update returns.
						 * @return true on success.
						 */
						bool Update(std::span<const std::byte> input) override {
							if (!m_filter)
								return false;
							try {
								m_filter->Put(reinterpret_cast<const CryptoPP::byte*>(input.data()), input.size_bytes());
								return true;
							} catch (...) {
								return false;
							}
						}

						/**
						 * @brief Finish verification.
						 * @return true if the signature is valid.
						 */
						bool Finalize() override {
							if (!m_filter)
								return false;
							try {
								m_filter->MessageEnd();
								const bool verified = m_filter->GetLastResult();
								m_filter.reset();
								return verified;
							} catch (...) {
								return false;
							}
						}
						private:
							Safe::Shared<PublicKeyT> m_key;		///< Loaded public key, destroyed in Crypto.
							Safe::Unique<VerifierT> m_verifier;	///< Private Crypto++ verifier.
							Safe::Unique<CryptoPP::SignatureVerificationFilter> m_filter;	///< Native verification filter.
					};
					}

				/**
				 * @brief One-shot sign from a Password.
				 * @tparam SignerT Crypto++ signer type.
				 * @tparam PrivateKeyT Crypto++ private key type.
				 * @param data Input.
				 * @param privKey Private key.
				 * @param output Signature destination.
				 * @return true on success.
				 */
				template<typename SignerT, typename PrivateKeyT>
				bool Sign(std::span<const std::byte> data, const Secure::Password& privKey, Buffer::WriteOnly& output) noexcept {
					try {
						return SignSpan(
							data, output,
							Safe::Unique<SignBox>::template MakePointer<Detail::ConcreteSignBox<SignerT, PrivateKeyT>>(privKey));
					} catch (...) {
						return false;
					}
				}

				/**
				 * @brief One-shot sign from a KeyPair.
				 * @tparam SignerT Crypto++ signer type.
				 * @tparam PrivateKeyT Crypto++ private key type.
				 * @param data Input.
				 * @param keypair Key pair with private key.
				 * @param output Signature destination.
				 * @return true on success.
				 */
				template<typename SignerT, typename PrivateKeyT>
				bool Sign(std::span<const std::byte> data, const StormByte::Crypto::KeyPair::Generic::PointerType keypair, Buffer::WriteOnly& output) noexcept {
					if (!keypair || !keypair->HasPrivateKey())
						return false;
					return Sign<SignerT, PrivateKeyT>(data, *keypair->PrivateKey(), output);
				}

				/**
				 * @brief Streaming sign from a Password.
				 * @tparam SignerT Crypto++ signer type.
				 * @tparam PrivateKeyT Crypto++ private key type.
				 * @param consumer Input consumer.
				 * @param privKey Private key.
				 * @param mode Copy or move.
				 * @return Consumer with the signature.
				 */
				template<typename SignerT, typename PrivateKeyT>
				Buffer::Consumer Sign(Buffer::Consumer consumer, Secure::Password privKey, ReadMode mode) noexcept {
					try {
						auto box = Safe::Unique<SignBox>::template MakePointer<Detail::ConcreteSignBox<SignerT, PrivateKeyT>>(privKey);
						return SignStream(
							std::move(consumer), mode, std::move(box));
					} catch (...) {
						return SignStream(std::move(consumer), mode, {});
					}
				}

				/**
				 * @brief Streaming sign from a KeyPair.
				 * @tparam SignerT Crypto++ signer type.
				 * @tparam PrivateKeyT Crypto++ private key type.
				 * @param consumer Input consumer.
				 * @param keypair Key pair with private key.
				 * @param mode Copy or move.
				 * @return Consumer with the signature, or error if no private key.
				 */
				template<typename SignerT, typename PrivateKeyT>
				Buffer::Consumer Sign(Buffer::Consumer consumer, const StormByte::Crypto::KeyPair::Generic::PointerType keypair, ReadMode mode) noexcept {
					if (!keypair || !keypair->HasPrivateKey()) {
						Buffer::Producer producer;
						producer.SetError();
						return producer.Consumer();
					}
					return Sign<SignerT, PrivateKeyT>(std::move(consumer), *keypair->PrivateKey(), mode);
				}

				/**
				 * @brief One-shot verify from a public key string.
				 * @tparam VerifierT Crypto++ verifier type.
				 * @tparam PublicKeyT Crypto++ public key type.
				 * @param data Input.
				 * @param signature Signature.
				 * @param pubKey Base64 public key.
				 * @return true if valid.
				 */
				template<typename VerifierT, typename PublicKeyT>
				bool Verify(std::span<const std::byte> data, std::string_view signature, std::string_view pubKey) noexcept {
					try {
						return VerifySpan(
							data, signature,
							Safe::Unique<VerifyBox>::template MakePointer<Detail::ConcreteVerifyBox<VerifierT, PublicKeyT>>(pubKey));
					} catch (...) {
						return false;
					}
				}

				/**
				 * @brief One-shot verify from a public @ref StormByte::Safe::String.
				 * @tparam VerifierT Crypto++ verifier type.
				 * @tparam PublicKeyT Crypto++ public key type.
				 * @param data Input.
				 * @param signature Signature.
				 * @param pubKey Base64 public key.
				 * @return true if valid.
				 */
				template<typename VerifierT, typename PublicKeyT>
				bool Verify(std::span<const std::byte> data, std::string_view signature, const StormByte::Safe::String& pubKey) noexcept {
					return Verify<VerifierT, PublicKeyT>(data, signature, static_cast<std::string_view>(pubKey));
				}

				/**
				 * @brief One-shot verify from a KeyPair.
				 * @tparam VerifierT Crypto++ verifier type.
				 * @tparam PublicKeyT Crypto++ public key type.
				 * @param data Input.
				 * @param signature Signature.
				 * @param keypair Key pair.
				 * @return true if valid.
				 */
				template<typename VerifierT, typename PublicKeyT>
				bool Verify(std::span<const std::byte> data, std::string_view signature, const StormByte::Crypto::KeyPair::Generic::PointerType keypair) noexcept {
					if (!keypair)
						return false;
					return Verify<VerifierT, PublicKeyT>(data, signature, keypair->PublicKey());
				}

				/**
				 * @brief Streaming verify from a public key string.
				 * @tparam VerifierT Crypto++ verifier type.
				 * @tparam PublicKeyT Crypto++ public key type.
				 * @param consumer Input consumer.
				 * @param signature Signature.
				 * @param pubKey Base64 public key.
				 * @param mode Copy or move.
				 * @return true if valid.
				 */
				template<typename VerifierT, typename PublicKeyT>
				bool Verify(Buffer::Consumer consumer, std::string_view signature, std::string_view pubKey, ReadMode mode) noexcept {
					try {
						return VerifyStream(
							std::move(consumer), mode, signature,
							Safe::Unique<VerifyBox>::template MakePointer<Detail::ConcreteVerifyBox<VerifierT, PublicKeyT>>(pubKey));
					} catch (...) {
						return false;
					}
				}

				/**
				 * @brief Streaming verify from a public @ref StormByte::Safe::String.
				 * @tparam VerifierT Crypto++ verifier type.
				 * @tparam PublicKeyT Crypto++ public key type.
				 * @param consumer Input consumer.
				 * @param signature Signature.
				 * @param pubKey Base64 public key.
				 * @param mode Copy or move.
				 * @return true if valid.
				 */
				template<typename VerifierT, typename PublicKeyT>
				bool Verify(Buffer::Consumer consumer, std::string_view signature, const StormByte::Safe::String& pubKey, ReadMode mode) noexcept {
					return Verify<VerifierT, PublicKeyT>(std::move(consumer), signature, static_cast<std::string_view>(pubKey), mode);
				}

				/**
				 * @brief Streaming verify from a KeyPair.
				 * @tparam VerifierT Crypto++ verifier type.
				 * @tparam PublicKeyT Crypto++ public key type.
				 * @param consumer Input consumer.
				 * @param signature Signature.
				 * @param keypair Key pair.
				 * @param mode Copy or move.
				 * @return true if valid.
				 */
				template<typename VerifierT, typename PublicKeyT>
				bool Verify(Buffer::Consumer consumer, std::string_view signature, const StormByte::Crypto::KeyPair::Generic::PointerType keypair, ReadMode mode) noexcept {
					if (!keypair)
						return false;
					return Verify<VerifierT, PublicKeyT>(std::move(consumer), signature, keypair->PublicKey(), mode);
				}
			}
		}
	}
}
