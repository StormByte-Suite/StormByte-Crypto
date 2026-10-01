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
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>
#include <StormByte/safe/string.hxx>

#include <filters.h>
#include <memory>
#include <span>
#include <string>
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
		 * @namespace StormByte::Crypto::Implementation
		 * @brief Private implementation of the Crypto module.
		 */
		namespace Engine {
			/**
			 * @namespace StormByte::Crypto::Engine::Signer
			 * @brief Private signer implementation.
			 */
			namespace Signer {
				namespace {
					/**
					 * @struct ConcreteSignBox
					 * @brief Crypto++ SignerFilter wrapped as SignBox.
					 * @tparam SignerT Crypto++ signer type.
					 * @tparam PrivateKeyT Crypto++ private key type.
					 */
					template<typename SignerT, typename PrivateKeyT>
					struct ConcreteSignBox final : SignBox {
						std::unique_ptr<PrivateKeyT> key;					///< Loaded private key
						std::unique_ptr<SignerT> signer;					///< Crypto++ signer
						StormByte::BinaryData signature;					///< Accumulated signature
						std::unique_ptr<CryptoPP::SignerFilter> filter;		///< Filter writing into signature

						/**
						 * @brief Load the private key and build the filter.
						 * @param privKey DER private key.
						 */
						explicit ConcreteSignBox(const Secure::Password& privKey) {
							auto keyRes = KeyPair::DeserializeKey<PrivateKeyT>(privKey);
							if (!keyRes)
								return;
							key = std::make_unique<PrivateKeyT>(std::move(*keyRes));
							if (!key->Validate(RNG(), 3)) {
								key.reset();
								return;
							}
							signer = std::make_unique<SignerT>(*key);
							filter = std::make_unique<CryptoPP::SignerFilter>(
								RNG(), *signer,
								new CryptoPP::StringSinkTemplate<StormByte::BinaryData>(signature)
							);
						}

						/**
						 * @brief Feed one message chunk.
						 * @param in Input bytes.
						 * @return true on success.
						 */
						bool Update(std::span<const std::byte> in) override {
							if (!filter)
								return false;
							try {
								filter->Put(reinterpret_cast<const CryptoPP::byte*>(in.data()), in.size_bytes());
								return true;
							} catch (...) {
								return false;
							}
						}

						/**
						 * @brief Finish signing and move the signature out.
						 * @param out Destination.
						 * @return true on success.
						 */
						bool Finalize(StormByte::BinaryData& out) override {
							if (!filter)
								return false;
							try {
								filter->MessageEnd();
								out = std::move(signature);
								filter.reset();
								return true;
							} catch (...) {
								return false;
							}
						}
					};

					/**
					 * @struct ConcreteVerifyBox
					 * @brief Crypto++ SignatureVerificationFilter wrapped as VerifyBox.
					 * @tparam VerifierT Crypto++ verifier type.
					 * @tparam PublicKeyT Crypto++ public key type.
					 */
					template<typename VerifierT, typename PublicKeyT>
					struct ConcreteVerifyBox final : VerifyBox {
						std::unique_ptr<PublicKeyT> key;								///< Loaded public key
						std::unique_ptr<VerifierT> verifier;							///< Crypto++ verifier
						bool result = false;											///< PUT_RESULT sink
						std::unique_ptr<CryptoPP::SignatureVerificationFilter> filter;	///< Filter

						/**
						 * @brief Load the public key.
						 * @param pubKey Base64 public key.
						 */
						explicit ConcreteVerifyBox(const std::string& pubKey) {
							auto keyRes = KeyPair::DeserializeKey<PublicKeyT>(pubKey);
							if (!keyRes)
								return;
							key = std::make_unique<PublicKeyT>(std::move(*keyRes));
							if (!key->Validate(RNG(), 3)) {
								key.reset();
								return;
							}
							verifier = std::make_unique<VerifierT>(*key);
						}

						/**
						 * @brief Load the public key from a @ref StormByte::Safe::String.
						 * @param pubKey Base64 public key.
						 */
						explicit ConcreteVerifyBox(const StormByte::Safe::String& pubKey):
							ConcreteVerifyBox(std::string(static_cast<std::string_view>(pubKey))) {}

						/**
						 * @brief Push the signature before message bytes.
						 * @param signature Signature.
						 * @return true on success.
						 */
						bool Begin(const std::string& signature) override {
							if (!verifier)
								return false;
							try {
								filter = std::make_unique<CryptoPP::SignatureVerificationFilter>(
									*verifier,
									new CryptoPP::ArraySink(
										reinterpret_cast<CryptoPP::byte*>(&result),
										sizeof(result)),
									CryptoPP::SignatureVerificationFilter::PUT_RESULT |
										CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_BEGIN
								);
								filter->Put(
									reinterpret_cast<const CryptoPP::byte*>(signature.data()),
									signature.size());
								return true;
							} catch (...) {
								return false;
							}
						}

						/**
						 * @brief Feed one message chunk.
						 * @param in Input bytes.
						 * @return true on success.
						 */
						bool Update(std::span<const std::byte> in) override {
							if (!filter)
								return false;
							try {
								filter->Put(reinterpret_cast<const CryptoPP::byte*>(in.data()), in.size_bytes());
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
							if (!filter)
								return false;
							try {
								filter->MessageEnd();
								filter.reset();
								return result;
							} catch (...) {
								return false;
							}
						}
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
					return SignSpan(
						data, output,
						std::make_unique<ConcreteSignBox<SignerT, PrivateKeyT>>(privKey));
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
					return SignStream(
						std::move(consumer), mode,
						std::make_unique<ConcreteSignBox<SignerT, PrivateKeyT>>(std::move(privKey)));
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
				bool Verify(std::span<const std::byte> data, const std::string& signature, const std::string& pubKey) noexcept {
					return VerifySpan(
						data, signature,
						std::make_unique<ConcreteVerifyBox<VerifierT, PublicKeyT>>(pubKey));
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
				bool Verify(std::span<const std::byte> data, const std::string& signature, const StormByte::Safe::String& pubKey) noexcept {
					return Verify<VerifierT, PublicKeyT>(data, signature, std::string(static_cast<std::string_view>(pubKey)));
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
				bool Verify(std::span<const std::byte> data, const std::string& signature, const StormByte::Crypto::KeyPair::Generic::PointerType keypair) noexcept {
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
				bool Verify(Buffer::Consumer consumer, const std::string& signature, const std::string& pubKey, ReadMode mode) noexcept {
					return VerifyStream(
						std::move(consumer), mode, signature,
						std::make_unique<ConcreteVerifyBox<VerifierT, PublicKeyT>>(pubKey));
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
				bool Verify(Buffer::Consumer consumer, const std::string& signature, const StormByte::Safe::String& pubKey, ReadMode mode) noexcept {
					return Verify<VerifierT, PublicKeyT>(std::move(consumer), signature, std::string(static_cast<std::string_view>(pubKey)), mode);
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
				bool Verify(Buffer::Consumer consumer, const std::string& signature, const StormByte::Crypto::KeyPair::Generic::PointerType keypair, ReadMode mode) noexcept {
					if (!keypair)
						return false;
					return Verify<VerifierT, PublicKeyT>(std::move(consumer), signature, keypair->PublicKey(), mode);
				}
			}
		}
	}
}
