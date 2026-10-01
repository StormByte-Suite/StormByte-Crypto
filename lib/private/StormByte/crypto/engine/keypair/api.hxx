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

#include <StormByte/crypto/helpers/password_view.hxx>
#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/engine/keypair/details.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/visibility.h>
#include <StormByte/safe/string.hxx>

#include <base64.h>
#include <filters.h>
#include <memory>
#include <optional>
#include <queue.h>
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
			 * @namespace StormByte::Crypto::Engine::KeyPair
			 * @brief Private keypair implementation.
			 */
			namespace KeyPair {
				/**
				 * @brief Serialize a Crypto++ key to Base64.
				 * @tparam KeyT Key type.
				 * @param key Key.
				 * @return Base64, or empty on failure.
				 */
				template<typename KeyT>
				std::string SerializeKey(const KeyT& key) noexcept {
					try {
						std::string keyString;
						CryptoPP::ByteQueue queue;
						key.Save(queue);
						CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(keyString), false);
						queue.CopyTo(encoder);
						encoder.MessageEnd();
						return keyString;
					} catch (...) {
						return {};
					}
				}

				/**
				 * @brief Serialize a Crypto++ key to DER inside a Password.
				 * @tparam KeyT Key type.
				 * @param key Key.
				 * @return Password, or empty on failure.
				 */
				template<typename KeyT>
				Secure::Password SerializeKeyBinary(const KeyT& key) noexcept {
					try {
						CryptoPP::ByteQueue queue;
						key.Save(queue);
						const size_t n = queue.CurrentSize();
						CryptoPP::SecByteBlock der(n);
						queue.Get(der.data(), der.size());
						Secure::Password result(der.data(), StormByte::ByteSize{der.size()});
						Helpers::SecureWipe(der);
						return result;
					} catch (...) {
						return Secure::Password(static_cast<const void*>(nullptr), StormByte::ByteSize{0});
					}
				}

				/**
				 * @brief Deserialize a key from Base64.
				 * @tparam KeyT Key type.
				 * @param keyString Base64.
				 * @return Shared key, or nullptr.
				 */
				template<typename KeyT>
				std::shared_ptr<KeyT> DeserializeKey(const std::string& keyString) noexcept {
					try {
						KeyT key;
						CryptoPP::ByteQueue queue;
						CryptoPP::StringSource ss(
							keyString, true,
							new CryptoPP::Base64Decoder(new CryptoPP::Redirector(queue)));
						key.Load(queue);
						return std::make_shared<KeyT>(std::move(key));
					} catch (...) {
						return nullptr;
					}
				}

				/**
				 * @brief Deserialize a key from a public @ref StormByte::Safe::String.
				 * @tparam KeyT Key type.
				 * @param keyString Base64 public key.
				 * @return Shared key, or nullptr.
				 */
				template<typename KeyT>
				std::shared_ptr<KeyT> DeserializeKey(const StormByte::Safe::String& keyString) noexcept {
					return DeserializeKey<KeyT>(std::string(static_cast<std::string_view>(keyString)));
				}

				/**
				 * @brief Deserialize a key from DER in a Password.
				 * @tparam KeyT Key type.
				 * @param keyBinary Password.
				 * @return Shared key, or nullptr.
				 */
				template<typename KeyT>
				std::shared_ptr<KeyT> DeserializeKey(const Secure::Password& keyBinary) noexcept {
					try {
						const unsigned char* data = Helpers::PasswordAccess::Data(keyBinary);
						const std::size_t n = Helpers::PasswordAccess::Size(keyBinary);
						if (!data || n == 0)
							return nullptr;

						KeyT key;
						CryptoPP::ByteQueue queue;
						queue.Put(data, n);
						key.Load(queue);
						return std::make_shared<KeyT>(std::move(key));
					} catch (...) {
						return nullptr;
					}
				}

				/**
				 * @brief Deserialize from optional Password.
				 * @tparam KeyT Key type.
				 * @param keyBinary Optional Password.
				 * @return Shared key, or nullptr.
				 */
				template<typename KeyT>
				std::shared_ptr<KeyT> DeserializeKey(const std::optional<Secure::Password>& keyBinary) noexcept {
					if (!keyBinary.has_value())
						return nullptr;
					return DeserializeKey<KeyT>(*keyBinary);
				}

				/**
				 * @brief Generate an Agreement keypair. Private stays in Password.
				 * @tparam KeyPairT Public wrapper type.
				 * @tparam AgreementT Crypto++ agreement type.
				 * @return Shared KeyPairT, or nullptr.
				 */
				template<typename KeyPairT, typename AgreementT, typename... CtorArgs>
				typename KeyPairT::PointerType AgreementGenerateKeyPair(CtorArgs&&... args) noexcept {
					try {
						AgreementT agr(std::forward<CtorArgs>(args)...);
						CryptoPP::SecByteBlock priv(agr.PrivateKeyLength());
						CryptoPP::SecByteBlock pub(agr.PublicKeyLength());
						agr.GenerateKeyPair(RNG(), priv, pub);

						auto pubStr = EncodeSecBlockBase64(pub);
						Secure::Password privPwd = PasswordFromSecBlock(priv);
						Helpers::SecureWipe(pub);

						return KeyPairT::template MakePointer<KeyPairT>(std::move(pubStr), std::move(privPwd));
					} catch (...) {
						return nullptr;
					}
				}
			}
		}
	}
}
