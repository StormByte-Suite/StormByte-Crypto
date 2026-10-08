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

#include <StormByte/crypto/engine/keypair/details.hxx>
#include <StormByte/crypto/helpers/password_view.hxx>
#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/crypto/visibility.h>
#include <StormByte/safe/optional.hxx>
#include <StormByte/safe/pointers.hxx>
#include <StormByte/safe/string.hxx>

#include <base64.h>
#include <queue.h>
#include <string_view>
#include <utility>

/**
 * @namespace StormByte::Crypto::Engine::KeyPair
 * @brief Private keypair implementation.
 */
namespace StormByte::Crypto::Engine::KeyPair {
	/**
	 * @brief Serialize a Crypto++ key to Base64.
	 * @tparam KeyT Key type.
	 * @param key Key.
	 * @return Base64, or empty on failure.
	 */
	template<typename KeyT>
	Safe::String SerializeKey(const KeyT& key) noexcept {
		try {
			Safe::String keyString;
			CryptoPP::ByteQueue queue;
			key.Save(queue);
			CryptoPP::Base64Encoder encoder(nullptr, false);
			queue.CopyTo(encoder);
			encoder.MessageEnd();
			keyString.resize(encoder.MaxRetrievable());
			if (!keyString.empty())
				encoder.Get(reinterpret_cast<CryptoPP::byte*>(keyString.data()), keyString.size());
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
			CryptoPP::SecByteBlock der(queue.CurrentSize());
			queue.Get(der.data(), der.size());
			Secure::Password result(der.data(), StormByte::ByteSize{der.size()});
			CryptoPP::SecureWipeBuffer(der.data(), der.size());
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
	 * @note Private backend owner only, not a certified Safe value. The concrete
	 *       destructor is bound in the creating module; Crypto, Base and the
	 *       backend must remain loaded until the last owner is released.
	 */
	template<typename KeyT>
	Safe::Shared<KeyT> DeserializeKey(std::string_view keyString) noexcept {
		try {
			auto key = Safe::MakeShared<KeyT>();
			CryptoPP::ByteQueue queue;
			CryptoPP::Base64Decoder decoder;
			decoder.Put(reinterpret_cast<const CryptoPP::byte*>(keyString.data()), keyString.size());
			decoder.MessageEnd();
			decoder.TransferTo(queue);
			key->Load(queue);
			return key;
		} catch (...) {
			return nullptr;
		}
	}

	/**
	 * @brief Deserialize a key from DER in a Password.
	 * @tparam KeyT Key type.
	 * @param keyBinary Password.
	 * @return Shared key, or nullptr.
	 */
	template<typename KeyT>
	Safe::Shared<KeyT> DeserializeKey(const Secure::Password& keyBinary) noexcept {
		try {
			const unsigned char* data = Helpers::PasswordAccess::Data(keyBinary);
			const std::size_t length = Helpers::PasswordAccess::Size(keyBinary);
			if (!data || length == 0)
				return nullptr;

			auto key = Safe::MakeShared<KeyT>();
			CryptoPP::ByteQueue queue;
			queue.Put(data, length);
			key->Load(queue);
			return key;
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
	Safe::Shared<KeyT> DeserializeKey(const Safe::Optional<Secure::Password>& keyBinary) noexcept {
		if (!keyBinary.has_value())
			return nullptr;
		return DeserializeKey<KeyT>(*keyBinary);
	}

	/**
	 * @brief Generate an Agreement keypair. Private stays in Password.
	 * @tparam KeyPairT Public wrapper type.
	 * @tparam AgreementT Crypto++ agreement type.
	 * @tparam CtorArgs Agreement constructor argument types.
	 * @param args Arguments forwarded to the agreement constructor.
	 * @return Shared KeyPairT, or nullptr.
	 */
	template<typename KeyPairT, typename AgreementT, typename... CtorArgs>
	typename KeyPairT::PointerType AgreementGenerateKeyPair(CtorArgs&&... args) noexcept {
		try {
			AgreementT agreement(std::forward<CtorArgs>(args)...);
			CryptoPP::SecByteBlock privateKey(agreement.PrivateKeyLength());
			CryptoPP::SecByteBlock publicKey(agreement.PublicKeyLength());
			agreement.GenerateKeyPair(RNG(), privateKey, publicKey);

			auto publicString = EncodeSecBlockBase64(publicKey);
			Secure::Password privatePassword = PasswordFromSecBlock(privateKey);
			CryptoPP::SecureWipeBuffer(publicKey.data(), publicKey.size());

			return KeyPairT::template MakePointer<KeyPairT>(std::move(publicString), std::move(privatePassword));
		} catch (...) {
			return nullptr;
		}
	}
}
