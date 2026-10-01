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

#include <StormByte/safe/clonable.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>
#include <StormByte/safe/string.hxx>

#include <filesystem>
#include <optional>
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
		 * @namespace StormByte::Crypto::KeyPair
		 * @brief Keypairs of the Crypto module.
		 */
		namespace KeyPair {
			/**
			 * @enum Type
			 * @brief Available keypair algorithms.
			 */
			enum class Type {
				DSA,		///< DSA
				ECC,		///< Elliptic-curve encryption
				ECDH,		///< ECDH
				ECDSA,		///< ECDSA
				ED25519,	///< Ed25519
				RSA,		///< RSA
				X25519		///< X25519
			};

			/**
			 * @enum StorageFormat
			 * @brief On-disk encoding.
			 */
			enum class StorageFormat {
				PEM,	///< OpenSSL PEM
				DER		///< Binary DER
			};

			/**
			 * @class Generic
			 * @brief Abstract keypair. Concrete algorithms derive from this.
			 *
			 * Public key is a non-secret @ref StormByte::Safe::String (typically Base64 SPKI DER).
			 * Private key, when present, is a @ref StormByte::Crypto::Secure::Password
			 * holding PKCS#8 or native DER and is wiped with the last owner.
			 */
			class STORMBYTE_CRYPTO_PUBLIC Generic: public StormByte::Safe::Clonable<Generic> {
				public:
					/**
					 * @name Construction
					 * @{
					 */
					/**
					 * @brief Copy constructor.
					 * @param other Keypair to copy.
					 */
					Generic(const Generic& other) = default;

					/**
					 * @brief Move constructor.
					 * @param other Keypair to move.
					 */
					Generic(Generic&& other) noexcept = default;

					/**
					 * @brief Destructor. Drops the private-key handle.
					 */
					virtual ~Generic() noexcept;

					/**
					 * @brief Copy assignment.
					 * @param other Keypair to copy.
					 * @return Reference to this keypair.
					 */
					Generic& operator=(const Generic& other) = default;

					/**
					 * @brief Move assignment.
					 * @param other Keypair to move.
					 * @return Reference to this keypair.
					 */
					Generic& operator=(Generic&& other) noexcept = default;
					/** @} */

					/**
					 * @brief Algorithm of this keypair.
					 * @return Keypair type.
					 */
					inline enum Type Type() const noexcept {
						return m_type;
					}

					/**
					 * @brief Public key string.
					 * @return Public material owned by this keypair.
					 */
					inline const StormByte::Safe::String& PublicKey() const noexcept {
						return m_public_key;
					}

					/**
					 * @brief Whether a private key is stored.
					 * @return true if present.
					 */
					inline bool HasPrivateKey() const noexcept {
						return m_private_key.has_value();
					}

					/**
					 * @brief Private key, if any.
					 * @return Shared Password, or empty.
					 */
					inline const std::optional<Secure::Password>& PrivateKey() const noexcept {
						return m_private_key;
					}

					/**
					 * @name Persistence
					 * @{
					 */
					/**
					 * @brief Write public and private files under a directory. Private key unencrypted.
					 * @param directory Existing directory.
					 * @param baseName File stem.
					 * @param format PEM or DER.
					 * @return true on success.
					 */
					bool Save(const std::filesystem::path& directory, std::string_view baseName, StorageFormat format = StorageFormat::PEM) const noexcept;

					/**
					 * @brief Write public and private files. Private key encrypted (prefer PEM).
					 * @param directory Existing directory.
					 * @param baseName File stem.
					 * @param encryptPassword Password for the private file.
					 * @param format Prefer PEM when encrypting.
					 * @return true on success.
					 */
					bool Save(const std::filesystem::path& directory, std::string_view baseName, const Secure::Password& encryptPassword, StorageFormat format = StorageFormat::PEM) const noexcept;

					/**
					 * @brief Write only the public key.
					 * @param filePath Destination.
					 * @param format PEM or DER.
					 * @return true on success.
					 */
					bool SavePublic(const std::filesystem::path& filePath, StorageFormat format = StorageFormat::PEM) const noexcept;

					/**
					 * @brief Write only the private key, unencrypted.
					 * @param filePath Destination.
					 * @param format PEM or DER.
					 * @return true on success.
					 */
					bool SavePrivate(const std::filesystem::path& filePath, StorageFormat format = StorageFormat::PEM) const noexcept;

					/**
					 * @brief Write only the private key, encrypted (prefer PEM).
					 * @param filePath Destination.
					 * @param encryptPassword Password.
					 * @param format Prefer PEM.
					 * @return true on success.
					 */
					bool SavePrivate(const std::filesystem::path& filePath, const Secure::Password& encryptPassword, StorageFormat format = StorageFormat::PEM) const noexcept;
					/** @} */

				protected:
					enum Type m_type;						///< Algorithm
					StormByte::Safe::String m_public_key;	///< Public material
					std::optional<Secure::Password> m_private_key;	///< Private material, if any

					/**
					 * @brief Construct with algorithm and material.
					 * @param type Algorithm.
					 * @param public_key Public material.
					 * @param private_key Optional private Password.
					 */
					inline Generic(enum Type type, StormByte::Safe::String public_key, std::optional<Secure::Password> private_key = std::nullopt):
						m_type(type),
						m_public_key(std::move(public_key)),
						m_private_key(std::move(private_key)) {}
			};

			/**
			 * @brief Generate a keypair.
			 * @param type Algorithm.
			 * @param bits Key size in bits.
			 * @return Keypair pointer.
			 */
			STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(Type type, unsigned short bits) noexcept;

			/**
			 * @brief Load from separate public and private files. Format is auto-detected.
			 * @param publicKeyPath Public file, or empty.
			 * @param privateKeyPath Private file, or empty. No default: a single path is @ref Load(const std::filesystem::path&).
			 * @return Keypair pointer, or nullptr.
			 */
			STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Load(const std::filesystem::path& publicKeyPath, const std::filesystem::path& privateKeyPath) noexcept;

			/**
			 * @brief Load from separate files; decrypt the private key if needed.
			 * @param publicKeyPath Public file, or empty.
			 * @param privateKeyPath Private file.
			 * @param password Password for an encrypted private key.
			 * @return Keypair pointer, or nullptr.
			 */
			STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Load(const std::filesystem::path& publicKeyPath, const std::filesystem::path& privateKeyPath, const Secure::Password& password) noexcept;

			/**
			 * @brief Load from one file (public, private, or concatenated PEM).
			 * @param path Key file.
			 * @return Keypair pointer, or nullptr.
			 */
			STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Load(const std::filesystem::path& path) noexcept;

			/**
			 * @brief Load from one file; decrypt if needed.
			 * @param path Key file.
			 * @param password Password for encrypted private material.
			 * @return Keypair pointer, or nullptr.
			 */
			STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Load(const std::filesystem::path& path, const Secure::Password& password) noexcept;
		}
	}
}
