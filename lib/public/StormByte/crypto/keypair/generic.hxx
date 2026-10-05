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
#include <StormByte/safe/optional.hxx>
#include <StormByte/safe/string.hxx>

#include <filesystem>
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
			 * @brief Borrowed native path characters for allocation-free DLL arguments.
			 * @note Uses wide characters on Windows and bytes on Linux/macOS. The
			 *       characters must remain valid for the call; Crypto copies them
			 *       into an owned filesystem path before performing OS operations.
			 */
			using PathView = std::basic_string_view<std::filesystem::path::value_type>;

			/**
			 * @class Generic
			 * @brief Abstract keypair. Concrete algorithms derive from this.
			 *
			 * Public key is a non-secret @ref StormByte::Safe::String (typically Base64 SPKI DER).
			 * Private key, when present, is a @ref StormByte::Crypto::Secure::Password
			 * holding PKCS#8 or native DER and is wiped with the last owner.
			 * @note Conditional DLL safety requires ABI-compatible modules and Crypto, Base
			 *       and Buffer to remain loaded while values or ownership callbacks exist.
			 *       Crypto binds private-material callbacks and defines value operations
			 *       out of line. Derived providers must preserve these requirements and
			 *       use boundary-safe fields, allocation, destruction and Clone/Move paths.
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
					Generic(const Generic& other);

					/**
					 * @brief Move constructor.
					 * @param other Keypair to move.
					 */
					Generic(Generic&& other) noexcept;

					/**
					 * @brief Destructor. Drops the private-key handle.
					 */
					virtual ~Generic() noexcept;

					/**
					 * @brief Copy assignment.
					 * @param other Keypair to copy.
					 * @return Reference to this keypair.
					 */
					Generic& operator=(const Generic& other);

					/**
					 * @brief Move assignment.
					 * @param other Keypair to move.
					 * @return Reference to this keypair.
					 */
					Generic& operator=(Generic&& other) noexcept;
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
					 * @return Safe optional containing a shared Password, or empty.
					 * @note Dereference returns a Password snapshot. Retain that snapshot
					 *       for the lifetime of any borrowed byte pointer or span.
					 */
					inline const StormByte::Safe::Optional<Secure::Password>& PrivateKey() const noexcept {
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
					bool Save(PathView directory, std::string_view baseName, StorageFormat format = StorageFormat::PEM) const noexcept;

					/**
					 * @brief Caller-side filesystem path adapter for unencrypted Save.
					 * @tparam Compatibility Defaulted to prefer the view overload for native strings.
					 * @param directory Existing directory.
					 * @param baseName File stem.
					 * @param format PEM or DER.
					 * @return true on success.
					 */
					template<typename Compatibility = void>
					STORMBYTE_FORCE_INLINE bool Save(const std::filesystem::path& directory, std::string_view baseName, StorageFormat format = StorageFormat::PEM) const noexcept {
						return Save(PathView{directory.native()}, baseName, format);
					}

					/**
					 * @brief Write public and private files. Private key encrypted (prefer PEM).
					 * @param directory Existing directory.
					 * @param baseName File stem.
					 * @param encryptPassword Password for the private file.
					 * @param format Prefer PEM when encrypting.
					 * @return true on success.
					 */
					bool Save(PathView directory, std::string_view baseName, const Secure::Password& encryptPassword, StorageFormat format = StorageFormat::PEM) const noexcept;

					/**
					 * @brief Caller-side filesystem path adapter for encrypted Save.
					 * @tparam Compatibility Defaulted to prefer the view overload for native strings.
					 * @param directory Existing directory.
					 * @param baseName File stem.
					 * @param encryptPassword Password for the private file.
					 * @param format Prefer PEM when encrypting.
					 * @return true on success.
					 */
					template<typename Compatibility = void>
					STORMBYTE_FORCE_INLINE bool Save(const std::filesystem::path& directory, std::string_view baseName, const Secure::Password& encryptPassword, StorageFormat format = StorageFormat::PEM) const noexcept {
						return Save(PathView{directory.native()}, baseName, encryptPassword, format);
					}

					/**
					 * @brief Write only the public key.
					 * @param filePath Destination.
					 * @param format PEM or DER.
					 * @return true on success.
					 */
					bool SavePublic(PathView filePath, StorageFormat format = StorageFormat::PEM) const noexcept;

					/**
					 * @brief Caller-side filesystem path adapter for SavePublic.
					 * @tparam Compatibility Defaulted to prefer the view overload for native strings.
					 * @param filePath Destination.
					 * @param format PEM or DER.
					 * @return true on success.
					 */
					template<typename Compatibility = void>
					STORMBYTE_FORCE_INLINE bool SavePublic(const std::filesystem::path& filePath, StorageFormat format = StorageFormat::PEM) const noexcept {
						return SavePublic(PathView{filePath.native()}, format);
					}

					/**
					 * @brief Write only the private key, unencrypted.
					 * @param filePath Destination.
					 * @param format PEM or DER.
					 * @return true on success.
					 */
					bool SavePrivate(PathView filePath, StorageFormat format = StorageFormat::PEM) const noexcept;

					/**
					 * @brief Caller-side filesystem path adapter for unencrypted SavePrivate.
					 * @tparam Compatibility Defaulted to prefer the view overload for native strings.
					 * @param filePath Destination.
					 * @param format PEM or DER.
					 * @return true on success.
					 */
					template<typename Compatibility = void>
					STORMBYTE_FORCE_INLINE bool SavePrivate(const std::filesystem::path& filePath, StorageFormat format = StorageFormat::PEM) const noexcept {
						return SavePrivate(PathView{filePath.native()}, format);
					}

					/**
					 * @brief Write only the private key, encrypted (prefer PEM).
					 * @param filePath Destination.
					 * @param encryptPassword Password.
					 * @param format Prefer PEM.
					 * @return true on success.
					 */
					bool SavePrivate(PathView filePath, const Secure::Password& encryptPassword, StorageFormat format = StorageFormat::PEM) const noexcept;

					/**
					 * @brief Caller-side filesystem path adapter for encrypted SavePrivate.
					 * @tparam Compatibility Defaulted to prefer the view overload for native strings.
					 * @param filePath Destination.
					 * @param encryptPassword Password.
					 * @param format Prefer PEM.
					 * @return true on success.
					 */
					template<typename Compatibility = void>
					STORMBYTE_FORCE_INLINE bool SavePrivate(const std::filesystem::path& filePath, const Secure::Password& encryptPassword, StorageFormat format = StorageFormat::PEM) const noexcept {
						return SavePrivate(PathView{filePath.native()}, encryptPassword, format);
					}
					/** @} */

				protected:
					enum Type m_type;						///< Algorithm
					StormByte::Safe::String m_public_key;	///< Public material
					StormByte::Safe::Optional<Secure::Password> m_private_key;	///< Crypto-owned optional private material.

					/**
					 * @brief Construct with algorithm and material.
					 * @param type Algorithm.
					 * @param public_key Public material.
					 * @param private_key Optional private Password.
					 */
					Generic(enum Type type, StormByte::Safe::String public_key, StormByte::Safe::Optional<Secure::Password> private_key = std::nullopt);
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
			 * @param privateKeyPath Private file, or empty. No default: a single path is @ref Load(PathView).
			 * @return Keypair pointer, or nullptr.
			 */
			STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Load(PathView publicKeyPath, PathView privateKeyPath) noexcept;

			/**
			 * @brief Caller-side filesystem path adapter for loading separate files.
			 * @tparam Compatibility Defaulted to prefer the view overload for native strings.
			 * @param publicKeyPath Public file, or empty.
			 * @param privateKeyPath Private file, or empty.
			 * @return Keypair pointer, or nullptr.
			 */
			template<typename Compatibility = void>
			STORMBYTE_FORCE_INLINE Generic::PointerType Load(const std::filesystem::path& publicKeyPath, const std::filesystem::path& privateKeyPath) noexcept {
				return Load(PathView{publicKeyPath.native()}, PathView{privateKeyPath.native()});
			}

			/**
			 * @brief Load from separate files; decrypt the private key if needed.
			 * @param publicKeyPath Public file, or empty.
			 * @param privateKeyPath Private file.
			 * @param password Password for an encrypted private key.
			 * @return Keypair pointer, or nullptr.
			 */
			STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Load(PathView publicKeyPath, PathView privateKeyPath, const Secure::Password& password) noexcept;

			/**
			 * @brief Caller-side filesystem path adapter for loading separate encrypted files.
			 * @tparam Compatibility Defaulted to prefer the view overload for native strings.
			 * @param publicKeyPath Public file, or empty.
			 * @param privateKeyPath Private file.
			 * @param password Password for an encrypted private key.
			 * @return Keypair pointer, or nullptr.
			 */
			template<typename Compatibility = void>
			STORMBYTE_FORCE_INLINE Generic::PointerType Load(const std::filesystem::path& publicKeyPath, const std::filesystem::path& privateKeyPath, const Secure::Password& password) noexcept {
				return Load(PathView{publicKeyPath.native()}, PathView{privateKeyPath.native()}, password);
			}

			/**
			 * @brief Load from one file (public, private, or concatenated PEM).
			 * @param path Key file.
			 * @return Keypair pointer, or nullptr.
			 */
			STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Load(PathView path) noexcept;

			/**
			 * @brief Caller-side filesystem path adapter for loading one file.
			 * @tparam Compatibility Defaulted to prefer the view overload for native strings.
			 * @param path Key file.
			 * @return Keypair pointer, or nullptr.
			 */
			template<typename Compatibility = void>
			STORMBYTE_FORCE_INLINE Generic::PointerType Load(const std::filesystem::path& path) noexcept {
				return Load(PathView{path.native()});
			}

			/**
			 * @brief Load from one file; decrypt if needed.
			 * @param path Key file.
			 * @param password Password for encrypted private material.
			 * @return Keypair pointer, or nullptr.
			 */
			STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Load(PathView path, const Secure::Password& password) noexcept;

			/**
			 * @brief Caller-side filesystem path adapter for loading one encrypted file.
			 * @tparam Compatibility Defaulted to prefer the view overload for native strings.
			 * @param path Key file.
			 * @param password Password for encrypted private material.
			 * @return Keypair pointer, or nullptr.
			 */
			template<typename Compatibility = void>
			STORMBYTE_FORCE_INLINE Generic::PointerType Load(const std::filesystem::path& path, const Secure::Password& password) noexcept {
				return Load(PathView{path.native()}, password);
			}
		}
	}
}

STORMBYTE_DECLARE_MAYBE_SAFE(StormByte::Crypto::KeyPair::Generic);
