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

#include <StormByte/buffer/consumer.hxx>
#include <StormByte/safe/clonable.hxx>
#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>
#include <StormByte/type_traits.hxx>
#include <StormByte/type_traits/safe.hxx>

#include <span>
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
		 * @namespace StormByte::Crypto::Signer
		 * @brief Signers of the Crypto module.
		 */
		namespace Signer {
			/**
			 * @enum Type
			 * @brief Available signer algorithms.
			 */
			enum class Type {
				DSA,		///< DSA
				ECDSA,		///< ECDSA
				ED25519,	///< Ed25519
				RSA			///< RSA
			};

			/**
			 * @class Generic
			 * @brief Abstract signer. Concrete algorithms derive from this.
			 * @note MaybeSafe requires ABI-compatible toolchains and all provider modules to remain
			 * loaded while objects, virtual functions or ownership callbacks can be used.
			 * The algorithm enum is Safe; the keypair uses Safe shared ownership and must satisfy
			 * its provider's MaybeSafe contract. Inline construction and special members delegate
			 * to Safe ownership or exported keypair operations rather than owning local heap storage.
			 * Destruction is exported, and owning Clone/Move implementations must allocate and bind
			 * creator/deleter callbacks in their provider module through Safe ownership operations.
			 * Derived providers must keep every field Safe or satisfy its MaybeSafe requirements,
			 * and preserve provider-owned allocation, copying, assignment, movement and destruction.
			 */
			class STORMBYTE_CRYPTO_PUBLIC Generic: public StormByte::Safe::Clonable<Generic> {
				public:
					/**
					 * @name Construction
					 * @{
					 */
					/**
					 * @brief Copy constructor.
					 * @param other Signer to copy.
					 */
					Generic(const Generic& other) = default;

					/**
					 * @brief Move constructor.
					 * @param other Signer to move.
					 */
					Generic(Generic&& other) noexcept = default;

					/**
					 * @brief Destructor.
					 */
					virtual ~Generic() noexcept;

					/**
					 * @brief Copy assignment.
					 * @param other Signer to copy.
					 * @return Reference to this signer.
					 */
					Generic& operator=(const Generic& other) = default;

					/**
					 * @brief Move assignment.
					 * @param other Signer to move.
					 * @return Reference to this signer.
					 */
					Generic& operator=(Generic&& other) noexcept = default;
					/** @} */

					/**
					 * @brief Keypair used to sign and verify.
					 * @return Keypair pointer.
					 */
					KeyPair::Generic::PointerType KeyPair() const noexcept {
						return m_keypair;
					}

					/**
					 * @name Sign
					 * @{
					 */
					/**
					 * @brief Sign a byte span.
					 * @param input Input bytes.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					inline bool Sign(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
						return DoSign(input, output);
					}

					/**
					 * @brief Sign an input range of byte-convertible values.
					 * @tparam Range Input range type.
					 * @param input Input values.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					template<StormByte::Type::ByteInputRange Range>
					bool Sign(const Range& input, Buffer::WriteOnly& output) const {
						StormByte::BinaryData data;
						for (const auto value: input) {
							data.emplace_back(static_cast<std::byte>(value));
						}
						return Sign(std::span<const std::byte>(data), output);
					}

					/**
					 * @brief Sign a ReadOnly buffer (copy).
					 * @param input Input buffer.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					inline bool Sign(const Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
						return DoSign(const_cast<Buffer::ReadOnly&>(input), output, ReadMode::Copy);
					}

					/**
					 * @brief Sign a ReadOnly buffer (move).
					 * @param input Input buffer.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					inline bool Sign(Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
						return DoSign(input, output, ReadMode::Move);
					}

					/**
					 * @brief Sign a Consumer.
					 * @param consumer Input consumer.
					 * @param mode Copy or move.
					 * @return Consumer with the signature.
					 */
					inline Buffer::Consumer Sign(Buffer::Consumer consumer, ReadMode mode = ReadMode::Move) const noexcept {
						return DoSign(consumer, mode);
					}
					/** @} */

					/**
					 * @name Verify
					 * @{
					 */
					/**
					 * @brief Verify a byte span against a signature.
					 * @param input Input bytes.
					 * @param signature Signature. Accepts String and std::string via string_view.
					 * @return true if valid.
					 */
					inline bool Verify(std::span<const std::byte> input, std::string_view signature) const noexcept {
						return DoVerify(input, signature);
					}

					/**
					 * @brief Verify an input range of byte-convertible values against a signature.
					 * @tparam Range Input range type.
					 * @param input Input values.
					 * @param signature Signature. Accepts String and std::string via string_view.
					 * @return true if valid.
					 */
					template<StormByte::Type::ByteInputRange Range>
					bool Verify(const Range& input, std::string_view signature) const {
						StormByte::BinaryData data;
						for (const auto value: input) {
							data.emplace_back(static_cast<std::byte>(value));
						}
						return Verify(std::span<const std::byte>(data), signature);
					}

					/**
					 * @brief Verify a ReadOnly buffer (copy).
					 * @param input Input buffer.
					 * @param signature Signature. Accepts String and std::string via string_view.
					 * @return true if valid.
					 */
					inline bool Verify(const Buffer::ReadOnly& input, std::string_view signature) const noexcept {
						return DoVerify(const_cast<Buffer::ReadOnly&>(input), signature, ReadMode::Copy);
					}

					/**
					 * @brief Verify a ReadOnly buffer (move).
					 * @param input Input buffer.
					 * @param signature Signature. Accepts String and std::string via string_view.
					 * @return true if valid.
					 */
					inline bool Verify(Buffer::ReadOnly& input, std::string_view signature) const noexcept {
						return DoVerify(input, signature, ReadMode::Move);
					}

					/**
					 * @brief Verify a Consumer.
					 * @param consumer Input consumer.
					 * @param signature Signature. Accepts String and std::string via string_view.
					 * @param mode Copy or move.
					 * @return true if valid.
					 */
					inline bool Verify(Buffer::Consumer consumer, std::string_view signature, ReadMode mode = ReadMode::Move) const noexcept {
						return DoVerify(consumer, signature, mode);
					}
					/** @} */

				protected:
					enum Type m_type;							///< Algorithm
					KeyPair::Generic::PointerType m_keypair;	///< Keypair

					/**
					 * @brief Construct from a keypair pointer.
					 * @param type Algorithm.
					 * @param keypair Keypair.
					 */
					inline Generic(enum Type type, KeyPair::Generic::PointerType keypair):
						m_type(type), m_keypair(keypair) {}

					/**
					 * @brief Construct by cloning a keypair.
					 * @param type Algorithm.
					 * @param keypair Keypair.
					 */
					inline Generic(enum Type type, const KeyPair::Generic& keypair):
						m_type(type), m_keypair(keypair.Clone()) {}

					/**
					 * @brief Construct by moving a keypair.
					 * @param type Algorithm.
					 * @param keypair Keypair.
					 */
					inline Generic(enum Type type, KeyPair::Generic&& keypair):
						m_type(type), m_keypair(keypair.Move()) {}

				private:
					/**
					 * @brief Sign a ReadOnly buffer.
					 * @param input Input buffer.
					 * @param output Destination buffer.
					 * @param mode Copy or move.
					 * @return true on success.
					 */
					bool DoSign(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept;

					/**
					 * @brief Sign a byte span.
					 * @param input Input bytes.
					 * @param output Destination buffer.
					 * @return true on success.
					 */
					virtual bool DoSign(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept = 0;

					/**
					 * @brief Sign a Consumer.
					 * @param consumer Input consumer.
					 * @param mode Copy or move.
					 * @return Consumer with the signature.
					 */
					virtual Buffer::Consumer DoSign(Buffer::Consumer consumer, ReadMode mode) const noexcept = 0;

					/**
					 * @brief Verify a ReadOnly buffer.
					 * @param input Input buffer.
					 * @param signature Signature.
					 * @param mode Copy or move.
					 * @return true if valid.
					 */
					bool DoVerify(Buffer::ReadOnly& input, std::string_view signature, ReadMode mode) const noexcept;

					/**
					 * @brief Verify a byte span.
					 * @param input Input bytes.
					 * @param signature Signature.
					 * @return true if valid.
					 */
					virtual bool DoVerify(std::span<const std::byte> input, std::string_view signature) const noexcept = 0;

					/**
					 * @brief Verify a Consumer.
					 * @param consumer Input consumer.
					 * @param signature Signature.
					 * @param mode Copy or move.
					 * @return true if valid.
					 */
					virtual bool DoVerify(Buffer::Consumer consumer, std::string_view signature, ReadMode mode) const noexcept = 0;
			};

			/**
			 * @brief Create a signer from a keypair pointer.
			 * @param type Algorithm.
			 * @param keypair Keypair.
			 * @return Signer pointer.
			 */
			STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(enum Type type, KeyPair::Generic::PointerType keypair) noexcept;

			/**
			 * @brief Create a signer by cloning a keypair.
			 * @param type Algorithm.
			 * @param keypair Keypair.
			 * @return Signer pointer.
			 */
			STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(enum Type type, const KeyPair::Generic& keypair) noexcept;

			/**
			 * @brief Create a signer by moving a keypair.
			 * @param type Algorithm.
			 * @param keypair Keypair.
			 * @return Signer pointer.
			 */
			STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(enum Type type, KeyPair::Generic&& keypair) noexcept;
		}
	}
}

STORMBYTE_DECLARE_MAYBE_SAFE(StormByte::Crypto::Signer::Generic);
