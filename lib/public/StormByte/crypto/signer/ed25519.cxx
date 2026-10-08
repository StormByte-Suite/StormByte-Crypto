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

#include <StormByte/crypto/engine/keypair/api.hxx>
#include <StormByte/crypto/engine/signer/details.hxx>
#include <StormByte/crypto/helpers/password_view.hxx>
#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/signer/ed25519.hxx>
#include <StormByte/safe/binary.hxx>
#include <StormByte/safe/pointers.hxx>

#include <filters.h>
#include <queue.h>
#include <string_view>
#include <xed25519.h>

using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using StormByte::Buffer::WriteOnly;
using StormByte::Crypto::Helpers::PasswordAccess;
using StormByte::Crypto::Helpers::SecureWipe;
using namespace StormByte::Crypto::Signer;

ED25519::~ED25519() noexcept = default;

Generic::PointerType ED25519::Clone() const noexcept {
	return MakePointer<ED25519>(*this);
}

Generic::PointerType ED25519::Move() noexcept {
	return MakePointer<ED25519>(std::move(*this));
}

namespace {
	/**
	 * @struct Ed25519SignBox
	 * @brief Ed25519 signing state owned and destroyed by Crypto.
	 */
	struct Ed25519SignBox final : StormByte::Crypto::Engine::Signer::SignBox {
		CryptoPP::ed25519::Signer signer;	///< Native signer, destroyed after the filter.
		StormByte::Safe::Unique<CryptoPP::SignerFilter> filter;	///< Owned signing filter.
		bool ready = false;	///< Whether the private key was loaded.

		/**
		 * @brief Load a private key and create its signing filter.
		 * @param priv DER private key, borrowed for construction.
		 */
		explicit Ed25519SignBox(const StormByte::Crypto::Secure::Password& priv) {
			const unsigned char* privData = PasswordAccess::Data(priv);
			const std::size_t privSize = PasswordAccess::Size(priv);
			if (!privData || privSize == 0)
				return;
			CryptoPP::ByteQueue queue;
			queue.Put(privData, privSize);
			signer.AccessPrivateKey().Load(queue);
			filter = StormByte::Safe::Unique<CryptoPP::SignerFilter>::MakePointer<CryptoPP::SignerFilter>(
				StormByte::Crypto::RNG(),
				signer
			);
			ready = true;
		}

		/**
		 * @brief Native signing state cannot be copied.
		 * @param other Source state.
		 */
		Ed25519SignBox(const Ed25519SignBox& other) = delete;

		/**
		 * @brief Native signing state cannot be moved.
		 * @param other Source state.
		 */
		Ed25519SignBox(Ed25519SignBox&& other) = delete;

		/**
		 * @brief Destroy the filter before its signer.
		 */
		~Ed25519SignBox() override = default;

		/**
		 * @brief Native signing state cannot be copy-assigned.
		 * @param other Source state.
		 * @return This state.
		 */
		Ed25519SignBox& operator=(const Ed25519SignBox& other) = delete;

		/**
		 * @brief Native signing state cannot be move-assigned.
		 * @param other Source state.
		 * @return This state.
		 */
		Ed25519SignBox& operator=(Ed25519SignBox&& other) = delete;

		/**
		 * @brief Feed one message chunk.
		 * @param in Input bytes, borrowed for this update.
		 * @return Whether the chunk was accepted.
		 */
		bool Update(std::span<const std::byte> in) override {
			if (!ready || !filter)
				return false;
			try {
				filter->Put(
					reinterpret_cast<const CryptoPP::byte*>(in.data()),
					in.size_bytes());
				return true;
			} catch (...) {
				return false;
			}
		}

		/**
		 * @brief Finish signing into Safe-owned storage.
		 * @param out Signature destination.
		 * @return Whether the signature was retrieved completely.
		 */
		bool Finalize(StormByte::Safe::Binary& out) override {
			if (!ready || !filter)
				return false;
			try {
				filter->MessageEnd();
				out.resize(StormByte::ByteSize{filter->MaxRetrievable()});
				const std::size_t outputSize = static_cast<std::size_t>(out.size());
				if (filter->Get(reinterpret_cast<CryptoPP::byte*>(out.data()), outputSize) != outputSize)
					return false;
				filter.reset();
				return true;
			} catch (...) {
				return false;
			}
		}
	};

	/**
	 * @struct Ed25519VerifyBox
	 * @brief Ed25519 verification state owned and destroyed by Crypto.
	 */
	struct Ed25519VerifyBox final : StormByte::Crypto::Engine::Signer::VerifyBox {
		CryptoPP::ed25519::Verifier verifier;	///< Native verifier, destroyed after the filter.
		StormByte::Safe::Unique<CryptoPP::SignatureVerificationFilter> filter;	///< Owned verification filter.
		bool ready = false;	///< Whether the public key was loaded.

		/**
		 * @brief Decode and load the public key.
		 * @param pubKeyB64 Base64 public key, borrowed for construction.
		 */
		explicit Ed25519VerifyBox(const StormByte::Safe::String& pubKeyB64) {
			CryptoPP::SecByteBlock pubRaw =
				StormByte::Crypto::Engine::KeyPair::DecodeSecBlockBase64(pubKeyB64);
			CryptoPP::ByteQueue queue;
			queue.Put(pubRaw.data(), pubRaw.size());
			SecureWipe(pubRaw);
			verifier.AccessPublicKey().Load(queue);
			ready = true;
		}

		/**
		 * @brief Native verification state cannot be copied.
		 * @param other Source state.
		 */
		Ed25519VerifyBox(const Ed25519VerifyBox& other) = delete;

		/**
		 * @brief Native verification state cannot be moved.
		 * @param other Source state.
		 */
		Ed25519VerifyBox(Ed25519VerifyBox&& other) = delete;

		/**
		 * @brief Destroy the filter before its verifier.
		 */
		~Ed25519VerifyBox() override = default;

		/**
		 * @brief Native verification state cannot be copy-assigned.
		 * @param other Source state.
		 * @return This state.
		 */
		Ed25519VerifyBox& operator=(const Ed25519VerifyBox& other) = delete;

		/**
		 * @brief Native verification state cannot be move-assigned.
		 * @param other Source state.
		 * @return This state.
		 */
		Ed25519VerifyBox& operator=(Ed25519VerifyBox&& other) = delete;

		/**
		 * @brief Supply the signature before the message.
		 * @param signature Signature bytes, borrowed for this call.
		 * @return Whether verification was initialized.
		 */
		bool Begin(std::string_view signature) override {
			if (!ready)
				return false;
			try {
				filter = StormByte::Safe::Unique<CryptoPP::SignatureVerificationFilter>::MakePointer<CryptoPP::SignatureVerificationFilter>(
					verifier,
					nullptr,
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
		 * @param in Input bytes, borrowed for this update.
		 * @return Whether the chunk was accepted.
		 */
		bool Update(std::span<const std::byte> in) override {
			if (!filter)
				return false;
			try {
				filter->Put(
					reinterpret_cast<const CryptoPP::byte*>(in.data()),
					in.size_bytes());
				return true;
			} catch (...) {
				return false;
			}
		}

		/**
		 * @brief Finish verification.
		 * @return Whether the signature is valid.
		 */
		bool Finalize() override {
			if (!filter)
				return false;
			try {
				filter->MessageEnd();
				const bool verified = filter->GetLastResult();
				filter.reset();
				return verified;
			} catch (...) {
				return false;
			}
		}
	};
}

bool ED25519::DoSign(std::span<const std::byte> data, WriteOnly& output) const noexcept {
	if (!m_keypair || !m_keypair->HasPrivateKey())
		return false;
	try {
		return Engine::Signer::SignSpan(
			data, output,
			StormByte::Safe::Unique<Engine::Signer::SignBox>::MakePointer<Ed25519SignBox>(*m_keypair->PrivateKey()));
	} catch (...) {
		return false;
	}
}

Consumer ED25519::DoSign(Consumer consumer, ReadMode mode) const noexcept {
	if (m_keypair && m_keypair->HasPrivateKey()) {
		try {
			return Engine::Signer::SignStream(
				std::move(consumer), mode,
				StormByte::Safe::Unique<Engine::Signer::SignBox>::MakePointer<Ed25519SignBox>(*m_keypair->PrivateKey()));
		} catch (...) {
			consumer.Producer().SetError();
			return consumer;
		}
	}

	Producer producer;
	producer.SetError();
	return producer.Consumer();
}

bool ED25519::DoVerify(std::span<const std::byte> data,
	std::string_view signature) const noexcept {
	if (!m_keypair)
		return false;
	try {
		return Engine::Signer::VerifySpan(
			data, signature,
			StormByte::Safe::Unique<Engine::Signer::VerifyBox>::MakePointer<Ed25519VerifyBox>(m_keypair->PublicKey()));
	} catch (...) {
		return false;
	}
}

bool ED25519::DoVerify(Consumer consumer,
	std::string_view signature,
	ReadMode mode) const noexcept {
	if (!m_keypair)
		return false;
	try {
		return Engine::Signer::VerifyStream(
			std::move(consumer), mode, signature,
			StormByte::Safe::Unique<Engine::Signer::VerifyBox>::MakePointer<Ed25519VerifyBox>(m_keypair->PublicKey()));
	} catch (...) {
		return false;
	}
}
