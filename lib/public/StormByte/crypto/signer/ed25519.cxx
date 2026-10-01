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

#include <StormByte/crypto/helpers/password_view.hxx>
#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/engine/keypair/api.hxx>
#include <StormByte/crypto/engine/signer/details.hxx>
#include <StormByte/crypto/random.hxx>
#include <StormByte/crypto/signer/ed25519.hxx>

#include <filters.h>
#include <memory>
#include <queue.h>
#include <string>
#include <string_view>
#include <xed25519.h>

using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using StormByte::Buffer::WriteOnly;
using StormByte::Crypto::Helpers::PasswordAccess;
using StormByte::Crypto::Helpers::SecureWipe;
using namespace StormByte::Crypto::Signer;

ED25519::~ED25519() noexcept = default;

namespace {
	struct Ed25519SignBox final : StormByte::Crypto::Engine::Signer::SignBox {
		CryptoPP::ed25519::Signer signer;
		StormByte::BinaryData signature;
		std::unique_ptr<CryptoPP::SignerFilter> filter;
		bool ready = false;

		explicit Ed25519SignBox(const StormByte::Crypto::Secure::Password& priv) {
			const unsigned char* privData = PasswordAccess::Data(priv);
			const std::size_t privSize = PasswordAccess::Size(priv);
			if (!privData || privSize == 0)
				return;
			CryptoPP::ByteQueue queue;
			queue.Put(privData, privSize);
			signer.AccessPrivateKey().Load(queue);
			filter = std::make_unique<CryptoPP::SignerFilter>(
				StormByte::Crypto::RNG(),
				signer,
				new CryptoPP::StringSinkTemplate<StormByte::BinaryData>(signature)
			);
			ready = true;
		}

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

		bool Finalize(StormByte::BinaryData& out) override {
			if (!ready || !filter)
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

	struct Ed25519VerifyBox final : StormByte::Crypto::Engine::Signer::VerifyBox {
		CryptoPP::ed25519::Verifier verifier;
		bool result = false;
		std::unique_ptr<CryptoPP::SignatureVerificationFilter> filter;
		bool ready = false;

		explicit Ed25519VerifyBox(const StormByte::Safe::String& pubKeyB64) {
			const std::string pubKey { static_cast<std::string_view>(pubKeyB64) };
			CryptoPP::SecByteBlock pubRaw =
				StormByte::Crypto::Engine::KeyPair::DecodeSecBlockBase64(pubKey);
			CryptoPP::ByteQueue queue;
			queue.Put(pubRaw.data(), pubRaw.size());
			SecureWipe(pubRaw);
			verifier.AccessPublicKey().Load(queue);
			ready = true;
		}

		bool Begin(const std::string& signature) override {
			if (!ready)
				return false;
			try {
				filter = std::make_unique<CryptoPP::SignatureVerificationFilter>(
					verifier,
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

bool ED25519::DoSign(std::span<const std::byte> data, WriteOnly& output) const noexcept {
	if (!m_keypair || !m_keypair->HasPrivateKey())
		return false;
	return Engine::Signer::SignSpan(
		data, output,
		std::make_unique<Ed25519SignBox>(*m_keypair->PrivateKey()));
}

Consumer ED25519::DoSign(Consumer consumer, ReadMode mode) const noexcept {
	if (!m_keypair || !m_keypair->HasPrivateKey()) {
		Producer producer;
		producer.SetError();
		return producer.Consumer();
	}

	return Engine::Signer::SignStream(
		std::move(consumer), mode,
		std::make_unique<Ed25519SignBox>(*m_keypair->PrivateKey()));
}

bool ED25519::DoVerify(std::span<const std::byte> data,
	std::string_view signature) const noexcept {
	if (!m_keypair)
		return false;
	return Engine::Signer::VerifySpan(
		data, std::string{signature},
		std::make_unique<Ed25519VerifyBox>(m_keypair->PublicKey()));
}

bool ED25519::DoVerify(Consumer consumer,
	std::string_view signature,
	ReadMode mode) const noexcept {
	if (!m_keypair)
		return false;
	return Engine::Signer::VerifyStream(
		std::move(consumer), mode, std::string{signature},
		std::make_unique<Ed25519VerifyBox>(m_keypair->PublicKey()));
}
