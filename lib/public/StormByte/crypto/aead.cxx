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

#include <StormByte/crypto/aead.hxx>
#include <StormByte/crypto/helpers/aead.hxx>
#include <StormByte/crypto/helpers/password_view.hxx>

#include <aes.h>
#include <gcm.h>

namespace {
	const CryptoPP::byte* Bytes(std::span<const std::byte> input) noexcept {
		static constexpr CryptoPP::byte empty = 0;
		return input.empty() ? &empty : reinterpret_cast<const CryptoPP::byte*>(input.data());
	}
}

StormByte::Crypto::AEAD::ExpectedSealed StormByte::Crypto::AEAD::Seal(
	Algorithm algorithm, const Secure::Password& key,
	std::span<const std::byte> nonce, std::span<const std::byte> plaintext,
	std::span<const std::byte> aad
) {
	auto valid = Helpers::ValidateAEAD(algorithm, key, nonce.size(), plaintext.size(), aad.size());
	if (!valid)
		return StormByte::Unexpected(valid.error());

	Sealed result{
		StormByte::Safe::Binary(StormByte::ByteSize{plaintext.size()}),
		StormByte::Safe::Binary(StormByte::ByteSize{TagSize})
	};
	CryptoPP::byte emptyOutput = 0;
	try {
		CryptoPP::GCM<CryptoPP::AES>::Encryption cipher;
		cipher.SetKeyWithIV(Helpers::PasswordAccess::Data(key), Helpers::PasswordAccess::Size(key),
			Bytes(nonce), NonceSize);
		cipher.EncryptAndAuthenticate(
			plaintext.empty() ? &emptyOutput : reinterpret_cast<CryptoPP::byte*>(result.ciphertext.data()),
			reinterpret_cast<CryptoPP::byte*>(result.tag.data()), TagSize,
			Bytes(nonce), static_cast<int>(NonceSize), Bytes(aad), aad.size(),
			Bytes(plaintext), plaintext.size());
	} catch (const CryptoPP::Exception&) {
		return StormByte::Unexpected<Error>(Error::BackendFailure);
	}
	return result;
}

StormByte::Crypto::AEAD::ExpectedPlaintext StormByte::Crypto::AEAD::Open(
	Algorithm algorithm, const Secure::Password& key,
	std::span<const std::byte> nonce, std::span<const std::byte> ciphertext,
	std::span<const std::byte> tag, std::span<const std::byte> aad
) {
	auto valid = Helpers::ValidateAEAD(algorithm, key, nonce.size(), ciphertext.size(), aad.size());
	if (!valid)
		return StormByte::Unexpected(valid.error());
	if (tag.size() != TagSize)
		return StormByte::Unexpected<Error>(Error::InvalidTagSize);

	// The password/envelope pipeline drains to public buffers. Keep the backend's
	// tentative plaintext in wiped private storage until whole-message verification.
	StormByte::Safe::SecureBinary plaintext(StormByte::ByteSize{ciphertext.size()});
	CryptoPP::byte emptyOutput = 0;
	try {
		CryptoPP::GCM<CryptoPP::AES>::Decryption cipher;
		cipher.SetKeyWithIV(Helpers::PasswordAccess::Data(key), Helpers::PasswordAccess::Size(key),
			Bytes(nonce), NonceSize);
		if (!cipher.DecryptAndVerify(
			ciphertext.empty() ? &emptyOutput : reinterpret_cast<CryptoPP::byte*>(plaintext.data()),
			Bytes(tag), TagSize,
			Bytes(nonce), static_cast<int>(NonceSize), Bytes(aad), aad.size(),
			Bytes(ciphertext), ciphertext.size()))
			return StormByte::Unexpected<Error>(Error::AuthenticationFailed);
	} catch (const CryptoPP::Exception&) {
		return StormByte::Unexpected<Error>(Error::BackendFailure);
	}
	return plaintext;
}
