/*
 * Copyright (C) 2024-2026 David C. Manuelda (StormBytePP)
 *
 * This file is part of StormByte-Crypto.
 *
 * StormByte-Crypto original source is dual-licensed:
 *
 * 1. GNU Lesser General Public License v3.0 (or later)
 *    You may redistribute and/or modify this file under the terms of the
 *    GNU Lesser General Public License version 3 (or later).
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

#include <StormByte/crypto/hkdf.hxx>
#include <StormByte/crypto/helpers/password_view.hxx>

#include <cryptlib.h>
#include <hmac.h>
#include <secblock.h>
#include <sha.h>

#include <algorithm>
#include <cstring>

namespace {
	using StormByte::Crypto::HKDF::Algorithm;
	using StormByte::Crypto::HKDF::Error;
	using StormByte::Crypto::HKDF::ExpectedKey;
	using StormByte::Crypto::Secure::Password;

	std::size_t HashSize(Algorithm algorithm) noexcept {
		switch (algorithm) {
			case Algorithm::SHA256:
				return CryptoPP::SHA256::DIGESTSIZE;
			case Algorithm::SHA384:
				return CryptoPP::SHA384::DIGESTSIZE;
		}
		return 0;
	}

	template<class Hash>
	ExpectedKey ExtractWith(
		std::span<const std::byte> salt,
		const Password& inputKeyMaterial
	) {
		constexpr std::size_t hashSize = Hash::DIGESTSIZE;
		CryptoPP::SecByteBlock emptySalt;
		if (salt.empty()) {
			emptySalt = CryptoPP::SecByteBlock(hashSize);
			std::memset(emptySalt.data(), 0, hashSize);
		}

		const auto saltSize = salt.empty() ? hashSize : salt.size();
		const auto* saltData = salt.empty()
			? emptySalt.data()
			: reinterpret_cast<const CryptoPP::byte*>(salt.data());
		const auto inputSize = StormByte::Crypto::Helpers::PasswordAccess::Size(inputKeyMaterial);
		const CryptoPP::byte emptyInput = 0;
		const auto* inputData = inputSize
			? StormByte::Crypto::Helpers::PasswordAccess::Data(inputKeyMaterial)
			: &emptyInput;

		CryptoPP::SecByteBlock prk(hashSize);
		try {
			CryptoPP::HMAC<Hash> hmac(saltData, saltSize);
			hmac.CalculateDigest(prk.data(), inputData, inputSize);
		} catch (const CryptoPP::Exception&) {
			return StormByte::Unexpected<Error>(Error::BackendFailure);
		}
		return Password(prk.data(), StormByte::ByteSize{hashSize});
	}

	template<class Hash>
	ExpectedKey ExpandWith(
		const Password& pseudorandomKey,
		std::span<const std::byte> info,
		std::size_t outputSize
	) {
		constexpr std::size_t hashSize = Hash::DIGESTSIZE;
		const auto keySize = StormByte::Crypto::Helpers::PasswordAccess::Size(pseudorandomKey);
		const auto* keyData = StormByte::Crypto::Helpers::PasswordAccess::Data(pseudorandomKey);
		const auto* infoData = info.empty()
			? nullptr
			: reinterpret_cast<const CryptoPP::byte*>(info.data());
		CryptoPP::SecByteBlock previous(hashSize);
		CryptoPP::SecByteBlock output(outputSize);
		std::size_t written = 0;
		CryptoPP::byte counter = 0;

		try {
			while (written < outputSize) {
				++counter;
				CryptoPP::HMAC<Hash> hmac(keyData, keySize);
				if (counter > 1)
					hmac.Update(previous.data(), hashSize);
				if (!info.empty())
					hmac.Update(infoData, info.size());
				hmac.Update(&counter, sizeof(counter));
				hmac.Final(previous.data());

				const std::size_t copySize = std::min(hashSize, outputSize - written);
				std::memcpy(output.data() + written, previous.data(), copySize);
				written += copySize;
			}
		} catch (const CryptoPP::Exception&) {
			return StormByte::Unexpected<Error>(Error::BackendFailure);
		}
		return Password(output.data(), StormByte::ByteSize{outputSize});
	}
}

StormByte::Crypto::HKDF::ExpectedKey StormByte::Crypto::HKDF::Extract(
	Algorithm algorithm,
	std::span<const std::byte> salt,
	const Secure::Password& inputKeyMaterial
) {
	if (HashSize(algorithm) == 0)
		return StormByte::Unexpected<Error>(Error::UnsupportedAlgorithm);

	switch (algorithm) {
		case Algorithm::SHA256:
			return ExtractWith<CryptoPP::SHA256>(salt, inputKeyMaterial);
		case Algorithm::SHA384:
			return ExtractWith<CryptoPP::SHA384>(salt, inputKeyMaterial);
	}
	return StormByte::Unexpected<Error>(Error::UnsupportedAlgorithm);
}

StormByte::Crypto::HKDF::ExpectedKey StormByte::Crypto::HKDF::Expand(
	Algorithm algorithm,
	const Secure::Password& pseudorandomKey,
	std::span<const std::byte> info,
	std::size_t outputSize
) {
	const std::size_t hashSize = HashSize(algorithm);
	if (hashSize == 0)
		return StormByte::Unexpected<Error>(Error::UnsupportedAlgorithm);
	if (pseudorandomKey.Size() < StormByte::ByteSize{hashSize})
		return StormByte::Unexpected<Error>(Error::InvalidPseudorandomKeySize);
	if (outputSize > 255 * hashSize)
		return StormByte::Unexpected<Error>(Error::OutputTooLong);

	switch (algorithm) {
		case Algorithm::SHA256:
			return ExpandWith<CryptoPP::SHA256>(pseudorandomKey, info, outputSize);
		case Algorithm::SHA384:
			return ExpandWith<CryptoPP::SHA384>(pseudorandomKey, info, outputSize);
	}
	return StormByte::Unexpected<Error>(Error::UnsupportedAlgorithm);
}
