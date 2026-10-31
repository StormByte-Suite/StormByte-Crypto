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

#include <StormByte/crypto/hmac.hxx>
#include <StormByte/crypto/helpers/password_view.hxx>

#include <hmac.h>
#include <sha.h>

using namespace StormByte::Crypto::HMAC;

namespace {
	std::size_t TagSize(Algorithm algorithm) noexcept {
		switch (algorithm) {
			case Algorithm::SHA256:
				return CryptoPP::SHA256::DIGESTSIZE;
			case Algorithm::SHA384:
				return CryptoPP::SHA384::DIGESTSIZE;
		}
		return 0;
	}

	template<class Hash>
	void ComputeTag(
		const StormByte::Crypto::Secure::Password& key,
		std::span<const std::byte> message,
		StormByte::Safe::Binary& tag
	) {
		const CryptoPP::byte empty = 0;
		const auto keySize = StormByte::Crypto::Helpers::PasswordAccess::Size(key);
		const auto* keyData = keySize
			? StormByte::Crypto::Helpers::PasswordAccess::Data(key)
			: &empty;
		const auto* messageData = message.empty()
			? &empty
			: reinterpret_cast<const CryptoPP::byte*>(message.data());

		CryptoPP::HMAC<Hash> hmac(keyData, keySize);
		hmac.CalculateDigest(
			reinterpret_cast<CryptoPP::byte*>(tag.data()),
			messageData,
			message.size_bytes()
		);
	}
}

ExpectedTag StormByte::Crypto::HMAC::Compute(
	Algorithm algorithm,
	const Secure::Password& key,
	std::span<const std::byte> message
) {
	const std::size_t size = TagSize(algorithm);
	if (size == 0)
		return StormByte::Unexpected<Error>(Error::UnsupportedAlgorithm);

	StormByte::Safe::Binary tag(StormByte::ByteSize{size});
	try {
		switch (algorithm) {
			case Algorithm::SHA256:
				ComputeTag<CryptoPP::SHA256>(key, message, tag);
				break;
			case Algorithm::SHA384:
				ComputeTag<CryptoPP::SHA384>(key, message, tag);
				break;
			default:
				return StormByte::Unexpected<Error>(Error::UnsupportedAlgorithm);
		}
	} catch (...) {
		return StormByte::Unexpected<Error>(Error::BackendFailure);
	}
	return tag;
}

ExpectedVerification StormByte::Crypto::HMAC::Verify(
	Algorithm algorithm,
	const Secure::Password& key,
	std::span<const std::byte> message,
	std::span<const std::byte> tag
) {
	const std::size_t size = TagSize(algorithm);
	if (size == 0)
		return StormByte::Unexpected<Error>(Error::UnsupportedAlgorithm);
	if (tag.size() != size)
		return StormByte::Unexpected<Error>(Error::InvalidTagSize);

	auto expected = Compute(algorithm, key, message);
	if (!expected)
		return StormByte::Unexpected(expected.error());

	unsigned char difference = 0;
	for (std::size_t index = 0; index < size; ++index)
		difference |= static_cast<unsigned char>(
			(*expected)[StormByte::ByteSize{index}] ^ tag[index]
		);
	return difference == 0;
}
