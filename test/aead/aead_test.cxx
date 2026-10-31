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
#include <StormByte/safe/optional.hxx>
#include <StormByte/safe/vector.hxx>
#include <StormByte/test_handlers.h>

#include <algorithm>
#include <array>
#include <iostream>
#include <limits>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;

namespace {
	std::vector<std::byte> FromHex(std::string_view hex) {
		std::vector<std::byte> result;
		for (std::size_t index = 0; index < hex.size(); index += 2) {
			const auto digit = [](char value) -> unsigned int {
				return value <= '9' ? value - '0' : value - 'a' + 10;
			};
			result.push_back(static_cast<std::byte>((digit(hex[index]) << 4) | digit(hex[index + 1])));
		}
		return result;
	}

	Password Secret(std::span<const std::byte> bytes) {
		return Password(bytes.data(), StormByte::ByteSize{bytes.size()});
	}

	bool Equal(const StormByte::Safe::Binary& value, std::span<const std::byte> bytes) {
		return std::ranges::equal(value.span(), bytes);
	}

	struct Vector {
		AEAD::Algorithm algorithm;
		std::string_view key, nonce, plaintext, aad, ciphertext, tag;
	};

	// NIST SP 800-38D/GCM submission test cases, 96-bit IV, full tags:
	// https://csrc.nist.gov/CSRC/media/Projects/Block-Cipher-Techniques/documents/BCM/Proposed-Modes/gcm/gcm-spec.pdf
	constexpr std::array vectors{
		Vector{AEAD::Algorithm::AES128GCM,
			"00000000000000000000000000000000", "000000000000000000000000",
			"", "", "", "58e2fccefa7e3061367f1d57a4e7455a"},
		Vector{AEAD::Algorithm::AES256GCM,
			"0000000000000000000000000000000000000000000000000000000000000000",
			"000000000000000000000000", "", "", "", "530f8afbc74536b9a963b4f1c4cb738b"},
		Vector{AEAD::Algorithm::AES128GCM,
			"00000000000000000000000000000000", "000000000000000000000000",
			"00000000000000000000000000000000", "",
			"0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf"},
		Vector{AEAD::Algorithm::AES256GCM,
			"0000000000000000000000000000000000000000000000000000000000000000",
			"000000000000000000000000", "00000000000000000000000000000000", "",
			"cea7403d4d606b6e074ec5d3baf39d18", "d0d1c8a799996bf0265b98b5d48ab919"},
		Vector{AEAD::Algorithm::AES128GCM,
			"feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
			"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
			"1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
			"feedfacedeadbeeffeedfacedeadbeefabaddad2",
			"42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
			"21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
			"5bc94fbc3221a5db94fae95ae7121a47"},
		Vector{AEAD::Algorithm::AES256GCM,
			"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
			"cafebabefacedbaddecaf888",
			"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
			"1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
			"feedfacedeadbeeffeedfacedeadbeefabaddad2",
			"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
			"8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
			"76fc6ece0f4e1768cddf8853bb2d551b"}
	};
}

int test_nist_known_answers() {
	for (const auto& vector : vectors) {
		const auto keyBytes = FromHex(vector.key);
		const auto nonce = FromHex(vector.nonce);
		const auto plaintext = FromHex(vector.plaintext);
		const auto aad = FromHex(vector.aad);
		const auto ciphertext = FromHex(vector.ciphertext);
		const auto tag = FromHex(vector.tag);
		const Password key = Secret(keyBytes);
		auto sealed = AEAD::Seal(vector.algorithm, key, nonce, plaintext, aad);
		ASSERT_TRUE(sealed);
		ASSERT_EQUAL(StormByte::ByteSize{plaintext.size()}, sealed->ciphertext.size());
		ASSERT_EQUAL(StormByte::ByteSize{AEAD::TagSize}, sealed->tag.size());
		ASSERT_TRUE(Equal(sealed->ciphertext, ciphertext));
		ASSERT_TRUE(Equal(sealed->tag, tag));
		// Verify independently supplied ciphertext/tag, not only our own output.
		auto opened = AEAD::Open(vector.algorithm, key, nonce, ciphertext, tag, aad);
		ASSERT_TRUE(opened);
		ASSERT_TRUE(Equal(*opened, plaintext));
	}
	RETURN_TEST(0);
}

int test_all_authentication_surfaces() {
	for (std::size_t index : {std::size_t{4}, std::size_t{5}}) {
		const auto& vector = vectors[index];
		auto keyBytes = FromHex(vector.key);
		auto nonce = FromHex(vector.nonce);
		auto ciphertext = FromHex(vector.ciphertext);
		auto tag = FromHex(vector.tag);
		auto aad = FromHex(vector.aad);
		const Password key = Secret(keyBytes);
		const auto rejected = [&](const Password& candidateKey) {
			auto opened = AEAD::Open(vector.algorithm, candidateKey, nonce, ciphertext, tag, aad);
			return !opened && *opened.error() == AEAD::Error::AuthenticationFailed;
		};
		keyBytes[0] ^= std::byte{1};
		ASSERT_TRUE(rejected(Secret(keyBytes)));
		keyBytes[0] ^= std::byte{1};
		for (auto* bytes : {&nonce, &ciphertext, &tag, &aad}) {
			for (std::size_t offset = 0; offset < bytes->size(); ++offset) {
				(*bytes)[offset] ^= std::byte{1};
				ASSERT_TRUE(rejected(key));
				(*bytes)[offset] ^= std::byte{1};
			}
		}
		aad.clear();
		ASSERT_TRUE(rejected(key));
		aad = FromHex(vector.aad);
		ciphertext.pop_back();
		ASSERT_TRUE(rejected(key));
		ciphertext = FromHex(vector.ciphertext);
		ciphertext.push_back(std::byte{0});
		ASSERT_TRUE(rejected(key));
		ciphertext.clear();
		ASSERT_TRUE(rejected(key));
	}
	RETURN_TEST(0);
}

int test_validation_errors() {
	for (const auto algorithm : {AEAD::Algorithm::AES128GCM, AEAD::Algorithm::AES256GCM}) {
		const std::size_t keySize = algorithm == AEAD::Algorithm::AES128GCM ? 16 : 32;
		std::vector<std::byte> keyBytes(keySize);
		const Password key = Secret(keyBytes);
		std::vector<std::byte> nonce(AEAD::NonceSize), tag(AEAD::TagSize);
		for (std::size_t size : {std::size_t{0}, keySize - 1, keySize + 1, std::size_t{24},
			algorithm == AEAD::Algorithm::AES128GCM ? std::size_t{32} : std::size_t{16}}) {
			const Password badKey = Secret(std::vector<std::byte>(size));
			auto sealed = AEAD::Seal(algorithm, badKey, nonce, {});
			auto opened = AEAD::Open(algorithm, badKey, nonce, {}, tag);
			ASSERT_FALSE(sealed);
			ASSERT_FALSE(opened);
			ASSERT_TRUE(*sealed.error() == AEAD::Error::InvalidKeySize);
			ASSERT_TRUE(*opened.error() == AEAD::Error::InvalidKeySize);
		}
		for (std::size_t size : {std::size_t{0}, std::size_t{11}, std::size_t{13}, std::size_t{16}}) {
			nonce.resize(size);
			auto sealed = AEAD::Seal(algorithm, key, nonce, {});
			auto opened = AEAD::Open(algorithm, key, nonce, {}, tag);
			ASSERT_FALSE(sealed);
			ASSERT_FALSE(opened);
			ASSERT_TRUE(*sealed.error() == AEAD::Error::InvalidNonceSize);
			ASSERT_TRUE(*opened.error() == AEAD::Error::InvalidNonceSize);
		}
		nonce.resize(AEAD::NonceSize);
		for (std::size_t size = 0; size <= 32; ++size) {
			if (size == AEAD::TagSize)
				continue;
			tag.resize(size);
			auto opened = AEAD::Open(algorithm, key, nonce, {}, tag);
			ASSERT_FALSE(opened);
			ASSERT_TRUE(*opened.error() == AEAD::Error::InvalidTagSize);
		}
		tag.resize(AEAD::TagSize);
		auto sealed = AEAD::Seal(static_cast<AEAD::Algorithm>(-1), key, nonce, {});
		auto opened = AEAD::Open(static_cast<AEAD::Algorithm>(-1), key, nonce, {}, tag);
		ASSERT_FALSE(sealed);
		ASSERT_FALSE(opened);
		ASSERT_TRUE(*sealed.error() == AEAD::Error::UnsupportedAlgorithm);
		ASSERT_TRUE(*opened.error() == AEAD::Error::UnsupportedAlgorithm);
		Password moved = key;
		const Password retained = std::move(moved);
		sealed = AEAD::Seal(algorithm, moved, nonce, {});
		ASSERT_FALSE(sealed);
		ASSERT_TRUE(*sealed.error() == AEAD::Error::InvalidKeySize);
		ASSERT_TRUE(retained == key);
	}
	RETURN_TEST(0);
}

int test_empty_and_binary_inputs_and_lifecycle() {
	for (const auto algorithm : {AEAD::Algorithm::AES128GCM, AEAD::Algorithm::AES256GCM}) {
		std::vector<std::byte> keyBytes(algorithm == AEAD::Algorithm::AES128GCM ? 16 : 32);
		const Password key = Secret(keyBytes);
		const auto nonce = FromHex("000102030405060708090a0b");
		const auto aad = FromHex("000100ff000200");
		for (std::size_t size : {std::size_t{0}, std::size_t{1}, std::size_t{15},
			std::size_t{16}, std::size_t{17}, std::size_t{1025}}) {
			std::vector<std::byte> message(size);
			for (std::size_t offset = 0; offset < size; ++offset)
				message[offset] = static_cast<std::byte>(offset % 256);
			StormByte::Safe::SecureBinary retained;
			StormByte::Safe::Optional<AEAD::Sealed> envelope;
			{
				auto sealed = AEAD::Seal(algorithm, key, nonce, message, aad);
				ASSERT_TRUE(sealed);
				auto opened = AEAD::Open(algorithm, key, nonce,
					sealed->ciphertext.span(), sealed->tag.span(), aad);
				ASSERT_TRUE(opened);
				StormByte::Safe::SecureBinary copied = *opened;
				if (!copied.empty()) {
					copied[StormByte::ByteSize{0}] ^= std::byte{1};
					ASSERT_TRUE(Equal(*opened, message));
					copied[StormByte::ByteSize{0}] ^= std::byte{1};
				}
				StormByte::Safe::SecureBinary moved = std::move(copied);
				ASSERT_TRUE(copied.empty());
				retained = std::move(moved);
				AEAD::Sealed ciphertextCopy = *sealed;
				AEAD::Sealed ciphertextMoved = std::move(ciphertextCopy);
				envelope = std::move(ciphertextMoved);
				StormByte::Safe::Vector<StormByte::Safe::SecureBinary> secrets;
				secrets.push_back(retained);
				ASSERT_TRUE(Equal(secrets[StormByte::Size{0}], message));
			}
			ASSERT_TRUE(Equal(retained, message));
			ASSERT_EQUAL(StormByte::ByteSize{size}, retained.size());
			const auto stored = *envelope;
			auto reopened = AEAD::Open(algorithm, key, nonce,
				stored.ciphertext.span(), stored.tag.span(), aad);
			ASSERT_TRUE(reopened);
			ASSERT_TRUE(Equal(*reopened, retained.span()));
			if (!reopened->empty()) {
				(*reopened)[StormByte::ByteSize{0}] ^= std::byte{1};
				ASSERT_TRUE(Equal(retained, message));
			}
			auto wrongAAD = aad;
			wrongAAD.back() ^= std::byte{1};
			auto rejected = AEAD::Open(algorithm, key, nonce,
				stored.ciphertext.span(), stored.tag.span(), wrongAAD);
			ASSERT_FALSE(rejected);
			ASSERT_TRUE(*rejected.error() == AEAD::Error::AuthenticationFailed);
			ASSERT_TRUE(Equal(retained, message));
		}
	}
	RETURN_TEST(0);
}

int test_input_limits_without_allocating_gigabytes() {
	for (const auto algorithm : {AEAD::Algorithm::AES128GCM, AEAD::Algorithm::AES256GCM}) {
		const Password key = Secret(std::vector<std::byte>(
			algorithm == AEAD::Algorithm::AES128GCM ? 16 : 32));
		auto atLimit = Helpers::ValidateAEAD(algorithm, key, AEAD::NonceSize,
			AEAD::MaxMessageSize, AEAD::MaxAADSize);
		ASSERT_TRUE(atLimit);
		for (const auto size : {AEAD::MaxMessageSize + 1, std::numeric_limits<std::uint64_t>::max()}) {
			auto overLimit = Helpers::ValidateAEAD(algorithm, key, AEAD::NonceSize, size, 0);
			ASSERT_FALSE(overLimit);
			ASSERT_TRUE(*overLimit.error() == AEAD::Error::InputTooLong);
		}
		for (const auto size : {AEAD::MaxAADSize + 1, std::numeric_limits<std::uint64_t>::max()}) {
			auto overLimit = Helpers::ValidateAEAD(algorithm, key, AEAD::NonceSize, 0, size);
			ASSERT_FALSE(overLimit);
			ASSERT_TRUE(*overLimit.error() == AEAD::Error::InputTooLong);
		}
	}
	RETURN_TEST(0);
}

int main() {
	int result = 0;
	result += test_nist_known_answers();
	result += test_all_authentication_surfaces();
	result += test_validation_errors();
	result += test_empty_and_binary_inputs_and_lifecycle();
	result += test_input_limits_without_allocating_gigabytes();
	if (result == 0)
		std::cout << "All AEAD tests passed!" << std::endl;
	return result;
}
