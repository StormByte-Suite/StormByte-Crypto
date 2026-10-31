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

#include <StormByte/crypto/hkdf.hxx>
#include <StormByte/test_handlers.h>

#include <array>
#include <cstddef>
#include <iostream>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;

namespace {
	std::vector<std::byte> FromHex(std::string_view hex) {
		std::vector<std::byte> result;
		result.reserve(hex.size() / 2);
		for (std::size_t index = 0; index < hex.size(); index += 2) {
			const auto digit = [](char value) -> unsigned int {
				if (value >= '0' && value <= '9')
					return static_cast<unsigned int>(value - '0');
				if (value >= 'a' && value <= 'f')
					return static_cast<unsigned int>(value - 'a' + 10);
				return static_cast<unsigned int>(value - 'A' + 10);
			};
			result.push_back(static_cast<std::byte>((digit(hex[index]) << 4) | digit(hex[index + 1])));
		}
		return result;
	}

	Password Secret(std::string_view hex) {
		const auto bytes = FromHex(hex);
		return Password(bytes.data(), StormByte::ByteSize{bytes.size()});
	}

	std::array<std::byte, 22> Rfc5869Input() {
		std::array<std::byte, 22> result{};
		result.fill(std::byte{0x0b});
		return result;
	}
}

int test_rfc5869_sha256_extract_and_expand() {
	const auto ikmBytes = Rfc5869Input();
	const Password ikm(ikmBytes.data(), StormByte::ByteSize{ikmBytes.size()});
	const auto salt = FromHex("000102030405060708090a0b0c");
	const auto info = FromHex("f0f1f2f3f4f5f6f7f8f9");
	auto prk = HKDF::Extract(HKDF::Algorithm::SHA256, salt, ikm);
	ASSERT_TRUE(prk);
	ASSERT_TRUE(*prk == Secret("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));

	auto okm = HKDF::Expand(HKDF::Algorithm::SHA256, *prk, info, 42);
	ASSERT_TRUE(okm);
	ASSERT_EQUAL(StormByte::ByteSize{42}, okm->Size());
	ASSERT_TRUE(*okm == Secret("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
	RETURN_TEST(0);
}

int test_rfc5869_sha256_long_output() {
	std::array<std::byte, 80> ikmBytes{};
	std::array<std::byte, 80> salt{};
	std::array<std::byte, 80> info{};
	for (std::size_t index = 0; index < ikmBytes.size(); ++index) {
		ikmBytes[index] = static_cast<std::byte>(index);
		salt[index] = static_cast<std::byte>(0x60 + index);
		info[index] = static_cast<std::byte>(0xb0 + index);
	}
	const Password ikm(ikmBytes.data(), StormByte::ByteSize{ikmBytes.size()});
	auto prk = HKDF::Extract(HKDF::Algorithm::SHA256, salt, ikm);
	ASSERT_TRUE(prk);
	ASSERT_TRUE(*prk == Secret("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"));
	auto okm = HKDF::Expand(HKDF::Algorithm::SHA256, *prk, info, 82);
	ASSERT_TRUE(okm);
	ASSERT_TRUE(*okm == Secret(
		"b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
		"59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
		"cc30c58179ec3e87c14c01d5c1f3434f1d87"
	));
	RETURN_TEST(0);
}

int test_sha384_known_answer_vectors() {
	// RFC 5869 A.1 inputs; SHA-384 expectations independently checked with OpenSSL 3.6.5 EVP_KDF/HMAC and Python hashlib/hmac.
	const auto ikmBytes = Rfc5869Input();
	const Password ikm(ikmBytes.data(), StormByte::ByteSize{ikmBytes.size()});
	const auto salt = FromHex("000102030405060708090a0b0c");
	const auto info = FromHex("f0f1f2f3f4f5f6f7f8f9");
	auto prk = HKDF::Extract(HKDF::Algorithm::SHA384, salt, ikm);
	ASSERT_TRUE(prk);
	ASSERT_TRUE(*prk == Secret(
		"704b39990779ce1dc548052c7dc39f303570dd13fb39f7acc564680bef80e8de"
		"c70ee9a7e1f3e293ef68eceb072a5ade"
	));
	auto okm = HKDF::Expand(HKDF::Algorithm::SHA384, *prk, info, 42);
	ASSERT_TRUE(okm);
	ASSERT_TRUE(*okm == Secret(
		"9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f7"
		"48b6457763e4f0204fc5"
	));

	std::array<std::byte, 80> longIkm{};
	std::array<std::byte, 80> longSalt{};
	std::array<std::byte, 80> longInfo{};
	for (std::size_t index = 0; index < longIkm.size(); ++index) {
		longIkm[index] = static_cast<std::byte>(index);
		longSalt[index] = static_cast<std::byte>(0x60 + index);
		longInfo[index] = static_cast<std::byte>(0xb0 + index);
	}
	const Password longInput(longIkm.data(), StormByte::ByteSize{longIkm.size()});
	auto longPrk = HKDF::Extract(HKDF::Algorithm::SHA384, longSalt, longInput);
	ASSERT_TRUE(longPrk);
	ASSERT_TRUE(*longPrk == Secret(
		"b319f6831dff9314efb643baa29263b30e4a8d779fe31e9c901efd7de737c85"
		"b62e676d4dc87b0895c6a7dc97b52cebb"
	));
	auto longOutput = HKDF::Expand(HKDF::Algorithm::SHA384, *longPrk, longInfo, 82);
	ASSERT_TRUE(longOutput);
	ASSERT_TRUE(*longOutput == Secret(
		"484ca052b8cc724fd1c4ec64d57b4e818c7e25a8e0f4569ed72a6a05fe0649ee"
		"bf69f8d5c832856bf4e4fbc17967d54975324a94987f7f41835817d8994fdbd6"
		"f4c09c5500dca24a56222fea53d8967a8b2e"
	));
	RETURN_TEST(0);
}

int test_binary_inputs_long_output_for_both_hashes() {
	const auto ikmBytes = FromHex("0001ff0042");
	const auto salt = FromHex("a50000ff");
	const auto info = FromHex("000102ff00");
	const Password ikm(ikmBytes.data(), StormByte::ByteSize{ikmBytes.size()});
	auto sha256Prk = HKDF::Extract(HKDF::Algorithm::SHA256, salt, ikm);
	auto sha384Prk = HKDF::Extract(HKDF::Algorithm::SHA384, salt, ikm);
	ASSERT_TRUE(sha256Prk);
	ASSERT_TRUE(sha384Prk);
	ASSERT_TRUE(*sha256Prk == Secret("3fad76ba3dc9dbfc922269487fb32edba7f126815e82c0f940090a37c41fb39e"));
	ASSERT_TRUE(*sha384Prk == Secret(
		"c43beabd9ce9496352c6dc0f75b2a3058cec306783d28d67699967b51c4dcaf5"
		"470e4fd616d59811554c06b449e2304d"
	));
	auto sha256Output = HKDF::Expand(HKDF::Algorithm::SHA256, *sha256Prk, info, 70);
	auto sha384Output = HKDF::Expand(HKDF::Algorithm::SHA384, *sha384Prk, info, 70);
	ASSERT_TRUE(sha256Output);
	ASSERT_TRUE(sha384Output);
	ASSERT_TRUE(*sha256Output == Secret(
		"eb0ee556a55bec7d852e8f851a0da852cf5755d69dbf41975c082a53b00f066b"
		"312cf9c76b176ad9a127027d9b76088dfe5be16296e7a26f12acac733da23f8843d9f217e781"
	));
	ASSERT_TRUE(*sha384Output == Secret(
		"4dc86f8d466a92db4a9b55be3c5bbe18660ec0da7c257534635aa4eebb7a69ed"
		"8bbeff7e50f29aa325e5c6c1a068a1b1c98c61bb5d850769bab2d16df2cd489d18d83d1928a6"
	));
	ASSERT_FALSE(*sha256Output == *sha384Output);
	RETURN_TEST(0);
}

int test_empty_inputs_use_zero_salt_and_zero_output_is_valid() {
	const Password ikm;
	const std::span<const std::byte> empty;
	auto sha256Prk = HKDF::Extract(HKDF::Algorithm::SHA256, empty, ikm);
	auto sha384Prk = HKDF::Extract(HKDF::Algorithm::SHA384, empty, ikm);
	ASSERT_TRUE(sha256Prk);
	ASSERT_TRUE(sha384Prk);
	ASSERT_TRUE(*sha256Prk == Secret("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"));
	ASSERT_TRUE(*sha384Prk == Secret(
		"6c1f2ee938fad2e24bd91298474382ca218c75db3d83e114b3d4367776d14d35"
		"51289e75e8209cd4b792302840234adc"
	));

	auto sha256Zero = HKDF::Expand(HKDF::Algorithm::SHA256, *sha256Prk, empty, 0);
	auto sha384Zero = HKDF::Expand(HKDF::Algorithm::SHA384, *sha384Prk, empty, 0);
	ASSERT_TRUE(sha256Zero);
	ASSERT_TRUE(sha384Zero);
	ASSERT_TRUE(sha256Zero->Empty());
	ASSERT_TRUE(sha384Zero->Empty());
	auto sha256Expanded = HKDF::Expand(HKDF::Algorithm::SHA256, *sha256Prk, empty, 64);
	auto sha384Expanded = HKDF::Expand(HKDF::Algorithm::SHA384, *sha384Prk, empty, 96);
	ASSERT_TRUE(sha256Expanded);
	ASSERT_TRUE(sha384Expanded);
	ASSERT_TRUE(*sha256Expanded == Secret(
		"eb70f01dede9afafa449eee1b1286504e1f62388b3f7dd4f956697b0e828fe18"
		"1e59c2ec0fe6e7e7ac2613b6ab65342a83379969da234240cded3777914db907"
	));
	ASSERT_TRUE(*sha384Expanded == Secret(
		"470cc65387ca4a10c7a68a3b5148c8e513daa63101000739c4c6659b86118884"
		"13b4617b1e75cf30370c2865d6d5eb499931fffca53cb44bc9bf8dfd7c2e9f12"
		"fe8c3aed4eee08b5cb076a526973f166c5a153fcb6df17d31d95928f0ddfbb9d"
	));
	RETURN_TEST(0);
}

int test_length_boundaries_and_errors() {
	const auto sha256 = HKDF::Algorithm::SHA256;
	const auto sha384 = HKDF::Algorithm::SHA384;
	const auto empty = std::span<const std::byte>{};
	const auto sha256Prk = Secret("0000000000000000000000000000000000000000000000000000000000000000");
	const auto sha384Prk = Secret(
		"0000000000000000000000000000000000000000000000000000000000000000"
		"000000000000000000000000000000000000000000000000"
	);

	auto max256 = HKDF::Expand(sha256, sha256Prk, empty, 255 * 32);
	auto max384 = HKDF::Expand(sha384, sha384Prk, empty, 255 * 48);
	ASSERT_TRUE(max256);
	ASSERT_TRUE(max384);
	ASSERT_EQUAL(StormByte::ByteSize{255 * 32}, max256->Size());
	ASSERT_EQUAL(StormByte::ByteSize{255 * 48}, max384->Size());
	auto tooLong256 = HKDF::Expand(sha256, sha256Prk, empty, 255 * 32 + 1);
	auto tooLong384 = HKDF::Expand(sha384, sha384Prk, empty, 255 * 48 + 1);
	ASSERT_FALSE(tooLong256);
	ASSERT_FALSE(tooLong384);
	ASSERT_EQUAL(HKDF::Error::OutputTooLong, *tooLong256.error());
	ASSERT_EQUAL(HKDF::Error::OutputTooLong, *tooLong384.error());

	const std::vector<std::byte> short256Bytes(31, std::byte{0});
	const std::vector<std::byte> short384Bytes(47, std::byte{0});
	const Password short256Key(short256Bytes.data(), StormByte::ByteSize{short256Bytes.size()});
	const Password short384Key(short384Bytes.data(), StormByte::ByteSize{short384Bytes.size()});
	auto short256 = HKDF::Expand(sha256, short256Key, empty, 1);
	auto short384 = HKDF::Expand(sha384, short384Key, empty, 1);
	ASSERT_FALSE(short256);
	ASSERT_FALSE(short384);
	ASSERT_EQUAL(HKDF::Error::InvalidPseudorandomKeySize, *short256.error());
	ASSERT_EQUAL(HKDF::Error::InvalidPseudorandomKeySize, *short384.error());

	const auto invalid = static_cast<HKDF::Algorithm>(255);
	auto badExtract = HKDF::Extract(invalid, empty, Password{});
	auto badExpand = HKDF::Expand(invalid, sha256Prk, empty, 1);
	ASSERT_FALSE(badExtract);
	ASSERT_FALSE(badExpand);
	ASSERT_EQUAL(HKDF::Error::UnsupportedAlgorithm, *badExtract.error());
	ASSERT_EQUAL(HKDF::Error::UnsupportedAlgorithm, *badExpand.error());
	RETURN_TEST(0);
}

int test_secure_result_lifecycle() {
	Password retained;
	{
		const auto ikmBytes = Rfc5869Input();
		const Password ikm(ikmBytes.data(), StormByte::ByteSize{ikmBytes.size()});
		const auto salt = FromHex("000102030405060708090a0b0c");
		auto extracted = HKDF::Extract(HKDF::Algorithm::SHA256, salt, ikm);
		ASSERT_TRUE(extracted);
		Password copied = *extracted;
		Password moved = std::move(copied);
		auto expanded = HKDF::Expand(HKDF::Algorithm::SHA256, moved, {}, 42);
		ASSERT_TRUE(expanded);
		retained = std::move(*expanded);
	}
	ASSERT_EQUAL(StormByte::ByteSize{42}, retained.Size());
	ASSERT_TRUE(retained == Secret(
		"b2a3d45126d31fb6828ef00d76c6d54e9c2bd4785e49c6ad86e327d89d0de940"
		"8eeda1cbef2b03f30e05"
	));
	RETURN_TEST(0);
}

int main() {
	int result = 0;
	result += test_rfc5869_sha256_extract_and_expand();
	result += test_rfc5869_sha256_long_output();
	result += test_sha384_known_answer_vectors();
	result += test_binary_inputs_long_output_for_both_hashes();
	result += test_empty_inputs_use_zero_salt_and_zero_output_is_valid();
	result += test_length_boundaries_and_errors();
	result += test_secure_result_lifecycle();

	if (result == 0)
		std::cout << "All HKDF tests passed!" << std::endl;
	else
		std::cout << result << " HKDF tests failed." << std::endl;
	return result;
}
