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
#include <StormByte/test_handlers.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <span>
#include <string>
#include <string_view>

using namespace StormByte::Crypto;
using StormByte::Crypto::Secure::Password;

namespace {
	std::span<const std::byte> Bytes(std::string_view value) {
		return {reinterpret_cast<const std::byte*>(value.data()), value.size()};
	}

	std::string Hex(const StormByte::Safe::Binary& bytes) {
		std::ostringstream result;
		result << std::hex << std::setfill('0');
		for (const std::byte value: bytes)
			result << std::setw(2) << std::to_integer<unsigned int>(value);
		return result.str();
	}

	bool MatchesHex(const StormByte::Safe::Binary& bytes, std::string_view expected) {
		return Hex(bytes) == expected;
	}

	Password RepeatedKey(std::byte value, std::size_t size) {
		StormByte::Safe::Binary key(StormByte::ByteSize{size}, value);
		return Password(key.data(), key.size());
	}
}

int test_rfc4231_sha256_vectors() {
	const Password case1Key = RepeatedKey(std::byte{0x0b}, 20);
	auto case1 = HMAC::Compute(HMAC::Algorithm::SHA256, case1Key, Bytes("Hi There"));
	ASSERT_TRUE(case1);
	ASSERT_TRUE(MatchesHex(*case1, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));

	const Password case2Key("Jefe");
	auto case2 = HMAC::Compute(HMAC::Algorithm::SHA256, case2Key, Bytes("what do ya want for nothing?"));
	ASSERT_TRUE(case2);
	ASSERT_TRUE(MatchesHex(*case2, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));

	const Password longKey = RepeatedKey(std::byte{0xaa}, 131);
	auto case6 = HMAC::Compute(
		HMAC::Algorithm::SHA256,
		longKey,
		Bytes("Test Using Larger Than Block-Size Key - Hash Key First")
	);
	ASSERT_TRUE(case6);
	ASSERT_TRUE(MatchesHex(*case6, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
	RETURN_TEST(0);
}

int test_rfc4231_sha384_vectors() {
	const Password case1Key = RepeatedKey(std::byte{0x0b}, 20);
	auto case1 = HMAC::Compute(HMAC::Algorithm::SHA384, case1Key, Bytes("Hi There"));
	ASSERT_TRUE(case1);
	ASSERT_TRUE(MatchesHex(*case1, "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"));

	const Password case2Key("Jefe");
	auto case2 = HMAC::Compute(HMAC::Algorithm::SHA384, case2Key, Bytes("what do ya want for nothing?"));
	ASSERT_TRUE(case2);
	ASSERT_TRUE(MatchesHex(*case2, "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"));

	const Password longKey = RepeatedKey(std::byte{0xaa}, 131);
	auto case6 = HMAC::Compute(
		HMAC::Algorithm::SHA384,
		longKey,
		Bytes("Test Using Larger Than Block-Size Key - Hash Key First")
	);
	ASSERT_TRUE(case6);
	ASSERT_TRUE(MatchesHex(*case6, "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"));
	RETURN_TEST(0);
}

int test_binary_key_and_message() {
	const std::array<std::byte, 5> keyBytes{
		std::byte{0x00}, std::byte{'k'}, std::byte{'e'}, std::byte{'y'}, std::byte{0xff}
	};
	const std::array<std::byte, 5> message{
		std::byte{0x00}, std::byte{'m'}, std::byte{'s'}, std::byte{'g'}, std::byte{0xff}
	};
	const Password key(keyBytes.data(), StormByte::ByteSize{keyBytes.size()});
	auto result = HMAC::Compute(HMAC::Algorithm::SHA256, key, message);
	ASSERT_TRUE(result);
	ASSERT_TRUE(MatchesHex(*result, "78a0fc4c52d12abe9a506acc70c662eb9faaab8386e6b249c482d30ebc67bf2e"));
	RETURN_TEST(0);
}

int test_empty_key_and_message() {
	const Password key;
	auto sha256 = HMAC::Compute(HMAC::Algorithm::SHA256, key, std::span<const std::byte>{});
	ASSERT_TRUE(sha256);
	ASSERT_TRUE(MatchesHex(*sha256, "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"));
	auto sha384 = HMAC::Compute(HMAC::Algorithm::SHA384, key, std::span<const std::byte>{});
	ASSERT_TRUE(sha384);
	ASSERT_TRUE(MatchesHex(*sha384, "6c1f2ee938fad2e24bd91298474382ca218c75db3d83e114b3d4367776d14d3551289e75e8209cd4b792302840234adc"));
	RETURN_TEST(0);
}

int test_verify_correct_and_tampered_tag() {
	const Password key("Jefe");
	auto tag = HMAC::Compute(HMAC::Algorithm::SHA256, key, Bytes("what do ya want for nothing?"));
	ASSERT_TRUE(tag);
	auto verified = HMAC::Verify(HMAC::Algorithm::SHA256, key, Bytes("what do ya want for nothing?"), *tag);
	ASSERT_TRUE(verified);
	ASSERT_TRUE(*verified);

	const Password wrongKey("not the key");
	auto wrongKeyResult = HMAC::Verify(HMAC::Algorithm::SHA256, wrongKey, Bytes("what do ya want for nothing?"), *tag);
	ASSERT_TRUE(wrongKeyResult);
	ASSERT_FALSE(*wrongKeyResult);

	(*tag)[StormByte::ByteSize{0}] ^= std::byte{0x01};
	auto tampered = HMAC::Verify(HMAC::Algorithm::SHA256, key, Bytes("what do ya want for nothing?"), *tag);
	ASSERT_TRUE(tampered);
	ASSERT_FALSE(*tampered);
	auto wrongMessage = HMAC::Verify(HMAC::Algorithm::SHA256, key, Bytes("different message"), *tag);
	ASSERT_TRUE(wrongMessage);
	ASSERT_FALSE(*wrongMessage);

	auto sha384Tag = HMAC::Compute(HMAC::Algorithm::SHA384, key, Bytes("verification"));
	ASSERT_TRUE(sha384Tag);
	auto sha384Verified = HMAC::Verify(HMAC::Algorithm::SHA384, key, Bytes("verification"), *sha384Tag);
	ASSERT_TRUE(sha384Verified);
	ASSERT_TRUE(*sha384Verified);
	RETURN_TEST(0);
}

int test_rejects_non_full_tags() {
	const Password key("verify");
	auto fullTag = HMAC::Compute(HMAC::Algorithm::SHA256, key, Bytes("payload"));
	ASSERT_TRUE(fullTag);
	const std::span<const std::byte> fullSpan{fullTag->data(), static_cast<std::size_t>(fullTag->size())};
	const std::span<const std::byte> truncated{fullTag->data(), 31};
	auto shortTag = HMAC::Verify(HMAC::Algorithm::SHA256, key, Bytes("payload"), truncated);
	ASSERT_FALSE(shortTag);
	ASSERT_EQUAL(HMAC::Error::InvalidTagSize, *shortTag.error());

	std::array<std::byte, 33> oversized{};
	std::copy(fullSpan.begin(), fullSpan.end(), oversized.begin());
	auto longTag = HMAC::Verify(HMAC::Algorithm::SHA256, key, Bytes("payload"), oversized);
	ASSERT_FALSE(longTag);
	ASSERT_EQUAL(HMAC::Error::InvalidTagSize, *longTag.error());
	RETURN_TEST(0);
}

int test_typed_unsupported_algorithm_error() {
	const Password key("key");
	const auto algorithm = static_cast<HMAC::Algorithm>(255);
	auto result = HMAC::Compute(algorithm, key, Bytes("message"));
	ASSERT_FALSE(result);
	ASSERT_EQUAL(HMAC::Error::UnsupportedAlgorithm, *result.error());
	auto verification = HMAC::Verify(algorithm, key, Bytes("message"), std::span<const std::byte>{});
	ASSERT_FALSE(verification);
	ASSERT_EQUAL(HMAC::Error::UnsupportedAlgorithm, *verification.error());
	RETURN_TEST(0);
}

int test_expected_result_lifecycle() {
	StormByte::Safe::Binary retained;
	{
		const Password key("lifecycle");
		auto result = HMAC::Compute(HMAC::Algorithm::SHA384, key, Bytes("retained result"));
		ASSERT_TRUE(result);
		retained = *result;
	}
	ASSERT_TRUE(MatchesHex(retained, "cfbb1ef284f58dd9889339bbfde040f9b2344bd38c09ab8991a057681881082180be0414b35c9019de708e8c920bcd4d"));

	StormByte::Safe::Shared<HMAC::Error> retainedError;
	{
		auto invalid = HMAC::Compute(static_cast<HMAC::Algorithm>(255), Password("key"), Bytes("message"));
		ASSERT_FALSE(invalid);
		retainedError = invalid.error();
	}
	ASSERT_TRUE(retainedError);
	ASSERT_EQUAL(HMAC::Error::UnsupportedAlgorithm, *retainedError);
	RETURN_TEST(0);
}

int main() {
	int result = 0;
	result += test_rfc4231_sha256_vectors();
	result += test_rfc4231_sha384_vectors();
	result += test_binary_key_and_message();
	result += test_empty_key_and_message();
	result += test_verify_correct_and_tampered_tag();
	result += test_rejects_non_full_tags();
	result += test_typed_unsupported_algorithm_error();
	result += test_expected_result_lifecycle();

	if (result == 0)
		std::cout << "All HMAC tests passed!" << std::endl;
	else
		std::cout << result << " HMAC tests failed." << std::endl;
	return result;
}
