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

#include "helpers.hxx"

#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/crypter/asymmetric/generic.hxx>
#include <StormByte/test_handlers.h>

#include <algorithm>
#include <chrono>
#include <string>
#include <thread>

namespace StormByte::Crypto::Test::StreamError {
	enum class Scenario {
		InitialError, BufferedError, DelayedError, CleanEmpty, CleanData
	};

	constexpr Scenario Scenarios[] = {
		Scenario::InitialError, Scenario::BufferedError, Scenario::DelayedError,
		Scenario::CleanEmpty, Scenario::CleanData
	};

	template<typename Predicate>
	bool WaitFor(Predicate ready) {
		const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
		while (!ready()) {
			if (std::chrono::steady_clock::now() >= deadline)
				return false;
			std::this_thread::yield();
		}
		return true;
	}

	inline bool Drain(Buffer::Consumer output, Safe::Binary& bytes) {
		const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
		while (!output.EoF()) {
			if (output.HasError())
				return true;
			if (std::chrono::steady_clock::now() >= deadline)
				return false;
			const auto available = output.Available();
			if (available == ByteSize{0}) {
				std::this_thread::yield();
				continue;
			}
			if (!output.Extract(available, bytes))
				return output.HasError();
		}
		return true;
	}

	template<typename Transform, typename Verify>
	int CheckStream(Transform transform, Verify verify, const Safe::Binary& data,
		ReadMode mode, Scenario scenario, bool digest) {
		Buffer::Producer input;
		const bool has_data = scenario != Scenario::InitialError;
		if (has_data)
			ASSERT_TRUE(input.Write(data.span()));
		if (scenario == Scenario::InitialError || scenario == Scenario::BufferedError)
			input.SetError();
		else if (scenario != Scenario::DelayedError)
			input.Close();

		auto observer = input.Consumer();
		auto output = transform(input.Consumer(), mode);
		if (scenario == Scenario::DelayedError) {
			const bool consumed = WaitFor([&] { return observer.Available() == ByteSize{0}; });
			input.SetError();
			ASSERT_TRUE(consumed);
		}

		Safe::Binary bytes;
		ASSERT_TRUE(Drain(output, bytes));
		const bool error = scenario == Scenario::InitialError
			|| scenario == Scenario::BufferedError || scenario == Scenario::DelayedError;
		ASSERT_EQUAL(output.HasError(), error);
		ASSERT_FALSE(output.IsWritable());
		if (error) {
			if (digest || scenario == Scenario::InitialError || scenario == Scenario::BufferedError) {
				ASSERT_TRUE(bytes.empty());
				ASSERT_EQUAL(output.Available(), ByteSize{0});
			}
		} else {
			ASSERT_TRUE(verify(bytes));
		}
		RETURN_TEST(0);
	}

	template<typename HasherType>
	int CheckHasher() {
		HasherType hasher;
		int result = 0;
		for (const auto mode : { ReadMode::Copy, ReadMode::Move }) {
			for (const auto scenario : Scenarios) {
				const Safe::Binary data(scenario == Scenario::CleanEmpty ? "" : std::string(8192, 'h'));
				Buffer::FIFO expected;
				ASSERT_TRUE(hasher.Hash(data.span(), expected));
				result += CheckStream(
					[&](Buffer::Consumer input, ReadMode read_mode) {
						return hasher.Hash(input, read_mode);
					},
					[&](const Safe::Binary& bytes) { return bytes == expected.Data(); },
					data, mode, scenario, true);
			}
		}
		return result;
	}

	template<typename Cipher, typename Encrypt>
	int CheckCipher(Cipher& cipher, Encrypt encrypt, std::size_t size) {
		int result = 0;
		for (const auto mode : { ReadMode::Copy, ReadMode::Move }) {
			for (const auto scenario : Scenarios) {
				const Safe::Binary plain(scenario == Scenario::CleanEmpty ? "" : std::string(size, 'c'));
				Buffer::Producer source;
				ASSERT_TRUE(source.Write(plain.span()));
				source.Close();
				auto encrypted = encrypt(source.Consumer(), mode);
				Safe::Binary ciphertext;
				ASSERT_TRUE(Drain(encrypted, ciphertext));
				ASSERT_FALSE(encrypted.HasError());

				for (const bool decrypt : { false, true }) {
					result += CheckStream(
						[&](Buffer::Consumer input, ReadMode read_mode) {
							return decrypt ? cipher.Decrypt(input, read_mode) : encrypt(input, read_mode);
						},
						[&](const Safe::Binary& bytes) {
							if (decrypt)
								return bytes == plain;
							Buffer::Producer check;
							if (!check.Write(bytes.span()))
								return false;
							check.Close();
							auto decrypted = cipher.Decrypt(check.Consumer(), mode);
							Safe::Binary recovered;
							return Drain(decrypted, recovered)
								&& !decrypted.HasError() && recovered == plain;
						},
						decrypt ? ciphertext : plain, mode, scenario, false);
				}
			}
		}
		return result;
	}

	template<typename Cipher>
	int CheckSymmetric() {
		Cipher cipher(Secure::Password("StreamErrorPassword123!"));
		return CheckCipher(cipher, [&](Buffer::Consumer input, ReadMode mode) {
			return cipher.Encrypt(input, mode);
		}, 8192);
	}

	template<typename Cipher, typename Encrypt>
	int CheckAsymmetric(Cipher& cipher, Encrypt encrypt) {
		int result = 0;
		for (const auto strategy : {
				Crypter::Asymmetric::Strategy::Native,
				Crypter::Asymmetric::Strategy::Hybrid}) {
			result += CheckCipher(cipher,
				[&](Buffer::Consumer input, ReadMode mode) {
					return encrypt(input, strategy, mode);
				}, 128);
		}
		return result;
	}
}
