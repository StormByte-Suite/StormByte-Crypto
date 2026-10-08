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

#include <StormByte/buffer/producer.hxx>
#include <StormByte/crypto/engine/crypter/details.hxx>
#include <StormByte/crypto/helpers/callback.hxx>
#include <StormByte/safe/thread.hxx>

#include <utility>

using namespace StormByte;
using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using StormByte::Buffer::WriteOnly;
using StormByte::Crypto::ReadMode;

namespace {
	constexpr ByteSize ChunkSize{4096};
}

bool StormByte::Crypto::Engine::Crypter::ProcessSpan(
	std::span<const std::byte> data,
	WriteOnly& output,
	Safe::Unique<Ops> ops) noexcept {
	if (!ops)
		return false;
	try {
		Safe::Binary chunk;
		if (!ops->WriteHeader(chunk))
			return false;
		if (!chunk.empty() && !output.Write(std::move(chunk)))
			return false;
		chunk.clear();
		if (!ops->ReadHeader(data))
			return false;
		if (!ops->Process(data, chunk))
			return false;
		if (!chunk.empty() && !output.Write(std::move(chunk)))
			return false;
		chunk.clear();
		if (!ops->Finalize(chunk))
			return false;
		if (!chunk.empty() && !output.Write(std::move(chunk)))
			return false;
		return true;
	} catch (...) {
		return false;
	}
}

Consumer StormByte::Crypto::Engine::Crypter::Stream(
	Consumer consumer,
	ReadMode mode,
	Safe::Unique<Ops> ops) noexcept {
	Producer producer;
	if (!ops) {
		producer.SetError();
		return producer.Consumer();
	}

	try {
		auto owner = Safe::Shared<Safe::Unique<Ops>>::MakePointer<Safe::Unique<Ops>>(std::move(ops));
		auto callback = Crypto::Helpers::MakeCallback<>([consumer = std::move(consumer), producer, owner = std::move(owner), mode]() mutable {
			try {
				auto& engine = *owner;
				Safe::Binary outChunk;
				if (!engine->WriteHeader(outChunk)) {
					producer.SetError();
					return;
				}

				if (!outChunk.empty() && !producer.Write(std::move(outChunk))) {
					producer.SetError();
					return;
				}

				outChunk.clear();
				if (!engine->ReadHeader(consumer)) {
					producer.SetError();
					return;
				}

				while (!consumer.EoF()) {
					const ByteSize available = consumer.Available();
					if (available == ByteSize{0}) {
						Safe::this_thread::yield();
						continue;
					}

					const ByteSize toRead = (available < ChunkSize) ? available : ChunkSize;
					Safe::Binary data;
					const bool ok = (mode == ReadMode::Copy)
						? consumer.Read(toRead, data)
						: consumer.Extract(toRead, data);
					if (!ok) {
						producer.SetError();
						return;
					}

					if (!engine->Process(std::span<const std::byte>(data.data(), static_cast<std::size_t>(data.size())), outChunk)) {
						producer.SetError();
						return;
					}

					if (!outChunk.empty() && !producer.Write(std::move(outChunk))) {
						producer.SetError();
						return;
					}

					outChunk.clear();
				}

				if (!engine->Finalize(outChunk)) {
					producer.SetError();
					return;
				}

				if (!outChunk.empty() && !producer.Write(std::move(outChunk))) {
					producer.SetError();
					return;
				}

				producer.Close();
			} catch (...) {
				producer.SetError();
			}
		});
		Safe::Thread([callback = std::move(callback), producer]() mutable {
			try {
				if (callback.Call() != Safe::Status::Success)
					producer.SetError();
			} catch (...) {
				producer.SetError();
			}
		}).detach();
	} catch (...) {
		producer.SetError();
	}
	return producer.Consumer();
}
