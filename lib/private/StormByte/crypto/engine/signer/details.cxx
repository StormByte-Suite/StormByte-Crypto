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
#include <StormByte/crypto/engine/signer/details.hxx>
#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/safe/function.hxx>
#include <StormByte/safe/thread.hxx>

#include <exception>
#include <memory>
#include <utility>

using namespace StormByte;
using namespace StormByte::Crypto::Engine::Signer;
using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using StormByte::Buffer::WriteOnly;
using StormByte::Crypto::ReadMode;

namespace {
	/**
	 * @brief Maximum borrowed message chunk copied into Safe storage.
	 */
	constexpr ByteSize ChunkSize{4096};

	/**
	 * @struct WipedChunk
	 * @brief Safe message bytes wiped before their allocation is released.
	 */
	struct WipedChunk {
		/**
		 * @brief Construct an empty chunk.
		 */
		WipedChunk() = default;

		/**
		 * @brief Chunks cannot be copied.
		 * @param other Source chunk.
		 */
		WipedChunk(const WipedChunk& other) = delete;

		/**
		 * @brief Chunks cannot be moved.
		 * @param other Source chunk.
		 */
		WipedChunk(WipedChunk&& other) = delete;

		/**
		 * @brief Wipe bytes before destroying Safe storage.
		 */
		~WipedChunk() { Crypto::Helpers::SecureWipe(m_data); }

		/**
		 * @brief Chunks cannot be copy-assigned.
		 * @param other Source chunk.
		 * @return This chunk.
		 */
		WipedChunk& operator=(const WipedChunk& other) = delete;

		/**
		 * @brief Chunks cannot be move-assigned.
		 * @param other Source chunk.
		 * @return This chunk.
		 */
		WipedChunk& operator=(WipedChunk&& other) = delete;

		Safe::Binary m_data;		///< Message bytes consumed during one update.
	};

	/**
	 * @struct SignContext
	 * @brief Shared operation state retained by independently allocated callback contexts.
	 */
	struct SignContext {
		/**
		 * @brief Retain the input, output and concrete backend for one execution.
		 * @param consumer Input consumer.
		 * @param producer Signature producer.
		 * @param box Private signing backend.
		 * @param mode Input read mode.
		 */
		SignContext(Consumer consumer, Producer producer, Safe::Unique<SignBox> box, ReadMode mode):
			m_consumer(std::move(consumer)), m_producer(std::move(producer)), m_box(std::move(box)), m_mode(mode) {}

		/**
		 * @brief Operation state cannot be copied.
		 * @param other Source operation.
		 */
		SignContext(const SignContext& other) = delete;

		/**
		 * @brief Operation state cannot be moved.
		 * @param other Source operation.
		 */
		SignContext(SignContext&& other) = delete;

		/**
		 * @brief Release input, output and backend in Crypto.
		 */
		~SignContext() = default;

		/**
		 * @brief Operation state cannot be copy-assigned.
		 * @param other Source operation.
		 * @return This operation.
		 */
		SignContext& operator=(const SignContext& other) = delete;

		/**
		 * @brief Operation state cannot be move-assigned.
		 * @param other Source operation.
		 * @return This operation.
		 */
		SignContext& operator=(SignContext&& other) = delete;

		Consumer m_consumer;		///< Input retained until the worker finishes.
		Producer m_producer;		///< Signature output and permanent error destination.
		Safe::Unique<SignBox> m_box;	///< Concrete Crypto-created backend.
		ReadMode m_mode;			///< Copy or extract input bytes.
	};

	/**
	 * @brief Safe owner stored inside each provider-owned callback context.
	 */
	using ContextOwner = Safe::Shared<SignContext>;

	/**
	 * @brief Allocate an independent context retaining the same one-shot operation.
	 * @param owner Operation owner to retain.
	 * @return Provider context released by ReleaseContext.
	 * @throws StormByte::AllocationError Context allocation failed.
	 */
	void* CreateContext(const ContextOwner& owner) {
		void* storage = Safe::Heap::Allocate(sizeof(ContextOwner));
		return std::construct_at(static_cast<ContextOwner*>(storage), owner);
	}

	/**
	 * @brief Clone the context owner, not the noncopyable signing operation.
	 * @param context Source context; copies must not be invoked concurrently.
	 * @return Independent context allocation, or null on allocation failure.
	 */
	void* CloneContext(const void* context) noexcept {
		try {
			return CreateContext(*static_cast<const ContextOwner*>(context));
		} catch (...) {
			return nullptr;
		}
	}

	/**
	 * @brief Destroy the context in Crypto and release its Base heap allocation.
	 * @param context Provider context.
	 */
	void ReleaseContext(void* context) noexcept {
		std::destroy_at(static_cast<ContextOwner*>(context));
		Safe::Heap::Free(context);
	}

	/**
	 * @brief Execute a signing operation and publish a permanent error on failure.
	 * @param context Provider context retaining the operation.
	 * @return Success after closing output, or Failure after an input or signing error.
	 */
	Safe::Status InvokeContext(void* context) noexcept {
		auto& operation = **static_cast<ContextOwner*>(context);
		try {
			while (!operation.m_consumer.EoF()) {
				if (!operation.m_producer.IsWritable() || operation.m_consumer.HasError()) {
					operation.m_producer.SetError();
					return Safe::Status::Failure;
				}
				const ByteSize available = operation.m_consumer.Available();
				if (available == ByteSize{0}) {
					Safe::this_thread::yield();
					continue;
				}
				const ByteSize toRead = (available < ChunkSize) ? available : ChunkSize;
				WipedChunk chunk;
				const bool read = (operation.m_mode == ReadMode::Copy)
					? operation.m_consumer.Read(toRead, chunk.m_data)
					: operation.m_consumer.Extract(toRead, chunk.m_data);
				if (!read || !operation.m_box->Update(std::span<const std::byte>(chunk.m_data.data(), static_cast<std::size_t>(chunk.m_data.size())))) {
					operation.m_producer.SetError();
					return Safe::Status::Failure;
				}
			}
			Safe::Binary signature;
			if (operation.m_consumer.HasError() || !operation.m_box->Finalize(signature) || !operation.m_producer.Write(std::move(signature))) {
				operation.m_producer.SetError();
				return Safe::Status::Failure;
			}
			operation.m_producer.Close();
			return Safe::Status::Success;
		} catch (...) {
			operation.m_producer.SetError();
			return Safe::Status::Failure;
		}
	}
}

bool StormByte::Crypto::Engine::Signer::SignSpan(
	std::span<const std::byte> data,
	WriteOnly& output,
	Safe::Unique<SignBox> box) noexcept {
	if (!box)
		return false;
	try {
		if (!box->Update(data))
			return false;
		Safe::Binary signature;
		if (!box->Finalize(signature))
			return false;
		return output.Write(std::move(signature));
	} catch (const StormByte::Exception&) {
		return false;
	} catch (...) {
		return false;
	}
}

Consumer StormByte::Crypto::Engine::Signer::SignStream(
	Consumer consumer,
	ReadMode mode,
	Safe::Unique<SignBox> box) noexcept {
	Producer producer;
	if (!box) {
		producer.SetError();
		return producer.Consumer();
	}

	try {
		auto owner = Safe::MakeShared<SignContext>(std::move(consumer), producer, std::move(box), mode);
		Safe::Function<void()> callback(CreateContext(owner), InvokeContext, CloneContext, ReleaseContext);
		Safe::Thread worker([callback = std::move(callback), producer]() mutable noexcept {
			try {
				if (callback.Call() != Safe::Status::Success)
					producer.SetError();
			} catch (...) {
				producer.SetError();
			}
		});
		try {
			worker.detach();
		} catch (...) {
			producer.SetError();
			if (worker.joinable()) {
				try {
					worker.join();
				} catch (...) {
					std::terminate();
				}
			}
		}
	} catch (const StormByte::Exception&) {
		producer.SetError();
	} catch (...) {
		producer.SetError();
	}
	return producer.Consumer();
}

bool StormByte::Crypto::Engine::Signer::VerifySpan(
	std::span<const std::byte> data,
	std::string_view signature,
	Safe::Unique<VerifyBox> box) noexcept {
	if (!box)
		return false;
	try {
		if (!box->Begin(signature))
			return false;
		if (!data.empty() && !box->Update(data))
			return false;
		return box->Finalize();
	} catch (const StormByte::Exception&) {
		return false;
	} catch (...) {
		return false;
	}
}

bool StormByte::Crypto::Engine::Signer::VerifyStream(
	Consumer consumer,
	ReadMode mode,
	std::string_view signature,
	Safe::Unique<VerifyBox> box) noexcept {
	if (!box)
		return false;
	try {
		if (!box->Begin(signature))
			return false;
		while (!consumer.EoF()) {
			if (consumer.HasError())
				return false;
			const StormByte::ByteSize available = consumer.Available();
			if (available == StormByte::ByteSize{0}) {
				Safe::this_thread::yield();
				continue;
			}

			const StormByte::ByteSize toRead = (available < ChunkSize) ? available : ChunkSize;
			WipedChunk chunk;
			const bool ok = (mode == ReadMode::Copy)
				? consumer.Read(toRead, chunk.m_data)
				: consumer.Extract(toRead, chunk.m_data);
			if (!ok)
				return false;
			if (!box->Update(std::span<const std::byte>(chunk.m_data.data(), static_cast<std::size_t>(chunk.m_data.size()))))
				return false;
		}

		return !consumer.HasError() && box->Finalize();
	} catch (const StormByte::Exception&) {
		return false;
	} catch (...) {
		return false;
	}
}
