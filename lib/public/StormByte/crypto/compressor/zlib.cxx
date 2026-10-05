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
#include <StormByte/crypto/compressor/zlib.hxx>
#include <StormByte/crypto/engine/compressor/details.hxx>

#include <algorithm>
#include <filters.h>
#include <memory>
#include <zlib.h>

using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using StormByte::Buffer::WriteOnly;
using namespace StormByte::Crypto::Compressor;

Zlib::~Zlib() noexcept = default;

Generic::PointerType Zlib::Clone() const {
	return MakePointer<Zlib>(*this);
}

Generic::PointerType Zlib::Move() noexcept {
	return MakePointer<Zlib>(std::move(*this));
}

namespace {
	struct ZlibCompressOps final : StormByte::Crypto::Engine::Compressor::StreamOps {
		StormByte::BinaryData buffer;
		std::unique_ptr<CryptoPP::ZlibCompressor> compressor;

		explicit ZlibCompressOps(unsigned short level) {
			compressor = std::make_unique<CryptoPP::ZlibCompressor>(
				new CryptoPP::StringSinkTemplate<StormByte::BinaryData>(buffer),
				level
			);
		}

		bool Process(std::span<const std::byte> in, StormByte::BinaryData& out) override {
			try {
				compressor->Put(reinterpret_cast<const uint8_t*>(in.data()), in.size_bytes());
				compressor->Flush(true);
				out = std::move(buffer);
				buffer.clear();
				return true;
			} catch (...) {
				return false;
			}
		}

		bool Finalize(StormByte::BinaryData& out) override {
			try {
				compressor->MessageEnd();
				out = std::move(buffer);
				buffer.clear();
				compressor.reset();
				return true;
			} catch (...) {
				return false;
			}
		}
	};

	struct ZlibDecompressOps final : StormByte::Crypto::Engine::Compressor::StreamOps {
		StormByte::BinaryData buffer;
		std::unique_ptr<CryptoPP::ZlibDecompressor> decompressor;

		ZlibDecompressOps() {
			decompressor = std::make_unique<CryptoPP::ZlibDecompressor>(
				new CryptoPP::StringSinkTemplate<StormByte::BinaryData>(buffer)
			);
		}

		bool Process(std::span<const std::byte> in, StormByte::BinaryData& out) override {
			try {
				decompressor->Put(reinterpret_cast<const uint8_t*>(in.data()), in.size_bytes());
				decompressor->Flush(true);
				out = std::move(buffer);
				buffer.clear();
				return true;
			} catch (...) {
				return false;
			}
		}

		bool Finalize(StormByte::BinaryData& out) override {
			try {
				decompressor->MessageEnd();
				out = std::move(buffer);
				buffer.clear();
				decompressor.reset();
				return true;
			} catch (...) {
				return false;
			}
		}
	};
}

Zlib::Zlib(unsigned short level):
	Generic(Type::Zlib, std::clamp<unsigned short>(
		static_cast<unsigned short>(level),
		1,
		CryptoPP::ZlibCompressor::MAX_DEFLATE_LEVEL)) {}

bool Zlib::DoCompress(std::span<const std::byte> input, WriteOnly& output) const noexcept {
	return Engine::Compressor::ProcessSpan(
		input, output, std::make_unique<ZlibCompressOps>(m_level));
}

Consumer Zlib::DoCompress(Consumer consumer, ReadMode mode) const noexcept {
	return Engine::Compressor::Stream(
		std::move(consumer), mode, std::make_unique<ZlibCompressOps>(m_level));
}

bool Zlib::DoDecompress(std::span<const std::byte> input, WriteOnly& output) const noexcept {
	return Engine::Compressor::ProcessSpan(
		input, output, std::make_unique<ZlibDecompressOps>());
}

Consumer Zlib::DoDecompress(Consumer consumer, ReadMode mode) const noexcept {
	return Engine::Compressor::Stream(
		std::move(consumer), mode, std::make_unique<ZlibDecompressOps>());
}
