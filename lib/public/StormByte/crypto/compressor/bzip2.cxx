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
#include <StormByte/crypto/compressor/bzip2.hxx>
#include <StormByte/crypto/engine/compressor/details.hxx>
#include <StormByte/safe/vector.hxx>

#include <algorithm>
#include <bzlib.h>

using StormByte::Buffer::Consumer;
using StormByte::Buffer::Producer;
using StormByte::Buffer::WriteOnly;
using namespace StormByte::Crypto::Compressor;

namespace {
	constexpr size_t kOutChunk = 4096;

	struct Bzip2CompressOps final : StormByte::Crypto::Engine::Compressor::StreamOps {
		bz_stream strm{};
		StormByte::Safe::Vector<char> outChunk;
		bool ok = false;

		explicit Bzip2CompressOps(unsigned short level):
			outChunk(kOutChunk) {
			const int rc = BZ2_bzCompressInit(&strm, static_cast<int>(level), 0, 30);
			ok = (rc == BZ_OK);
		}

		~Bzip2CompressOps() override {
			if (ok)
				BZ2_bzCompressEnd(&strm);
		}

		bool Process(std::span<const std::byte> in, StormByte::Safe::Binary& out) override {
			if (!ok)
				return false;
			try {
				strm.next_in = reinterpret_cast<char*>(const_cast<std::byte*>(in.data()));
				strm.avail_in = static_cast<unsigned int>(in.size_bytes());
				while (strm.avail_in > 0) {
					strm.next_out = outChunk.data();
					strm.avail_out = static_cast<unsigned int>(outChunk.size());
					const int rc = BZ2_bzCompress(&strm, BZ_RUN);
					if (rc != BZ_RUN_OK && rc != BZ_FINISH_OK && rc != BZ_FLUSH_OK)
						return false;
					const unsigned int produced = static_cast<unsigned int>(outChunk.size()) - strm.avail_out;
					if (produced)
						out.append(std::as_bytes(std::span(outChunk.data(), produced)));
				}

				return true;
			} catch (...) {
				return false;
			}
		}

		bool Finalize(StormByte::Safe::Binary& out) override {
			if (!ok)
				return false;
			try {
				for (;;) {
					strm.next_out = outChunk.data();
					strm.avail_out = static_cast<unsigned int>(outChunk.size());
					const int r = BZ2_bzCompress(&strm, BZ_FINISH);
					if (r != BZ_FINISH_OK && r != BZ_STREAM_END && r != BZ_RUN_OK)
						return false;
					const unsigned int produced = static_cast<unsigned int>(outChunk.size()) - strm.avail_out;
					if (produced)
						out.append(std::as_bytes(std::span(outChunk.data(), produced)));

					if (r == BZ_STREAM_END)
						break;
				}

				BZ2_bzCompressEnd(&strm);
				ok = false;
				return true;
			} catch (...) {
				return false;
			}
		}
	};

	struct Bzip2DecompressOps final : StormByte::Crypto::Engine::Compressor::StreamOps {
		bz_stream strm{};
		StormByte::Safe::Vector<char> outChunk;
		bool ok = false;
		bool ended = false;

		Bzip2DecompressOps():
			outChunk(kOutChunk) {
			const int rc = BZ2_bzDecompressInit(&strm, 0, 0);
			ok = (rc == BZ_OK);
		}

		~Bzip2DecompressOps() override {
			if (ok)
				BZ2_bzDecompressEnd(&strm);
		}

		bool Process(std::span<const std::byte> in, StormByte::Safe::Binary& out) override {
			if (!ok || ended)
				return !ended;
			try {
				strm.next_in = reinterpret_cast<char*>(const_cast<std::byte*>(in.data()));
				strm.avail_in = static_cast<unsigned int>(in.size_bytes());
				while (strm.avail_in > 0) {
					strm.next_out = outChunk.data();
					strm.avail_out = static_cast<unsigned int>(outChunk.size());
					const int r = BZ2_bzDecompress(&strm);
					if (r != BZ_OK && r != BZ_STREAM_END)
						return false;
					const unsigned int produced = static_cast<unsigned int>(outChunk.size()) - strm.avail_out;
					if (produced)
						out.append(std::as_bytes(std::span(outChunk.data(), produced)));

					if (r == BZ_STREAM_END) {
						ended = true;
						break;
					}
				}

				return true;
			} catch (...) {
				return false;
			}
		}

		bool Finalize(StormByte::Safe::Binary& /*out*/) override {
			if (!ok)
				return false;
			BZ2_bzDecompressEnd(&strm);
			ok = false;
			return true;
		}
	};
}

Bzip2::~Bzip2() noexcept = default;

Generic::PointerType Bzip2::Clone() const {
	return MakePointer<Bzip2>(*this);
}

Generic::PointerType Bzip2::Move() noexcept {
	return MakePointer<Bzip2>(std::move(*this));
}

Bzip2::Bzip2(unsigned short level):
	Generic(Type::Bzip2, std::clamp<unsigned short>(static_cast<unsigned short>(level), 1, 9)) {}

bool Bzip2::DoCompress(std::span<const std::byte> input, WriteOnly& output) const noexcept {
	if (input.size_bytes() == 0)
		return true;
	try {
		unsigned int inLen = static_cast<unsigned int>(input.size_bytes());
		unsigned int outLen = inLen + (inLen / 100) + 600;
		StormByte::Safe::Vector<char> outBuf(outLen);
		const int rc = BZ2_bzBuffToBuffCompress(
			outBuf.data(),
			&outLen,
			reinterpret_cast<char*>(const_cast<std::byte*>(input.data())),
			inLen,
			static_cast<int>(m_level),
			0,
			30
		);
		if (rc != BZ_OK)
			return false;
		StormByte::Safe::Binary compressed(std::as_bytes(std::span(outBuf.data(), outLen)));
		return output.Write(std::move(compressed));
	} catch (...) {
		return false;
	}
}

Consumer Bzip2::DoCompress(Consumer consumer, ReadMode mode) const noexcept {
	return Engine::Compressor::Stream(
		std::move(consumer), mode, StormByte::Safe::Unique<Engine::Compressor::StreamOps>::MakePointer<Bzip2CompressOps>(m_level));
}

bool Bzip2::DoDecompress(std::span<const std::byte> input, WriteOnly& output) const noexcept {
	if (input.size_bytes() == 0)
		return true;
	try {
		unsigned int inLen = static_cast<unsigned int>(input.size_bytes());
		unsigned int outLen = inLen * 5 + 1000;
		StormByte::Safe::Vector<char> outBuf(outLen);
		const int rc = BZ2_bzBuffToBuffDecompress(
			outBuf.data(),
			&outLen,
			reinterpret_cast<char*>(const_cast<std::byte*>(input.data())),
			inLen,
			0,
			0
		);
		if (rc != BZ_OK)
			return false;
		StormByte::Safe::Binary decompressed(std::as_bytes(std::span(outBuf.data(), outLen)));
		return output.Write(std::move(decompressed));
	} catch (...) {
		return false;
	}
}

Consumer Bzip2::DoDecompress(Consumer consumer, ReadMode mode) const noexcept {
	return Engine::Compressor::Stream(
		std::move(consumer), mode, StormByte::Safe::Unique<Engine::Compressor::StreamOps>::MakePointer<Bzip2DecompressOps>());
}
