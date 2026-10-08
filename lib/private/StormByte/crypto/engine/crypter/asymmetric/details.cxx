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
#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/engine/crypter/asymmetric/details.hxx>
#include <StormByte/crypto/random.hxx>

#include <aes.h>
#include <cstring>
#include <filters.h>
#include <gcm.h>

#include <limits>
#include <thread>
#include <type_traits>
#include <utility>

using namespace StormByte;
using namespace StormByte::Crypto;
using namespace StormByte::Crypto::Engine::Crypter::Asymmetric;
using StormByte::Crypto::Helpers::SecureWipe;

bool StormByte::Crypto::Engine::Crypter::Asymmetric::WriteEnvelopeHeader(const Safe::Binary& encryptedKey, const CryptoPP::SecByteBlock& iv, Safe::Binary& output) noexcept {
	try {
		const auto count = static_cast<std::size_t>(encryptedKey.size());
		if (count > std::numeric_limits<std::uint32_t>::max() || iv.size() != IvLen)
			return false;
		const auto length = static_cast<std::uint32_t>(count);
		Safe::Binary header{static_cast<std::byte>((length >> 24) & 0xFF), static_cast<std::byte>((length >> 16) & 0xFF), static_cast<std::byte>((length >> 8) & 0xFF), static_cast<std::byte>(length & 0xFF)};
		header.append(encryptedKey);
		header.append(reinterpret_cast<const std::byte*>(iv.data()), ByteSize{iv.size()});
		output.append(header);
		return true;
	} catch (...) {
		return false;
	}
}

std::uint32_t StormByte::Crypto::Engine::Crypter::Asymmetric::ParseEskLength(const Safe::Binary& lengthBytes) noexcept {
	if (lengthBytes.size() != ByteSize{4})
		return 0;
	const auto bytes = lengthBytes.span();
	return (static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[0])) << 24) |
		(static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[1])) << 16) |
		(static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[2])) << 8) |
		static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[3]));
}

namespace {
	/**
	 * @class NativeOps
	 * @brief Independently transform native public-key message chunks.
	 */
	class NativeOps final: public Engine::Crypter::Ops {
		public:
			/**
			 * @brief Own a key transform.
			 * @param box Transform to own.
			 */
			explicit NativeOps(Safe::Unique<PkBox> box): m_box(std::move(box)) {}

			NativeOps(const NativeOps& other) = delete;

			NativeOps(NativeOps&& other) = delete;

			/**
			 * @brief Release the owned transform.
			 */
			~NativeOps() override = default;

			NativeOps& operator=(const NativeOps& other) = delete;

			NativeOps& operator=(NativeOps&& other) = delete;

			/**
			 * @brief Transform one independent chunk.
			 * @param input Message bytes.
			 * @param output Transformed bytes.
			 * @return Whether transformation succeeded.
			 */
			bool Process(std::span<const std::byte> input, Safe::Binary& output) override {
				return m_box && m_box->Transform(input, output);
			}

			/**
			 * @brief Complete the already finalized transform.
			 * @param output Remaining-output destination.
			 * @return Whether completion succeeded.
			 */
			bool Finalize(Safe::Binary& output) override {
				output.clear();
				return true;
			}

		private:
			Safe::Unique<PkBox> m_box;	///< Owned public-key transform.
	};

	/**
	 * @class HybridOps
	 * @brief Safe-owned AES-GCM envelope state with wiped backend secrets.
	 * @tparam Encrypting Whether to wrap and encrypt rather than unwrap and decrypt.
	 */
	template<bool Encrypting>
	class HybridOps final: public Engine::Crypter::Ops {
		public:
			/**
			 * @brief Configure message processing and own its key transform.
			 * @param box Key transform.
			 * @param mode Source mode.
			 * @param streaming Whether input spans multiple chunks.
			 */
			HybridOps(Safe::Unique<PkBox> box, ReadMode mode, bool streaming):
				m_box(std::move(box)), m_mode(mode), m_streaming(streaming) {}

			HybridOps(const HybridOps& other) = delete;

			HybridOps(HybridOps&& other) = delete;

			/**
			 * @brief Destroy the filter before wiping backend key material.
			 */
			~HybridOps() noexcept override {
				m_filter.reset();
				SecureWipe(m_key);
				SecureWipe(m_iv);
				SecureWipe(m_key_bytes);
			}

			HybridOps& operator=(const HybridOps& other) = delete;

			HybridOps& operator=(HybridOps&& other) = delete;

			/**
			 * @brief Generate and wrap an AES-256 key and emit its envelope header.
			 * @param output Header destination.
			 * @return Whether wrapping and initialization succeeded.
			 */
			bool WriteHeader(Safe::Binary& output) override {
				if constexpr (!Encrypting)
					return true;
				if (!m_box)
					return false;
				try {
					m_key.CleanNew(SymKeyLen);
					m_iv.CleanNew(IvLen);
					RNG().GenerateBlock(m_key, m_key.size());
					RNG().GenerateBlock(m_iv, m_iv.size());
					Safe::Binary encryptedKey;
					if (!m_box->Transform({reinterpret_cast<const std::byte*>(m_key.data()), m_key.size()}, encryptedKey) || !WriteEnvelopeHeader(encryptedKey, m_iv, output))
						return false;
					Initialize();
					return true;
				} catch (...) {
					return false;
				}
			}

			/**
			 * @brief Consume an envelope header and unwrap the session key.
			 * @param input Input advanced past the header on success.
			 * @return Whether parsing and initialization succeeded.
			 */
			bool ReadHeader(std::span<const std::byte>& input) override {
				if constexpr (Encrypting)
					return true;
				if (!m_box || input.size_bytes() < 4 + IvLen)
					return false;
				try {
					const Safe::Binary lengthBytes{input.first(4)};
					const std::size_t count = ParseEskLength(lengthBytes);
					if (count == 0 || count > input.size_bytes() - 4 - IvLen)
						return false;
					m_iv.Assign(reinterpret_cast<const CryptoPP::byte*>(input.data() + 4 + count), IvLen);
					if (!Unwrap(input.subspan(4, count)))
						return false;
					input = input.subspan(4 + count + IvLen);
					return true;
				} catch (...) {
					SecureWipe(m_key_bytes);
					return false;
				}
			}

			/**
			 * @brief Consume the streaming header and unwrap the session key.
			 * @param consumer Header source.
			 * @return Whether parsing and initialization succeeded.
			 */
			bool ReadHeader(Buffer::Consumer& consumer) override {
				if constexpr (Encrypting)
					return true;
				if (!m_box)
					return false;
				try {
					Safe::Binary lengthBytes;
					if (!ReadBytes(consumer, ByteSize{4}, lengthBytes))
						return false;
					const auto count = ParseEskLength(lengthBytes);
					if (count == 0)
						return false;
					Safe::Binary encryptedKey;
					Safe::Binary ivBytes;
					if (!ReadBytes(consumer, ByteSize{count}, encryptedKey) || !ReadBytes(consumer, ByteSize{IvLen}, ivBytes))
						return false;
					m_iv.Assign(reinterpret_cast<const CryptoPP::byte*>(ivBytes.data()), IvLen);
					return Unwrap(encryptedKey.span());
				} catch (...) {
					SecureWipe(m_key_bytes);
					return false;
				}
			}

			/**
			 * @brief Process bytes and drain the private backend queue.
			 * @param input Message bytes.
			 * @param output Processed bytes.
			 * @return Whether processing and one-shot authentication succeeded.
			 */
			bool Process(std::span<const std::byte> input, Safe::Binary& output) override {
				if (!m_filter || m_finished)
					return false;
				try {
					if (!input.empty())
						m_filter->Put(reinterpret_cast<const CryptoPP::byte*>(input.data()), input.size_bytes());
					if (!m_streaming) {
						m_filter->MessageEnd();
						m_finished = true;
					}
					Drain(output);
					return true;
				} catch (...) {
					return false;
				}
			}

			/**
			 * @brief Complete authentication and release the filter.
			 * @param output Remaining output bytes.
			 * @return Whether completion and authentication succeeded.
			 */
			bool Finalize(Safe::Binary& output) override {
				if (!m_filter)
					return false;
				try {
					if (!m_finished) {
						m_filter->MessageEnd();
						m_finished = true;
					}
					Drain(output);
					m_filter.reset();
					return true;
				} catch (...) {
					return false;
				}
			}

		private:
			/**
			 * @brief Backend cipher for this envelope direction.
			 */
			using Cipher = std::conditional_t<Encrypting, CryptoPP::GCM<CryptoPP::AES>::Encryption, CryptoPP::GCM<CryptoPP::AES>::Decryption>;

			/**
			 * @brief Backend filter for this envelope direction.
			 */
			using Filter = std::conditional_t<Encrypting, CryptoPP::AuthenticatedEncryptionFilter, CryptoPP::AuthenticatedDecryptionFilter>;

			/**
			 * @brief Initialize the cipher and its unattached Safe-owned filter.
			 * @throws StormByte::Exception Safe allocation failed.
			 * @throws CryptoPP::Exception Backend initialization failed.
			 */
			void Initialize() {
				m_cipher.SetKeyWithIV(m_key, m_key.size(), m_iv, m_iv.size());
				m_filter = Safe::Unique<Filter>::template MakePointer<Filter>(m_cipher);
				SecureWipe(m_key);
			}

			/**
			 * @brief Unwrap exactly one AES-256 key and wipe the temporary on all paths.
			 * @param encryptedKey Wrapped session key.
			 * @return Whether unwrapping and initialization succeeded.
			 * @throws StormByte::Exception Safe allocation failed.
			 * @throws CryptoPP::Exception Backend initialization failed.
			 */
			bool Unwrap(std::span<const std::byte> encryptedKey) {
				try {
					if (!m_box->Transform(encryptedKey, m_key_bytes) || m_key_bytes.size() != ByteSize{SymKeyLen}) {
						SecureWipe(m_key_bytes);
						return false;
					}
					m_key.Assign(reinterpret_cast<const CryptoPP::byte*>(m_key_bytes.data()), SymKeyLen);
					SecureWipe(m_key_bytes);
					Initialize();
					return true;
				} catch (...) {
					SecureWipe(m_key_bytes);
					throw;
				}
			}

			/**
			 * @brief Wait for and consume exact header bytes in the selected mode.
			 * @param consumer Header source.
			 * @param count Required byte count.
			 * @param output Consumed bytes.
			 * @return Whether all requested bytes were consumed.
			 */
			bool ReadBytes(Buffer::Consumer& consumer, ByteSize count, Safe::Binary& output) {
				while (consumer.Available() < count && !consumer.EoF())
					std::this_thread::yield();
				if (consumer.Available() < count)
					return false;
				return (m_mode == ReadMode::Copy ? consumer.Read(count, output) : consumer.Extract(count, output)) && output.size() == count;
			}

			/**
			 * @brief Drain queued bytes into Base-owned storage.
			 * @param output Output destination.
			 * @throws StormByte::Exception Safe allocation failed.
			 * @throws CryptoPP::Exception Queue access failed.
			 */
			void Drain(Safe::Binary& output) {
				const ByteSize count{m_filter->MaxRetrievable()};
				output.resize(count);
				if (!output.empty())
					m_filter->Get(reinterpret_cast<CryptoPP::byte*>(output.data()), static_cast<std::size_t>(count));
			}

			Safe::Unique<PkBox> m_box;	///< Owned key transform.
			ReadMode m_mode;				///< Source processing mode.
			bool m_streaming;			///< Whether input spans multiple chunks.
			CryptoPP::SecByteBlock m_key;	///< Wiped backend session key.
			CryptoPP::SecByteBlock m_iv;	///< Wiped backend initialization vector.
			Safe::Binary m_key_bytes;	///< Unwrapped key temporary, wiped on every path.
			Cipher m_cipher;			///< Backend cipher, outlives its filter.
			Safe::Unique<Filter> m_filter;	///< Safe-owned filter without attachment transfers.
			bool m_finished = false;		///< Whether MessageEnd succeeded.
	};

	/**
	 * @brief Allocate an engine without letting allocation failures escape noexcept entry points.
	 * @tparam OpsT Concrete engine type.
	 * @tparam Args Constructor argument types.
	 * @param args Forwarded constructor arguments.
	 * @return Owned engine, or an empty owner on failure.
	 */
	template<class OpsT, class... Args>
	Safe::Unique<Engine::Crypter::Ops> MakeOps(Args&&... args) noexcept {
		try {
			return Safe::Unique<Engine::Crypter::Ops>::template MakePointer<OpsT>(std::forward<Args>(args)...);
		} catch (...) {
			return {};
		}
	}
}

bool StormByte::Crypto::Engine::Crypter::Asymmetric::NativeProcessSpan(std::span<const std::byte> data, Buffer::WriteOnly& output, Safe::Unique<PkBox> box) noexcept {
	return box && Engine::Crypter::ProcessSpan(data, output, MakeOps<NativeOps>(std::move(box)));
}

Buffer::Consumer StormByte::Crypto::Engine::Crypter::Asymmetric::NativeProcessStream(Buffer::Consumer consumer, ReadMode mode, Safe::Unique<PkBox> box) noexcept {
	return Engine::Crypter::Stream(std::move(consumer), mode, box ? MakeOps<NativeOps>(std::move(box)) : Safe::Unique<Engine::Crypter::Ops>{});
}

bool StormByte::Crypto::Engine::Crypter::Asymmetric::HybridEncryptSpan(std::span<const std::byte> data, Buffer::WriteOnly& output, Safe::Unique<PkBox> box) noexcept {
	return box && Engine::Crypter::ProcessSpan(data, output, MakeOps<HybridOps<true>>(std::move(box), ReadMode::Copy, false));
}

Buffer::Consumer StormByte::Crypto::Engine::Crypter::Asymmetric::HybridEncryptStream(Buffer::Consumer consumer, ReadMode mode, Safe::Unique<PkBox> box) noexcept {
	return Engine::Crypter::Stream(std::move(consumer), mode, box ? MakeOps<HybridOps<true>>(std::move(box), mode, true) : Safe::Unique<Engine::Crypter::Ops>{});
}

bool StormByte::Crypto::Engine::Crypter::Asymmetric::HybridDecryptSpan(std::span<const std::byte> data, Buffer::WriteOnly& output, Safe::Unique<PkBox> box) noexcept {
	return box && Engine::Crypter::ProcessSpan(data, output, MakeOps<HybridOps<false>>(std::move(box), ReadMode::Copy, false));
}

Buffer::Consumer StormByte::Crypto::Engine::Crypter::Asymmetric::HybridDecryptStream(Buffer::Consumer consumer, ReadMode mode, Safe::Unique<PkBox> box) noexcept {
	return Engine::Crypter::Stream(std::move(consumer), mode, box ? MakeOps<HybridOps<false>>(std::move(box), mode, true) : Safe::Unique<Engine::Crypter::Ops>{});
}
