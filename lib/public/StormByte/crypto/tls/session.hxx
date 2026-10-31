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
 * thirdparty/, in particular OpenSSL, Crypto++, bundled libbzip2, the
 * StormByte-Buffer tree and the StormByte suite it vendors), which remains
 * under its own license.
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

#include <StormByte/crypto/tls/policy.hxx>
#include <StormByte/crypto/x509/trust_path.hxx>
#include <StormByte/crypto/visibility.h>
#include <StormByte/expected.hxx>

#include <cstddef>
#include <chrono>
#include <memory>
#include <span>
#include <string_view>

namespace StormByte::Crypto::TLS {
	/**
	 * @enum Role
	 * @brief TLS endpoint role for a stream session.
	 */
	enum class Role {
		Client,	///< Initiates a TLS handshake and authenticates a server.
		Server	///< Accepts a TLS handshake and presents a configured certificate.
	};

	/**
	 * @enum State
	 * @brief Observable lifecycle of a buffer-driven TLS session.
	 */
	enum class State {
		Handshaking,	///< The peer handshake is not yet complete.
		Open,		///< The handshake completed and application data may flow.
		Closing,	///< A local or peer close-notify is being exchanged.
		Closed,		///< TLS shutdown completed.
		Failed		///< A fatal protocol, validation or backend error occurred.
	};

	/**
	 * @enum SessionError
	 * @brief Typed TLS session failures.
	 */
	enum class SessionError {
		InvalidConfiguration,	///< Invalid role, identity, certificate, key or trust configuration.
		UnsupportedPolicy,	///< The selected TLS policy cannot be represented by this engine.
		BackendFailure,		///< OpenSSL failed an operation or resource allocation.
		PeerRejected,		///< Peer certificate, trust path, identity or revocation was rejected.
		InvalidState,		///< The requested operation is invalid for this session state.
		BufferLimit		///< A configured internal bound would be exceeded.
	};

	/**
	 * @enum TrustSource
	 * @brief Source of trust anchors for a client or mutual-TLS server.
	 */
	enum class TrustSource {
		Bundled,	///< The versioned StormByte public server-root bundle.
		Custom		///< Only the explicitly supplied certificate authorities.
	};

	/**
	 * @struct ClientConfiguration
	 * @brief Borrowed construction inputs for an authenticated TLS client.
	 *
	 * Empty trust_anchors selects the bundled trust source only when trust_source
	 * is Bundled. Custom trust requires at least one explicit anchor. Revocation
	 * evidence is copied during CreateClient when required and must be ordered
	 * leaf-to-issuer, excluding the trust anchor.
	 */
	struct ClientConfiguration final {
		X509::SubjectAltName identity;	///< Required expected DNS or binary IP SAN.
		TrustSource trust_source{TrustSource::Bundled};	///< Trust store policy.
		std::span<const X509::Certificate> trust_anchors{};	///< Custom anchors, never merged with bundled roots.
		X509::TimePoint validation_time{std::chrono::floor<std::chrono::seconds>(
			std::chrono::system_clock::now())};	///< Certificate/evidence validation time.
		bool require_revocation{false};	///< Require fresh Good evidence for each non-anchor certificate.
		std::span<const X509::RevocationEvidence> revocation_evidence{};	///< Borrowed DER evidence copied at construction.
		std::span<const std::byte> certificate_chain_pem{};	///< Optional client certificate chain for mutual TLS.
		std::span<const std::byte> private_key_pem{};	///< Optional matching client private key.
		std::span<const std::byte> private_key_password{};	///< Optional password for an encrypted client key.
		Configuration policy{};	///< Validated TLS 1.3 suites, groups and signature schemes.
		std::span<const std::byte> alpn_wire{};	///< Optional length-prefixed ALPN protocol list.
	};

	/**
	 * @struct ServerConfiguration
	 * @brief Borrowed construction inputs for a TLS server.
	 *
	 * The certificate PEM contains the leaf first, followed by any intermediate
	 * certificates. The private key is parsed synchronously and never retained as
	 * caller-owned memory.
	 */
	struct ServerConfiguration final {
		std::span<const std::byte> certificate_chain_pem{};	///< PEM leaf and optional intermediate certificates.
		std::span<const std::byte> private_key_pem{};	///< PEM private key matching the leaf certificate.
		std::span<const std::byte> private_key_password{};	///< Optional PEM key password.
		bool require_client_certificate{false};	///< Require and validate a client certificate.
		std::span<const X509::Certificate> client_trust_anchors{};	///< Exclusive custom client CA anchors for mTLS.
		X509::TimePoint validation_time{std::chrono::floor<std::chrono::seconds>(
			std::chrono::system_clock::now())};	///< Client certificate validation time.
		Configuration policy{};	///< Validated TLS 1.3 suites, groups and signature schemes.
		std::span<const std::byte> alpn_wire{};	///< Optional length-prefixed server protocol preference list.
	};

	/**
	 * @class Session
	 * @brief OpenSSL-backed TLS 1.3 stream engine driven only by caller buffers.
	 *
	 * Crypto performs no socket, DNS, HTTP, filesystem or clock I/O. Callers feed
	 * received ciphertext with FeedEncrypted, drain pending protocol bytes with
	 * DrainEncrypted, and exchange application bytes with WritePlaintext and
	 * ReadPlaintext. Methods report partial progress so the caller retains
	 * ownership of transport scheduling, deadlines, cancellation and retries.
	 * OpenSSL types are private to the implementation and are not part of this API.
	 *
	 * Each session is single-threaded; callers must serialize all operations on it.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Session final {
		public:
			/**
			 * @brief Construct a failed, empty session.
			 */
			Session() noexcept;

			/**
			 * @brief Transfer session state.
			 * @param other Source session; it becomes empty.
			 */
			Session(Session&& other) noexcept;

			/**
			 * @brief Destroy the TLS state and its private OpenSSL resources.
			 */
			~Session() noexcept;

			/**
			 * @brief Transfer session state.
			 * @param other Source session; it becomes empty.
			 * @return This session.
			 */
			Session& operator=(Session&& other) noexcept;

			Session(const Session&) = delete;
			Session& operator=(const Session&) = delete;

			/**
			 * @brief Create a client with explicit identity, trust, time and TLS policy.
			 * @param configuration Borrowed options copied or consumed during this call.
			 * @return Configured client or a typed setup failure.
			 * @throws StormByte::Safe::AllocationError Safe-owned configuration cannot be copied.
			 */
			static StormByte::Expected<Session, SessionError> CreateClient(const ClientConfiguration& configuration);

			/**
			 * @brief Create a server that presents the configured certificate and key.
			 * @param configuration Borrowed certificate/key and policy options.
			 * @return Configured server or a typed setup failure.
			 * @throws StormByte::Safe::AllocationError Safe-owned configuration cannot be copied.
			 */
			static StormByte::Expected<Session, SessionError> CreateServer(const ServerConfiguration& configuration);

			/**
			 * @brief Copy ciphertext into the bounded input buffer and advance TLS.
			 * @param encrypted Caller-owned network bytes.
			 * @return Number of bytes consumed; zero means backpressure or no progress.
			 * @throws No exception is raised for peer-controlled protocol errors; they set Failed.
			 */
			StormByte::Expected<std::size_t, SessionError> FeedEncrypted(std::span<const std::byte> encrypted);

			/**
			 * @brief Copy pending TLS protocol bytes into the caller's output buffer.
			 * @param output Destination for ciphertext.
			 * @return Number of encrypted bytes produced; zero means no output is pending.
			 */
			StormByte::Expected<std::size_t, SessionError> DrainEncrypted(std::span<std::byte> output);

			/**
			 * @brief Encrypt caller plaintext after successful handshake validation.
			 * @param plaintext Application bytes.
			 * @return Number of plaintext bytes consumed; partial progress is allowed.
			 */
			StormByte::Expected<std::size_t, SessionError> WritePlaintext(std::span<const std::byte> plaintext);

			/**
			 * @brief Decrypt available application bytes into the caller's buffer.
			 * @param output Destination for plaintext.
			 * @return Number of plaintext bytes produced; zero means more ciphertext is needed.
			 */
			StormByte::Expected<std::size_t, SessionError> ReadPlaintext(std::span<std::byte> output);

			/**
			 * @brief Begin or advance orderly TLS shutdown.
			 * @return Success, including when peer close-notify is still outstanding.
			 */
			StormByte::Expected<void, SessionError> Shutdown();

			/**
			 * @brief Read the current lifecycle state.
			 * @return State; a moved-from or empty session reports Failed.
			 */
			State Status() const noexcept;

			/**
			 * @brief Read the sticky fatal failure, if any.
			 * @return Failure code; BackendFailure for a session that was never created.
			 */
			SessionError Failure() const noexcept;

			/**
			 * @brief Test whether the TLS handshake finished successfully.
			 * @return True only while the session is Open or Closing after a validated handshake.
			 */
			bool HandshakeComplete() const noexcept;

			/**
			 * @brief Read the negotiated application protocol.
			 * @return Borrowed protocol name, empty when ALPN was not negotiated.
			 * @note The view remains valid only while this session remains alive.
			 */
			std::string_view NegotiatedALPN() const noexcept;

			/**
			 * @brief Maximum ciphertext accepted by one FeedEncrypted call.
			 */
			static constexpr std::size_t MaxInputChunk = 64 * 1024;

			/**
			 * @brief Maximum ciphertext retained in either internal buffer.
			 */
			static constexpr std::size_t MaxPendingCiphertext = 1024 * 1024;

		private:
			struct Impl;

			explicit Session(std::unique_ptr<Impl> impl) noexcept;
			std::unique_ptr<Impl> m_impl;
	};
}
