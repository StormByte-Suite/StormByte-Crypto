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

#include <StormByte/crypto/tls/session.hxx>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <climits>
#include <cstring>
#include <ctime>
#include <string>
#include <utility>
#include <vector>

namespace {
	using namespace StormByte::Crypto::TLS;
	namespace CryptoX509 = StormByte::Crypto::X509;

	constexpr std::size_t MaxPlaintextRecord = 16 * 1024;
	constexpr std::size_t MaxCertificateChain = 18;
	constexpr std::size_t MaxCertificateList = 256 * 1024;
	constexpr std::size_t MaxPEMCertificateChain = MaxCertificateList * 2;
	constexpr std::size_t MaxRevocationEvidence = 4 * 1024 * 1024;

	/**
	 * @brief Adapts the validated suite list to OpenSSL's TLS 1.3 names.
	 * @param configuration Validated policy input.
	 * @return Colon-separated cipher suite names, or an empty string for invalid input.
	 */
	std::string CipherSuites(const Configuration& configuration) {
		std::string result;
		for (const auto suite : configuration.cipher_suites) {
			const char* name = nullptr;
			switch (suite) {
				case CipherSuite::TLS_AES_128_GCM_SHA256: name = "TLS_AES_128_GCM_SHA256"; break;
				case CipherSuite::TLS_AES_256_GCM_SHA384: name = "TLS_AES_256_GCM_SHA384"; break;
			}
			if (!name)
				return {};
			if (!result.empty())
				result.push_back(':');
			result += name;
		}
		return result;
	}

	/**
	 * @brief Adapts named groups to OpenSSL's group-list names.
	 * @param configuration Validated policy input.
	 * @return Colon-separated group names, or an empty string for invalid input.
	 */
	std::string Groups(const Configuration& configuration) {
		std::string result;
		for (const auto group : configuration.groups) {
			const char* name = nullptr;
			switch (group) {
				case Group::X25519: name = "X25519"; break;
				case Group::Secp256r1: name = "prime256v1"; break;
			}
			if (!name)
				return {};
			if (!result.empty())
				result.push_back(':');
			result += name;
		}
		return result;
	}

	/**
	 * @brief Adapts signature schemes to OpenSSL's TLS signature list.
	 * @param configuration Validated policy input.
	 * @return Colon-separated signature names, or an empty string for invalid input.
	 */
	std::string SignatureSchemes(const Configuration& configuration) {
		std::string result;
		for (const auto scheme : configuration.signature_schemes) {
			const char* name = nullptr;
			switch (scheme) {
				case SignatureScheme::ECDSA_SECP256R1_SHA256: name = "ecdsa_secp256r1_sha256"; break;
				case SignatureScheme::RSA_PSS_RSAE_SHA256: name = "rsa_pss_rsae_sha256"; break;
			}
			if (!name)
				return {};
			if (!result.empty())
				result.push_back(':');
			result += name;
		}
		return result;
	}

	bool ConfigurePolicy(SSL_CTX* context, const Configuration& configuration) {
		if (!Validate(configuration))
			return false;
		const auto suites = CipherSuites(configuration);
		const auto groups = Groups(configuration);
		const auto signatures = SignatureSchemes(configuration);
		const auto list_result = SSL_CTX_set_max_cert_list(context, MaxCertificateList);
		return !suites.empty() && !groups.empty() && !signatures.empty()
			&& SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) == 1
			&& SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION) == 1
			&& SSL_CTX_set_options(context, SSL_OP_NO_COMPRESSION) != 0
			&& SSL_CTX_set_ciphersuites(context, suites.c_str()) == 1
			&& SSL_CTX_set1_groups_list(context, groups.c_str()) == 1
			&& SSL_CTX_set1_sigalgs_list(context, signatures.c_str()) == 1
			&& list_result > 0
			&& SSL_CTX_get_max_cert_list(context) == static_cast<long>(MaxCertificateList);
	}

	bool AddTrustAnchor(SSL_CTX* context, const CryptoX509::Certificate& certificate) {
		const auto der = certificate.Der().span();
		if (der.empty() || der.size() > LONG_MAX)
			return false;
		const auto* cursor = reinterpret_cast<const unsigned char*>(der.data());
		::X509* root = d2i_X509(nullptr, &cursor, static_cast<long>(der.size()));
		if (!root)
			return false;
		const bool added = X509_STORE_add_cert(SSL_CTX_get_cert_store(context), root) == 1;
		X509_free(root);
		return added;
	}

	bool AddTrustAnchors(SSL_CTX* context, std::span<const CryptoX509::Certificate> anchors) {
		if (anchors.empty() || anchors.size() > MaxCertificateChain)
			return false;
		for (std::size_t i = 0; i < anchors.size(); ++i) {
			if (anchors[i].Der().empty() || !anchors[i].IsCA())
				return false;
			for (std::size_t j = 0; j < i; ++j)
				if (anchors[i] == anchors[j])
					return false;
			if (!AddTrustAnchor(context, anchors[i])) {
				ERR_clear_error();
				return false;
			}
		}
		return true;
	}

	bool AddCertificateChain(SSL_CTX* context, std::span<const std::byte> pem) {
		if (pem.empty() || pem.size() > MaxPEMCertificateChain || pem.size() > INT_MAX)
			return false;
		std::size_t pem_size = pem.size();
		while (pem_size > 0) {
			const auto value = std::to_integer<unsigned char>(pem[pem_size - 1]);
			if (value != '\n' && value != '\r' && value != '\t' && value != ' ')
				break;
			--pem_size;
		}
		BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem_size));
		if (!bio)
			return false;
		::X509* leaf = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
		if (!leaf) {
			BIO_free(bio);
			ERR_clear_error();
			return false;
		}
		const int leaf_size = i2d_X509(leaf, nullptr);
		std::size_t total_der_size = leaf_size > 0 ? static_cast<std::size_t>(leaf_size) : 0;
		std::size_t certificate_count = 1;
		bool success = leaf_size > 0 && total_der_size <= MaxCertificateList
			&& SSL_CTX_use_certificate(context, leaf) == 1;
		::X509* chain_certificate = nullptr;
		while (success && BIO_ctrl_pending(bio) > 0) {
			if (certificate_count == MaxCertificateChain) {
				success = false;
				break;
			}
			chain_certificate = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
			if (!chain_certificate) {
				success = false;
				break;
			}
			const int certificate_size = i2d_X509(chain_certificate, nullptr);
			success = certificate_size > 0
				&& static_cast<std::size_t>(certificate_size) <= MaxCertificateList - total_der_size
				&& SSL_CTX_add1_chain_cert(context, chain_certificate) == 1;
			if (success) {
				total_der_size += static_cast<std::size_t>(certificate_size);
				++certificate_count;
			}
			X509_free(chain_certificate);
			chain_certificate = nullptr;
		}
		if (chain_certificate)
			X509_free(chain_certificate);
		X509_free(leaf);
		BIO_free(bio);
		ERR_clear_error();
		return success;
	}

	int ReadPassword(char* output, int capacity, int, void* user_data) {
		const auto* password = static_cast<const std::span<const std::byte>*>(user_data);
		if (!password || password->size() > static_cast<std::size_t>(capacity))
			return 0;
		if (!password->empty())
			std::memcpy(output, password->data(), password->size());
		return static_cast<int>(password->size());
	}

	bool AddPrivateKey(SSL_CTX* context, std::span<const std::byte> pem,
		std::span<const std::byte> password) {
		if (pem.empty() || pem.size() > INT_MAX || password.size() > INT_MAX)
			return false;
		BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
		if (!bio)
			return false;
		auto password_copy = password;
		EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, ReadPassword, &password_copy);
		BIO_free(bio);
		if (!key) {
			ERR_clear_error();
			return false;
		}
		const bool success = SSL_CTX_use_PrivateKey(context, key) == 1
			&& SSL_CTX_check_private_key(context) == 1;
		EVP_PKEY_free(key);
		ERR_clear_error();
		return success;
	}

	bool ValidALPN(std::span<const std::byte> protocols) {
		if (protocols.empty())
			return true;
		std::size_t offset = 0;
		while (offset < protocols.size()) {
			const auto length = std::to_integer<std::size_t>(protocols[offset++]);
			if (length == 0 || length > protocols.size() - offset)
				return false;
			offset += length;
		}
		return true;
	}
}

struct StormByte::Crypto::TLS::Session::Impl final {
	struct StoredEvidence {
		CryptoX509::RevocationFormat format;
		StormByte::Safe::Binary der;
	};

	SSL_CTX* context{};
	SSL* ssl{};
	BIO* input{};
	BIO* output{};
	std::vector<CryptoX509::Certificate> anchors;
	std::vector<StoredEvidence> evidence;
	std::vector<unsigned char> server_alpn;
	CryptoX509::SubjectAltName identity;
	CryptoX509::TimePoint validation_time{};
	TrustSource trust_source{TrustSource::Bundled};
	Role role{Role::Client};
	State state{State::Handshaking};
	SessionError failure{SessionError::BackendFailure};
	bool require_revocation{false};
	bool verification_failed{false};

	~Impl() {
		if (ssl)
			SSL_free(ssl);
		if (context)
			SSL_CTX_free(context);
	}

	bool Fail(SessionError error) noexcept {
		state = State::Failed;
		failure = error;
		return false;
	}

	static int VerifyCallback(X509_STORE_CTX* store, void*) noexcept {
		SSL* ssl = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(store,
			SSL_get_ex_data_X509_STORE_CTX_idx()));
		auto* self = ssl ? static_cast<Impl*>(SSL_get_app_data(ssl)) : nullptr;
		if (!self)
			return 0;
		return self->VerifyPeer(store) ? 1 : 0;
	}

	static int SelectALPN(SSL* ssl, const unsigned char** output,
		unsigned char* output_length, const unsigned char* input,
		unsigned int input_length, void*) noexcept {
		auto* self = static_cast<Impl*>(SSL_get_app_data(ssl));
		if (!self || self->server_alpn.empty())
			return SSL_TLSEXT_ERR_NOACK;
		unsigned char* selected = nullptr;
		unsigned char selected_length = 0;
		const int result = SSL_select_next_proto(&selected, &selected_length,
			self->server_alpn.data(), static_cast<unsigned int>(self->server_alpn.size()),
			input, input_length);
		if (result != OPENSSL_NPN_NEGOTIATED)
			return SSL_TLSEXT_ERR_NOACK;
		*output = selected;
		*output_length = selected_length;
		return SSL_TLSEXT_ERR_OK;
	}

	bool VerifyPeer(X509_STORE_CTX* store) noexcept {
		if (X509_verify_cert(store) != 1)
			return VerificationFailure();
		STACK_OF(X509)* chain = X509_STORE_CTX_get0_chain(store);
		const int count = chain ? sk_X509_num(chain) : 0;
		if (count < 2 || static_cast<std::size_t>(count) > MaxCertificateChain)
			return VerificationFailure();
		try {
			std::vector<CryptoX509::Certificate> certificates;
			certificates.reserve(static_cast<std::size_t>(count));
			std::size_t total_der_size = 0;
			for (int index = 0; index < count; ++index) {
				auto* certificate = static_cast<::X509*>(OPENSSL_sk_value(
					reinterpret_cast<const OPENSSL_STACK*>(chain), index));
				const int der_size = i2d_X509(certificate, nullptr);
				if (der_size <= 0
					|| static_cast<std::size_t>(der_size) > MaxCertificateList - total_der_size)
					return VerificationFailure();
				total_der_size += static_cast<std::size_t>(der_size);
				std::vector<unsigned char> der(static_cast<std::size_t>(der_size));
				unsigned char* cursor = der.data();
				if (i2d_X509(certificate, &cursor) != der_size)
					return VerificationFailure();
				CryptoX509::Certificate parsed;
				const auto bytes = std::as_bytes(std::span(der));
				if (!CryptoX509::Certificate::Parse(bytes, parsed))
					return VerificationFailure();
				certificates.emplace_back(std::move(parsed));
			}
			const auto* leaf = &certificates.front();
			const auto* anchor = &certificates.back();
			const std::span<const CryptoX509::Certificate> intermediates(
				certificates.data() + 1, certificates.size() - 2);
			if (role == Role::Client) {
				if (trust_source == TrustSource::Bundled) {
					const auto path = CryptoX509::ValidateBundledTLSPath(*leaf, intermediates,
						validation_time, identity);
					if (!path)
						return VerificationFailure();
				} else {
					const auto admitted = std::ranges::any_of(anchors,
						[anchor](const CryptoX509::Certificate& candidate) { return candidate == *anchor; });
					if (!admitted || !CryptoX509::ValidateCustomCATLSPath(*leaf, intermediates,
						*anchor, validation_time, identity))
						return VerificationFailure();
				}
				if (require_revocation && !VerifyRevocation(certificates))
					return VerificationFailure();
			} else {
				const auto admitted = std::ranges::any_of(anchors,
					[anchor](const CryptoX509::Certificate& candidate) { return candidate == *anchor; });
				if (!admitted || !CryptoX509::TLSPeerVerifier::Verify(*leaf, intermediates,
					*anchor, validation_time, CryptoX509::TLSRole::Client, nullptr))
					return VerificationFailure();
			}
			return true;
		} catch (...) {
			return VerificationFailure();
		}
	}

	bool VerifyRevocation(const std::vector<CryptoX509::Certificate>& certificates) {
		if (evidence.size() != certificates.size() - 1)
			return false;
		for (std::size_t index = 0; index + 1 < certificates.size(); ++index) {
			const auto der = evidence[index].der.span();
			const auto result = CryptoX509::RevocationVerifier::Verify(certificates[index],
				certificates[index + 1], evidence[index].format, der, validation_time);
			if (!result || *result != CryptoX509::RevocationStatus::Good)
				return false;
		}
		return true;
	}

	bool VerificationFailure() noexcept {
		verification_failed = true;
		return false;
	}

	bool Initialize(Role endpoint_role, const Configuration& policy) {
		role = endpoint_role;
		if (!ConfigurePolicy(context, policy))
			return Fail(SessionError::UnsupportedPolicy);
		SSL_CTX_set_verify(context, endpoint_role == Role::Client ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
			nullptr);
		SSL_CTX_set_cert_verify_callback(context, VerifyCallback, nullptr);
		return true;
	}

	bool InitializeSSL() {
		ssl = SSL_new(context);
		if (!ssl)
			return Fail(SessionError::BackendFailure);
		SSL_set_app_data(ssl, this);
		BIO* input_bio = BIO_new(BIO_s_mem());
		BIO* output_bio = BIO_new(BIO_s_mem());
		if (!input_bio || !output_bio) {
			BIO_free(input_bio);
			BIO_free(output_bio);
			return Fail(SessionError::BackendFailure);
		}
		input = input_bio;
		output = output_bio;
		BIO_set_mem_eof_return(input, -1);
		SSL_set_bio(ssl, input, output);
		SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
		const auto previous_maximum = SSL_set_max_cert_list(ssl, MaxCertificateList);
		if (previous_maximum <= 0
			|| SSL_get_max_cert_list(ssl) != static_cast<long>(MaxCertificateList))
			return Fail(SessionError::BackendFailure);
		return true;
	}

	bool SetVerificationTime(CryptoX509::TimePoint at) {
		const auto time = std::chrono::system_clock::to_time_t(at);
		X509_VERIFY_PARAM* parameters = SSL_CTX_get0_param(context);
		if (!parameters)
			return false;
		X509_VERIFY_PARAM_set_depth(parameters, static_cast<int>(MaxCertificateChain));
		X509_VERIFY_PARAM_set_time(parameters, time);
		return true;
	}

	bool AddClientIdentity(std::span<const std::byte> certificate_pem,
		std::span<const std::byte> key_pem, std::span<const std::byte> password) {
		if (certificate_pem.empty() && key_pem.empty())
			return true;
		if (certificate_pem.empty() || key_pem.empty())
			return false;
		return AddCertificateChain(context, certificate_pem)
			&& AddPrivateKey(context, key_pem, password);
	}

	bool ConfigureClient(const ClientConfiguration& configuration) {
		if (!Initialize(Role::Client, configuration.policy))
			return false;
		if (configuration.identity.Value().empty())
			return Fail(SessionError::InvalidConfiguration);
		identity = configuration.identity;
		validation_time = configuration.validation_time;
		trust_source = configuration.trust_source;
		require_revocation = configuration.require_revocation;
		if (trust_source == TrustSource::Bundled) {
			if (!configuration.trust_anchors.empty())
				return Fail(SessionError::InvalidConfiguration);
			auto roots = CryptoX509::LoadBundledTLSRoots();
			if (!roots)
				return Fail(SessionError::InvalidConfiguration);
			anchors.assign(roots->begin(), roots->end());
		} else if (trust_source == TrustSource::Custom) {
			if (!AddTrustAnchors(context, configuration.trust_anchors))
				return Fail(SessionError::InvalidConfiguration);
			anchors.assign(configuration.trust_anchors.begin(), configuration.trust_anchors.end());
		} else {
			return Fail(SessionError::InvalidConfiguration);
		}
		if (!SetVerificationTime(validation_time))
			return Fail(SessionError::InvalidConfiguration);
		if (require_revocation) {
			if (configuration.revocation_evidence.size() > MaxCertificateChain)
				return Fail(SessionError::InvalidConfiguration);
			evidence.reserve(configuration.revocation_evidence.size());
			std::size_t evidence_size = 0;
			for (const auto& item : configuration.revocation_evidence) {
				if (item.der.empty() || item.der.size() > MaxRevocationEvidence - evidence_size)
					return Fail(SessionError::InvalidConfiguration);
				evidence_size += item.der.size();
				evidence.push_back({item.format, StormByte::Safe::Binary(item.der)});
			}
		} else if (!configuration.revocation_evidence.empty()) {
			return Fail(SessionError::InvalidConfiguration);
		}
		if (!AddClientIdentity(configuration.certificate_chain_pem,
			configuration.private_key_pem, configuration.private_key_password))
			return Fail(SessionError::InvalidConfiguration);
		if (!ValidALPN(configuration.alpn_wire)
			|| configuration.alpn_wire.size() > USHRT_MAX)
			return Fail(SessionError::InvalidConfiguration);
		if (!InitializeSSL())
			return false;
		if (!configuration.alpn_wire.empty()
			&& SSL_set_alpn_protos(ssl,
				reinterpret_cast<const unsigned char*>(configuration.alpn_wire.data()),
				static_cast<unsigned int>(configuration.alpn_wire.size())) != 0)
			return Fail(SessionError::InvalidConfiguration);
		if (identity.Type() == CryptoX509::SubjectAltNameType::DNS) {
			const auto bytes = identity.Value().span();
			const std::string hostname(reinterpret_cast<const char*>(bytes.data()), bytes.size());
			if (hostname.empty() || hostname.find('\0') != std::string::npos
				|| SSL_set_tlsext_host_name(ssl, hostname.c_str()) != 1)
				return Fail(SessionError::InvalidConfiguration);
		} else if (identity.Type() != CryptoX509::SubjectAltNameType::IP) {
			return Fail(SessionError::InvalidConfiguration);
		}
		SSL_set_connect_state(ssl);
		return AdvanceHandshake();
	}

	bool ConfigureServer(const ServerConfiguration& configuration) {
		if (!Initialize(Role::Server, configuration.policy))
			return false;
		const bool chain = AddCertificateChain(context, configuration.certificate_chain_pem);
		const bool key = AddPrivateKey(context, configuration.private_key_pem,
			configuration.private_key_password);
		if (!chain || !key)
			return Fail(SessionError::InvalidConfiguration);
		if (!ValidALPN(configuration.alpn_wire)
			|| configuration.alpn_wire.size() > USHRT_MAX)
			return Fail(SessionError::InvalidConfiguration);
		if (!configuration.alpn_wire.empty()) {
			server_alpn.assign(
				reinterpret_cast<const unsigned char*>(configuration.alpn_wire.data()),
				reinterpret_cast<const unsigned char*>(configuration.alpn_wire.data())
					+ configuration.alpn_wire.size());
			SSL_CTX_set_alpn_select_cb(context, SelectALPN, nullptr);
		}
		if (configuration.require_client_certificate) {
			if (!AddTrustAnchors(context, configuration.client_trust_anchors))
				return Fail(SessionError::InvalidConfiguration);
			anchors.assign(configuration.client_trust_anchors.begin(),
				configuration.client_trust_anchors.end());
			validation_time = configuration.validation_time;
			if (!SetVerificationTime(validation_time))
				return Fail(SessionError::InvalidConfiguration);
			SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
		} else if (!configuration.client_trust_anchors.empty()) {
			return Fail(SessionError::InvalidConfiguration);
		}
		if (!InitializeSSL())
			return false;
		SSL_set_accept_state(ssl);
		return true;
	}

	bool AdvanceHandshake() noexcept {
		if (state != State::Handshaking)
			return state == State::Open || state == State::Closing;
		ERR_clear_error();
		const int result = SSL_do_handshake(ssl);
		if (result == 1) {
			state = State::Open;
			return true;
		}
		const int ssl_error = SSL_get_error(ssl, result);
		if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
			return true;
		return Fail(verification_failed ? SessionError::PeerRejected : SessionError::BackendFailure);
	}

	SessionError HandleFailure(int result) noexcept {
		const int ssl_error = SSL_get_error(ssl, result);
		if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE
			|| ssl_error == SSL_ERROR_ZERO_RETURN)
			return SessionError::InvalidState;
		return verification_failed ? SessionError::PeerRejected : SessionError::BackendFailure;
	}
};

using namespace StormByte::Crypto::TLS;

Session::Session() noexcept = default;

Session::Session(std::unique_ptr<Impl> impl) noexcept:
	m_impl(std::move(impl)) {}

Session::Session(Session&& other) noexcept = default;

Session::~Session() noexcept = default;

Session& Session::operator=(Session&& other) noexcept = default;

StormByte::Expected<Session, SessionError> Session::CreateClient(const ClientConfiguration& configuration) {
	auto impl = std::make_unique<Impl>();
	impl->context = SSL_CTX_new(TLS_method());
	if (!impl->context)
		return StormByte::Unexpected(SessionError::BackendFailure);
	if (!impl->ConfigureClient(configuration))
		return StormByte::Unexpected(impl->failure);
	return Session(std::move(impl));
}

StormByte::Expected<Session, SessionError> Session::CreateServer(const ServerConfiguration& configuration) {
	auto impl = std::make_unique<Impl>();
	impl->context = SSL_CTX_new(TLS_method());
	if (!impl->context)
		return StormByte::Unexpected(SessionError::BackendFailure);
	if (!impl->ConfigureServer(configuration))
		return StormByte::Unexpected(impl->failure);
	return Session(std::move(impl));
}

StormByte::Expected<std::size_t, SessionError> Session::FeedEncrypted(std::span<const std::byte> encrypted) {
	if (!m_impl)
		return StormByte::Unexpected(SessionError::InvalidState);
	if (m_impl->state == State::Failed)
		return StormByte::Unexpected(m_impl->failure);
	if (m_impl->state == State::Closed)
		return StormByte::Unexpected(SessionError::InvalidState);
	if (encrypted.empty())
		return std::size_t{0};
	const auto pending = BIO_ctrl_pending(m_impl->input);
	if (pending >= MaxPendingCiphertext)
		return std::size_t{0};
	const auto count = std::min({encrypted.size(), MaxInputChunk,
		MaxPendingCiphertext - pending, static_cast<std::size_t>(INT_MAX)});
	const int accepted = BIO_write(m_impl->input, encrypted.data(), static_cast<int>(count));
	if (accepted <= 0)
		return std::size_t{0};
	if (m_impl->state == State::Handshaking && !m_impl->AdvanceHandshake())
		return StormByte::Unexpected(m_impl->failure);
	if (m_impl->state == State::Closing) {
		const auto shutdown = Shutdown();
		if (!shutdown)
			return StormByte::Unexpected(*shutdown.error());
	}
	return static_cast<std::size_t>(accepted);
}

StormByte::Expected<std::size_t, SessionError> Session::DrainEncrypted(std::span<std::byte> output) {
	if (!m_impl)
		return StormByte::Unexpected(SessionError::InvalidState);
	if (output.empty())
		return std::size_t{0};
	const auto available = BIO_ctrl_pending(m_impl->output);
	if (available == 0)
		return std::size_t{0};
	const auto count = std::min({available, output.size(), static_cast<std::size_t>(INT_MAX)});
	const int read = BIO_read(m_impl->output, output.data(), static_cast<int>(count));
	if (read < 0)
		return StormByte::Unexpected(SessionError::BackendFailure);
	return static_cast<std::size_t>(read);
}

StormByte::Expected<std::size_t, SessionError> Session::WritePlaintext(std::span<const std::byte> plaintext) {
	if (!m_impl)
		return StormByte::Unexpected(SessionError::InvalidState);
	if (m_impl->state == State::Failed)
		return StormByte::Unexpected(m_impl->failure);
	if (m_impl->state != State::Open)
		return StormByte::Unexpected(SessionError::InvalidState);
	if (plaintext.empty())
		return std::size_t{0};
	const auto pending = BIO_ctrl_pending(m_impl->output);
	constexpr std::size_t RecordOverhead = 2048;
	if (pending + RecordOverhead >= MaxPendingCiphertext)
		return std::size_t{0};
	const auto count = std::min({plaintext.size(), MaxPlaintextRecord,
		MaxPendingCiphertext - pending - RecordOverhead});
	std::size_t written = 0;
	ERR_clear_error();
	if (SSL_write_ex(m_impl->ssl, plaintext.data(), count, &written) == 1)
		return written;
	const auto error = m_impl->HandleFailure(0);
	if (error == SessionError::InvalidState)
		return std::size_t{0};
	m_impl->Fail(error);
	return StormByte::Unexpected(error);
}

StormByte::Expected<std::size_t, SessionError> Session::ReadPlaintext(std::span<std::byte> output) {
	if (!m_impl)
		return StormByte::Unexpected(SessionError::InvalidState);
	if (m_impl->state == State::Failed)
		return StormByte::Unexpected(m_impl->failure);
	if (m_impl->state == State::Handshaking)
		return StormByte::Unexpected(SessionError::InvalidState);
	if (output.empty())
		return std::size_t{0};
	std::size_t read = 0;
	ERR_clear_error();
	if (SSL_read_ex(m_impl->ssl, output.data(),
		std::min(output.size(), MaxPlaintextRecord), &read) == 1)
		return read;
	const int ssl_error = SSL_get_error(m_impl->ssl, 0);
	if (ssl_error == SSL_ERROR_ZERO_RETURN) {
		const auto shutdown = Shutdown();
		if (!shutdown)
			return StormByte::Unexpected(*shutdown.error());
		return std::size_t{0};
	}
	if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
		return std::size_t{0};
	const auto error = m_impl->verification_failed ? SessionError::PeerRejected : SessionError::BackendFailure;
	m_impl->Fail(error);
	return StormByte::Unexpected(error);
}

StormByte::Expected<void, SessionError> Session::Shutdown() {
	if (!m_impl)
		return StormByte::Unexpected(SessionError::InvalidState);
	if (m_impl->state == State::Failed)
		return StormByte::Unexpected(m_impl->failure);
	if (m_impl->state == State::Closed)
		return {};
	if (m_impl->state == State::Handshaking)
		return StormByte::Unexpected(SessionError::InvalidState);
	ERR_clear_error();
	const int result = SSL_shutdown(m_impl->ssl);
	if (result == 1) {
		m_impl->state = State::Closed;
		return {};
	}
	if (result == 0) {
		m_impl->state = State::Closing;
		return {};
	}
	const int ssl_error = SSL_get_error(m_impl->ssl, result);
	if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
		m_impl->state = State::Closing;
		return {};
	}
	const auto error = m_impl->HandleFailure(result);
	m_impl->Fail(error == SessionError::InvalidState ? SessionError::BackendFailure : error);
	return StormByte::Unexpected(m_impl->failure);
}

State Session::Status() const noexcept {
	return m_impl ? m_impl->state : State::Failed;
}
SessionError Session::Failure() const noexcept {
	return m_impl ? m_impl->failure : SessionError::BackendFailure;
}

bool Session::HandshakeComplete() const noexcept {
	return m_impl && SSL_is_init_finished(m_impl->ssl) == 1
		&& (m_impl->state == State::Open || m_impl->state == State::Closing
			|| m_impl->state == State::Closed);
}

std::string_view Session::NegotiatedALPN() const noexcept {
	if (!m_impl || !SSL_is_init_finished(m_impl->ssl))
		return {};
	const unsigned char* protocol = nullptr;
	unsigned int length = 0;
	SSL_get0_alpn_selected(m_impl->ssl, &protocol, &length);
	if (!protocol || length == 0)
		return {};
	return {reinterpret_cast<const char*>(protocol), length};
}
