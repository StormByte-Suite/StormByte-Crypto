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
#include <StormByte/test_handlers.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace CryptoX509 = StormByte::Crypto::X509;
namespace TLS = StormByte::Crypto::TLS;

namespace {
	using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
	using Certificate = std::unique_ptr<::X509, decltype(&X509_free)>;
	using Bio = std::unique_ptr<BIO, decltype(&BIO_free)>;

	constexpr std::array ServerALPN{
		std::byte{8}, std::byte{'h'}, std::byte{'t'}, std::byte{'t'}, std::byte{'p'},
		std::byte{'/'}, std::byte{'1'}, std::byte{'.'}, std::byte{'1'}
	};

	struct Fixtures {
		Key root_key{nullptr, EVP_PKEY_free};
		Key server_key{nullptr, EVP_PKEY_free};
		Key client_key{nullptr, EVP_PKEY_free};
		Certificate root{nullptr, X509_free};
		Certificate server{nullptr, X509_free};
		Certificate client{nullptr, X509_free};
		CryptoX509::Certificate parsed_root;
		std::vector<std::byte> server_pem;
		std::vector<std::byte> server_key_pem;
		std::vector<std::byte> client_pem;
		std::vector<std::byte> client_key_pem;
	};

	std::vector<std::byte> BufferBytes(BIO* bio) {
		char* data = nullptr;
		const long length = BIO_get_mem_data(bio, &data);
		if (length <= 0)
			return {};
		const auto* first = reinterpret_cast<const std::byte*>(data);
		return {first, first + length};
	}

	Key MakeRSAKey() {
		EVP_PKEY_CTX* raw_context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
		if (!raw_context)
			return {nullptr, EVP_PKEY_free};
		std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(raw_context,
			EVP_PKEY_CTX_free);
		EVP_PKEY* raw_key = nullptr;
		if (EVP_PKEY_keygen_init(context.get()) <= 0
			|| EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), 2048) <= 0
			|| EVP_PKEY_keygen(context.get(), &raw_key) <= 0)
			return {nullptr, EVP_PKEY_free};
		return {raw_key, EVP_PKEY_free};
	}

	bool AddExtension(::X509* certificate, ::X509* issuer, int nid, const char* value) {
		X509V3_CTX context{};
		X509V3_set_ctx(&context, issuer, certificate, nullptr, nullptr, 0);
		auto* extension = X509V3_EXT_conf_nid(nullptr, &context, nid,
			const_cast<char*>(value));
		if (!extension)
			return false;
		const bool result = X509_add_ext(certificate, extension, -1) == 1;
		X509_EXTENSION_free(extension);
		return result;
	}

	Certificate MakeCertificate(EVP_PKEY* public_key, const char* common_name,
		::X509* issuer, EVP_PKEY* issuer_key, long serial, bool is_ca,
		const char* extended_key_usage = "serverAuth",
		const char* subject_alt_name = "DNS:localhost") {
		Certificate certificate(X509_new(), X509_free);
		if (!certificate || X509_set_version(certificate.get(), 2) != 1
			|| ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), serial) != 1
			|| !X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -3600)
			|| !X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 86400L * 3650)
			|| X509_set_pubkey(certificate.get(), public_key) != 1)
			return {nullptr, X509_free};

		X509_NAME* subject = X509_get_subject_name(certificate.get());
		if (!subject || X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
			reinterpret_cast<const unsigned char*>(common_name), -1, -1, 0) != 1)
			return {nullptr, X509_free};
		if (X509_set_issuer_name(certificate.get(),
			issuer ? X509_get_subject_name(issuer) : subject) != 1)
			return {nullptr, X509_free};

		if (!AddExtension(certificate.get(), issuer ? issuer : certificate.get(),
				NID_basic_constraints, is_ca ? "critical,CA:TRUE,pathlen:1" : "critical,CA:FALSE")
			|| !AddExtension(certificate.get(), issuer ? issuer : certificate.get(),
				NID_key_usage, is_ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature")
			|| !AddExtension(certificate.get(), issuer ? issuer : certificate.get(),
				NID_subject_key_identifier, "hash"))
			return {nullptr, X509_free};
		if (!is_ca) {
			if (!AddExtension(certificate.get(), issuer, NID_ext_key_usage, extended_key_usage)
				|| (subject_alt_name && !AddExtension(certificate.get(), issuer,
					NID_subject_alt_name, subject_alt_name)))
				return {nullptr, X509_free};
		}
		if (issuer && !AddExtension(certificate.get(), issuer,
			NID_authority_key_identifier, "keyid:always"))
			return {nullptr, X509_free};
		if (X509_sign(certificate.get(), issuer_key, EVP_sha256()) <= 0)
			return {nullptr, X509_free};
		return certificate;
	}

	std::vector<std::byte> CertificatePEM(::X509* certificate) {
		Bio bio(BIO_new(BIO_s_mem()), BIO_free);
		if (!bio || PEM_write_bio_X509(bio.get(), certificate) != 1)
			return {};
		return BufferBytes(bio.get());
	}

	std::vector<std::byte> PrivateKeyPEM(EVP_PKEY* key) {
		Bio bio(BIO_new(BIO_s_mem()), BIO_free);
		if (!bio || PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0,
			nullptr, nullptr) != 1)
			return {};
		return BufferBytes(bio.get());
	}

	bool ParseCertificate(::X509* source, CryptoX509::Certificate& output) {
		const int size = i2d_X509(source, nullptr);
		if (size <= 0)
			return false;
		std::vector<unsigned char> der(static_cast<std::size_t>(size));
		unsigned char* cursor = der.data();
		if (i2d_X509(source, &cursor) != size)
			return false;
		return CryptoX509::Certificate::Parse(std::as_bytes(std::span(der)), output);
	}

	Fixtures MakeFixtures() {
		Fixtures result;
		result.root_key = MakeRSAKey();
		result.server_key = MakeRSAKey();
		result.client_key = MakeRSAKey();
		if (!result.root_key || !result.server_key || !result.client_key)
			return result;
		result.root = MakeCertificate(result.root_key.get(), "StormByte TLS Test Root",
			nullptr, result.root_key.get(), 1, true);
		if (!result.root)
			return result;
		result.server = MakeCertificate(result.server_key.get(), "localhost",
			result.root.get(), result.root_key.get(), 2, false);
		result.client = MakeCertificate(result.client_key.get(), "StormByte TLS Test Client",
			result.root.get(), result.root_key.get(), 3, false, "clientAuth", nullptr);
		if (!result.server || !ParseCertificate(result.root.get(), result.parsed_root))
			return result;
		if (!result.client)
			return result;
		result.server_pem = CertificatePEM(result.server.get());
		result.server_key_pem = PrivateKeyPEM(result.server_key.get());
		result.client_pem = CertificatePEM(result.client.get());
		result.client_key_pem = PrivateKeyPEM(result.client_key.get());
		return result;
	}

	TLS::ClientConfiguration ClientConfig(const Fixtures& fixtures, std::string_view identity) {
		TLS::ClientConfiguration configuration;
		configuration.identity = CryptoX509::SubjectAltName(
			CryptoX509::SubjectAltNameType::DNS,
			StormByte::Safe::Binary(std::as_bytes(std::span(identity.data(), identity.size()))));
		configuration.trust_source = TLS::TrustSource::Custom;
		configuration.trust_anchors = std::span(&fixtures.parsed_root, 1);
		configuration.validation_time = std::chrono::floor<std::chrono::seconds>(
			std::chrono::system_clock::now());
		configuration.policy.signature_schemes = {TLS::SignatureScheme::RSA_PSS_RSAE_SHA256};
		configuration.alpn_wire = ServerALPN;
		return configuration;
	}

	TLS::ServerConfiguration ServerConfig(const Fixtures& fixtures, bool require_client = false) {
		TLS::ServerConfiguration configuration;
		configuration.certificate_chain_pem = fixtures.server_pem;
		configuration.private_key_pem = fixtures.server_key_pem;
		configuration.validation_time = std::chrono::floor<std::chrono::seconds>(
			std::chrono::system_clock::now());
		configuration.policy.signature_schemes = {TLS::SignatureScheme::RSA_PSS_RSAE_SHA256};
		configuration.alpn_wire = ServerALPN;
		if (require_client) {
			configuration.require_client_certificate = true;
			configuration.client_trust_anchors = std::span(&fixtures.parsed_root, 1);
		}
		return configuration;
	}

	void AddClientCertificate(const Fixtures& fixtures, TLS::ClientConfiguration& configuration) {
		configuration.certificate_chain_pem = fixtures.client_pem;
		configuration.private_key_pem = fixtures.client_key_pem;
	}

	bool Pump(TLS::Session& source, TLS::Session& destination) {
		std::array<std::byte, 37> wire{};
		while (true) {
			const auto drained = source.DrainEncrypted(wire);
			if (!drained)
				return false;
			if (*drained == 0)
				return true;
			std::size_t offset = 0;
			while (offset < *drained) {
				const auto fed = destination.FeedEncrypted(
					std::span<const std::byte>(wire).subspan(offset, *drained - offset));
				if (!fed)
					return false;
				if (*fed == 0)
					return false;
				offset += *fed;
			}
		}
	}

	bool CompleteHandshake(TLS::Session& client, TLS::Session& server) {
		for (std::size_t attempt = 0; attempt < 1000; ++attempt) {
			Pump(client, server);
			Pump(server, client);
			if (client.HandshakeComplete() && server.HandshakeComplete())
				return true;
			if (client.Status() == TLS::State::Failed || server.Status() == TLS::State::Failed)
				return false;
		}
		return false;
	}
}

int test_buffer_driven_tls13_rsa_pss_alpn_and_bidirectional_data() {
	auto fixtures = MakeFixtures();
	ASSERT_TRUE(fixtures.root);
	ASSERT_TRUE(fixtures.server);
	ASSERT_TRUE(fixtures.parsed_root.Der().size() > 0);
	ASSERT_TRUE(!fixtures.server_pem.empty() && !fixtures.server_key_pem.empty());

	auto client_result = TLS::Session::CreateClient(ClientConfig(fixtures, "localhost"));
	auto server_result = TLS::Session::CreateServer(ServerConfig(fixtures));
	ASSERT_TRUE(client_result && server_result);
	auto client = std::move(*client_result);
	auto server = std::move(*server_result);
	const bool complete = CompleteHandshake(client, server);
	ASSERT_TRUE(complete);
	ASSERT_TRUE(client.Status() == TLS::State::Open);
	ASSERT_TRUE(server.Status() == TLS::State::Open);
	ASSERT_TRUE(client.NegotiatedALPN() == "http/1.1");

	constexpr std::string_view outgoing = "client-to-server";
	const auto sent = client.WritePlaintext(
		std::as_bytes(std::span(outgoing.data(), outgoing.size())));
	ASSERT_TRUE(sent && *sent == outgoing.size());
	ASSERT_TRUE(Pump(client, server));
	std::array<std::byte, 64> plaintext{};
	auto received = server.ReadPlaintext(plaintext);
	ASSERT_TRUE(received && *received == outgoing.size());
	ASSERT_TRUE(std::memcmp(plaintext.data(), outgoing.data(), outgoing.size()) == 0);

	constexpr std::string_view reply = "server-to-client";
	const auto response = server.WritePlaintext(
		std::as_bytes(std::span(reply.data(), reply.size())));
	ASSERT_TRUE(response && *response == reply.size());
	ASSERT_TRUE(Pump(server, client));
	received = client.ReadPlaintext(plaintext);
	ASSERT_TRUE(received && *received == reply.size());
	ASSERT_TRUE(std::memcmp(plaintext.data(), reply.data(), reply.size()) == 0);

	ASSERT_TRUE(client.Shutdown());
	ASSERT_TRUE(Pump(client, server));
	received = server.ReadPlaintext(plaintext);
	ASSERT_TRUE(received && *received == 0);
	ASSERT_TRUE(server.Status() == TLS::State::Closed);
	ASSERT_TRUE(Pump(server, client));
	ASSERT_TRUE(client.Status() == TLS::State::Closed);
	ASSERT_TRUE(server.Status() == TLS::State::Closed);
	ASSERT_TRUE(server.Shutdown());
	ASSERT_TRUE(server.Status() == TLS::State::Closed);
	RETURN_TEST(0);
}

int test_tls_rejects_wrong_identity_and_missing_revocation_evidence() {
	auto fixtures = MakeFixtures();
	ASSERT_TRUE(fixtures.parsed_root.Der().size() > 0);
	auto server_result = TLS::Session::CreateServer(ServerConfig(fixtures));
	ASSERT_TRUE(server_result);
	auto server = std::move(*server_result);

	auto wrong_name_config = ClientConfig(fixtures, "not-localhost.example");
	auto wrong_name_result = TLS::Session::CreateClient(wrong_name_config);
	ASSERT_TRUE(wrong_name_result);
	auto wrong_name = std::move(*wrong_name_result);
	CompleteHandshake(wrong_name, server);
	ASSERT_TRUE(wrong_name.Status() == TLS::State::Failed);
	ASSERT_TRUE(wrong_name.Failure() == TLS::SessionError::PeerRejected);

	server_result = TLS::Session::CreateServer(ServerConfig(fixtures));
	ASSERT_TRUE(server_result);
	server = std::move(*server_result);
	auto revocation_config = ClientConfig(fixtures, "localhost");
	revocation_config.require_revocation = true;
	auto revocation_result = TLS::Session::CreateClient(revocation_config);
	ASSERT_TRUE(revocation_result);
	auto revocation_client = std::move(*revocation_result);
	CompleteHandshake(revocation_client, server);
	ASSERT_TRUE(revocation_client.Status() == TLS::State::Failed);
	ASSERT_TRUE(revocation_client.Failure() == TLS::SessionError::PeerRejected);
	RETURN_TEST(0);
}

int test_tls_rejects_invalid_policy_and_protocol_configuration() {
	auto fixtures = MakeFixtures();
	ASSERT_TRUE(fixtures.parsed_root.Der().size() > 0);
	auto configuration = ClientConfig(fixtures, "localhost");
	configuration.policy.cipher_suites.clear();
	auto invalid_policy = TLS::Session::CreateClient(configuration);
	ASSERT_FALSE(invalid_policy);
	ASSERT_TRUE(*invalid_policy.error() == TLS::SessionError::UnsupportedPolicy);

	configuration = ClientConfig(fixtures, "localhost");
	constexpr std::array invalid_alpn{std::byte{0}};
	configuration.alpn_wire = invalid_alpn;
	auto malformed_protocol = TLS::Session::CreateClient(configuration);
	ASSERT_FALSE(malformed_protocol);
	ASSERT_TRUE(*malformed_protocol.error() == TLS::SessionError::InvalidConfiguration);

	TLS::ClientConfiguration custom_without_anchors;
	custom_without_anchors.identity = ClientConfig(fixtures, "localhost").identity;
	custom_without_anchors.trust_source = TLS::TrustSource::Custom;
	auto missing_trust = TLS::Session::CreateClient(custom_without_anchors);
	ASSERT_FALSE(missing_trust);
	ASSERT_TRUE(*missing_trust.error() == TLS::SessionError::InvalidConfiguration);
	RETURN_TEST(0);
}

int test_mutual_tls_validates_client_certificate() {
	auto fixtures = MakeFixtures();
	ASSERT_TRUE(fixtures.parsed_root.Der().size() > 0);
	auto client_configuration = ClientConfig(fixtures, "localhost");
	AddClientCertificate(fixtures, client_configuration);
	auto client_result = TLS::Session::CreateClient(client_configuration);
	auto server_result = TLS::Session::CreateServer(ServerConfig(fixtures, true));
	ASSERT_TRUE(client_result && server_result);
	auto client = std::move(*client_result);
	auto server = std::move(*server_result);
	ASSERT_TRUE(CompleteHandshake(client, server));
	ASSERT_TRUE(client.Status() == TLS::State::Open);
	ASSERT_TRUE(server.Status() == TLS::State::Open);
	RETURN_TEST(0);
}

int test_tls_without_alpn_reports_empty_protocol() {
	auto fixtures = MakeFixtures();
	auto client_configuration = ClientConfig(fixtures, "localhost");
	client_configuration.alpn_wire = {};
	auto server_configuration = ServerConfig(fixtures);
	server_configuration.alpn_wire = {};
	auto client_result = TLS::Session::CreateClient(client_configuration);
	auto server_result = TLS::Session::CreateServer(server_configuration);
	ASSERT_TRUE(client_result && server_result);
	auto client = std::move(*client_result);
	auto server = std::move(*server_result);
	ASSERT_TRUE(CompleteHandshake(client, server));
	ASSERT_TRUE(client.NegotiatedALPN().empty());
	ASSERT_TRUE(server.NegotiatedALPN().empty());
	RETURN_TEST(0);
}

int test_ciphertext_backpressure_and_alert_drain_after_failure() {
	auto fixtures = MakeFixtures();
	auto client_result = TLS::Session::CreateClient(ClientConfig(fixtures, "localhost"));
	auto server_result = TLS::Session::CreateServer(ServerConfig(fixtures));
	ASSERT_TRUE(client_result && server_result);
	auto client = std::move(*client_result);
	auto server = std::move(*server_result);
	ASSERT_TRUE(CompleteHandshake(client, server));

	std::array<std::byte, 16 * 1024> plaintext{};
	bool backpressure = false;
	for (std::size_t attempt = 0; attempt < 128; ++attempt) {
		const auto written = client.WritePlaintext(plaintext);
		ASSERT_TRUE(written);
		if (*written == 0) {
			backpressure = true;
			break;
		}
		ASSERT_TRUE(*written > 0 && *written <= plaintext.size());
	}
	ASSERT_TRUE(backpressure);
	std::array<std::byte, 4096> encrypted{};
	bool drained = false;
	while (true) {
		const auto count = client.DrainEncrypted(encrypted);
		ASSERT_TRUE(count);
		if (*count == 0)
			break;
		drained = true;
	}
	ASSERT_TRUE(drained);
	const auto resumed = client.WritePlaintext(plaintext);
	ASSERT_TRUE(resumed && *resumed > 0);

	auto broken_server_result = TLS::Session::CreateServer(ServerConfig(fixtures));
	ASSERT_TRUE(broken_server_result);
	auto broken_server = std::move(*broken_server_result);
	constexpr std::array<std::byte, 5> invalid_record{
		std::byte{0}, std::byte{3}, std::byte{3}, std::byte{0}, std::byte{0}
	};
	const auto rejected = broken_server.FeedEncrypted(invalid_record);
	ASSERT_FALSE(rejected);
	ASSERT_TRUE(broken_server.Status() == TLS::State::Failed);
	const auto alert = broken_server.DrainEncrypted(encrypted);
	ASSERT_TRUE(alert && *alert > 0);
	RETURN_TEST(0);
}

int main() {
	int result = 0;
	result += test_buffer_driven_tls13_rsa_pss_alpn_and_bidirectional_data();
	result += test_tls_rejects_wrong_identity_and_missing_revocation_evidence();
	result += test_tls_rejects_invalid_policy_and_protocol_configuration();
	result += test_mutual_tls_validates_client_certificate();
	result += test_tls_without_alpn_reports_empty_protocol();
	result += test_ciphertext_backpressure_and_alert_drain_after_failure();
	if (result == 0)
		std::cout << "All TLS session tests passed!" << std::endl;
	return result;
}
