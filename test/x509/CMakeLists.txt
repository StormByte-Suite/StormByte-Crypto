add_executable(X509CertificateTests certificate_test.cxx)
target_link_libraries(X509CertificateTests StormByte::Crypto tests)
add_test(NAME X509CertificateTests COMMAND X509CertificateTests)
set_tests_properties(X509CertificateTests PROPERTIES
	LABELS "x509"
)

add_executable(X509IdentityTests identity_test.cxx)
target_link_libraries(X509IdentityTests StormByte::Crypto tests)
add_test(NAME X509IdentityTests COMMAND X509IdentityTests)
set_tests_properties(X509IdentityTests PROPERTIES
	LABELS "x509;identity"
)

add_executable(X509PurposeTests purpose_test.cxx)
target_link_libraries(X509PurposeTests StormByte::Crypto tests)
add_test(NAME X509PurposeTests COMMAND X509PurposeTests)
set_tests_properties(X509PurposeTests PROPERTIES
	LABELS "x509;purpose"
)

add_executable(X509TLSPeerTests tls_peer_test.cxx)
target_link_libraries(X509TLSPeerTests StormByte::Crypto tests)
add_test(NAME X509TLSPeerTests COMMAND X509TLSPeerTests)
set_tests_properties(X509TLSPeerTests PROPERTIES
	LABELS "x509;tls-peer"
)

add_executable(X509TrustPathTests trust_path_test.cxx)
target_link_libraries(X509TrustPathTests StormByte::Crypto tests)
add_test(NAME X509TrustPathTests COMMAND X509TrustPathTests)
set_tests_properties(X509TrustPathTests PROPERTIES LABELS "x509;trust-path")

add_executable(X509RevocationTests revocation_test.cxx)
target_link_libraries(X509RevocationTests StormByte::Crypto tests)
add_test(NAME X509RevocationTests COMMAND X509RevocationTests)
set_tests_properties(X509RevocationTests PROPERTIES LABELS "x509;revocation")

# Verify that Linux ignores even hostile trust environment settings.
if(NOT WIN32 AND NOT APPLE)
	add_test(NAME X509TrustPathEnvironmentTests COMMAND X509TrustPathTests)
	set_tests_properties(X509TrustPathEnvironmentTests PROPERTIES
		LABELS "x509;trust-path"
		ENVIRONMENT "SSL_CERT_FILE=/nonexistent/stormbyte-roots;SSL_CERT_DIR=/nonexistent/stormbyte-roots;CURL_CA_BUNDLE=/nonexistent/stormbyte-roots")
endif()

if(WIN32 OR APPLE)
	add_executable(X509NativeTrustTests native_trust_test.cxx
		"${PROJECT_SOURCE_DIR}/lib/private/StormByte/crypto/x509/native_trust.cxx")
	target_compile_definitions(X509NativeTrustTests PRIVATE STORMBYTE_CRYPTO_TRUST_TESTING)
	target_link_libraries(X509NativeTrustTests PRIVATE StormByte::Crypto tests)
	if(WIN32)
		target_link_libraries(X509NativeTrustTests PRIVATE crypt32)
	else()
		target_link_libraries(X509NativeTrustTests PRIVATE "-framework Security" "-framework CoreFoundation")
	endif()
	add_test(NAME X509NativeTrustTests COMMAND X509NativeTrustTests)
	set_tests_properties(X509NativeTrustTests PROPERTIES LABELS "x509;trust-path;native" TIMEOUT 60)
endif()
