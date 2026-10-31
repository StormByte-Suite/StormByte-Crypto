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
