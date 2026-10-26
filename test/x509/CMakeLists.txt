add_executable(X509CertificateTests certificate_test.cxx)
target_link_libraries(X509CertificateTests StormByte::Crypto tests)
add_test(NAME X509CertificateTests COMMAND X509CertificateTests)
set_tests_properties(X509CertificateTests PROPERTIES
	LABELS "x509"
)
