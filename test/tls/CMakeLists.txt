add_executable(TLSPolicyTests policy_test.cxx)
target_link_libraries(TLSPolicyTests StormByte::Crypto tests)
add_test(NAME TLSPolicyTests COMMAND TLSPolicyTests)
set_tests_properties(TLSPolicyTests PROPERTIES LABELS "tls;policy")

add_executable(TLSSessionTests session_test.cxx)
target_link_libraries(TLSSessionTests PRIVATE StormByte::Crypto tests OpenSSL)
add_test(NAME TLSSessionTests COMMAND TLSSessionTests)
set_tests_properties(TLSSessionTests PROPERTIES LABELS "tls;session" TIMEOUT 60)
