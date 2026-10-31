add_executable(TLSPolicyTests policy_test.cxx)
target_link_libraries(TLSPolicyTests StormByte::Crypto tests)
add_test(NAME TLSPolicyTests COMMAND TLSPolicyTests)
set_tests_properties(TLSPolicyTests PROPERTIES LABELS "tls;policy")
