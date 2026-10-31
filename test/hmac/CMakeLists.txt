add_executable(HMACTests hmac_test.cxx)
target_link_libraries(HMACTests StormByte::Crypto tests)
add_test(NAME HMACTests COMMAND HMACTests)
set_tests_properties(HMACTests PROPERTIES LABELS "security")
