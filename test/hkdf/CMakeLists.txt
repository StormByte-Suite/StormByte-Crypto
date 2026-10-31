add_executable(HKDFTests hkdf_test.cxx)
target_link_libraries(HKDFTests StormByte::Crypto tests)
add_test(NAME HKDFTests COMMAND HKDFTests)
set_tests_properties(HKDFTests PROPERTIES LABELS "security")
