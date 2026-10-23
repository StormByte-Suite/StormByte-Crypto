add_executable(RandomTests random_test.cxx)
target_link_libraries(RandomTests StormByte::Crypto tests)
add_test(NAME Random COMMAND RandomTests)
set_tests_properties(Random PROPERTIES LABELS "security")

add_executable(RandomProviderTests
	random_provider_test.cxx
	${PROJECT_SOURCE_DIR}/lib/public/StormByte/crypto/exception.cxx
	${PROJECT_SOURCE_DIR}/lib/public/StormByte/crypto/random.cxx
)
target_include_directories(RandomProviderTests PRIVATE
	${PROJECT_SOURCE_DIR}/lib/public
	${PROJECT_SOURCE_DIR}/lib/private
)
target_link_libraries(RandomProviderTests StormByte-Base CryptoPP::CryptoPP tests)
add_test(NAME RandomProvider COMMAND RandomProviderTests)
set_tests_properties(RandomProvider PROPERTIES LABELS "security")
