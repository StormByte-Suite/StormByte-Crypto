# ---------------------------------------------------------------------------
# KeyPair disk I/O fixtures and tests
#
# Separate directories so parallel ctest (-j) cannot race on a shared tree:
#   keys_openssl/           — OpenSSL interop Load fixtures
#   keys_stormbyte_crypto/  — library Generate → Save → Load workspace
#   keys_invalid/           — self-contained garbage Load tests (no fixture)
#
# Generator scripts (configure_file):
#   Unix/macOS: test/scripts/generate-openssl-keypairs_unix.sh.in
#               → ${CMAKE_BINARY_DIR}/test/scripts/generate-openssl-keypairs.sh
#   Windows:    test/scripts/generate-openssl-keypairs_windows.ps1.in
#               → ${CMAKE_BINARY_DIR}/test/scripts/generate-openssl-keypairs.ps1
#
# @KEYPAIR_OPENSSL_DIR@ and @KEYPAIR_TEST_PASS@ are substituted into the script.
# Passphrase is also compiled into tests via STORMBYTE_TEST_KEYS_PASSWORD.
# ---------------------------------------------------------------------------
set(KEYPAIR_OPENSSL_DIR "${CMAKE_BINARY_DIR}/test/keys_openssl")
set(KEYPAIR_SAVE_DIR    "${CMAKE_BINARY_DIR}/test/keys_stormbyte_crypto")
set(KEYPAIR_INVALID_DIR "${CMAKE_BINARY_DIR}/test/keys_invalid")
set(KEYPAIR_TEST_PASS   "StormByteTestPassphrase!")

file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/test/scripts")

if(WIN32)
	set(KEYPAIR_GEN_SCRIPT_IN
		"${CMAKE_SOURCE_DIR}/test/scripts/generate-openssl-keypairs_windows.ps1.in")
	set(KEYPAIR_GEN_SCRIPT
		"${CMAKE_BINARY_DIR}/test/scripts/generate-openssl-keypairs.ps1")
	configure_file("${KEYPAIR_GEN_SCRIPT_IN}" "${KEYPAIR_GEN_SCRIPT}" @ONLY)
	# CMake list → separate argv: powershell.exe, -NoProfile, ...
	set(KEYPAIR_GEN_COMMAND
		powershell.exe
		-NoProfile
		-ExecutionPolicy Bypass
		-File
		"${KEYPAIR_GEN_SCRIPT}"
	)
else()
	set(KEYPAIR_GEN_SCRIPT_IN
		"${CMAKE_SOURCE_DIR}/test/scripts/generate-openssl-keypairs_unix.sh.in")
	set(KEYPAIR_GEN_SCRIPT
		"${CMAKE_BINARY_DIR}/test/scripts/generate-openssl-keypairs.sh")
	configure_file("${KEYPAIR_GEN_SCRIPT_IN}" "${KEYPAIR_GEN_SCRIPT}" @ONLY)
	file(CHMOD "${KEYPAIR_GEN_SCRIPT}"
		PERMISSIONS
			OWNER_READ OWNER_WRITE OWNER_EXECUTE
			GROUP_READ GROUP_EXECUTE
			WORLD_READ WORLD_EXECUTE
	)
	set(KEYPAIR_GEN_COMMAND "${KEYPAIR_GEN_SCRIPT}")
endif()

# --- OpenSSL interop fixture -------------------------------------------------
add_test(
	NAME KeyPairGenerateOpenSslKeys
	COMMAND ${KEYPAIR_GEN_COMMAND}
)
set_tests_properties(KeyPairGenerateOpenSslKeys PROPERTIES
	LABELS "keypair"
	FIXTURES_SETUP KeyPairOpenSslKeys
)

add_test(
	NAME KeyPairCleanupOpenSslKeys
	COMMAND ${CMAKE_COMMAND} -E rm -rf "${KEYPAIR_OPENSSL_DIR}"
)
set_tests_properties(KeyPairCleanupOpenSslKeys PROPERTIES
	LABELS "keypair"
	FIXTURES_CLEANUP KeyPairOpenSslKeys
)

add_executable(KeyPairOpenSSLLoadTests keypair_openssl_load_test.cxx)
target_link_libraries(KeyPairOpenSSLLoadTests StormByte::Crypto tests)
target_compile_definitions(KeyPairOpenSSLLoadTests PRIVATE
	STORMBYTE_TEST_KEYS_DIR="${KEYPAIR_OPENSSL_DIR}"
	STORMBYTE_TEST_KEYS_PASSWORD="${KEYPAIR_TEST_PASS}"
)
add_test(NAME KeyPairOpenSSLLoadTests COMMAND KeyPairOpenSSLLoadTests)
set_tests_properties(KeyPairOpenSSLLoadTests PROPERTIES
	LABELS "keypair"
	FIXTURES_REQUIRED KeyPairOpenSslKeys
)

# --- Save → Load fixture (no OpenSSL; portable dir prepare) ------------------
add_test(
	NAME KeyPairPrepareSaveDir
	COMMAND ${CMAKE_COMMAND} -E rm -rf "${KEYPAIR_SAVE_DIR}"
)
set_tests_properties(KeyPairPrepareSaveDir PROPERTIES
	LABELS "keypair"
	FIXTURES_SETUP KeyPairSaveDir
)

add_test(
	NAME KeyPairPrepareSaveDirMkdir
	COMMAND ${CMAKE_COMMAND} -E make_directory "${KEYPAIR_SAVE_DIR}"
)
set_tests_properties(KeyPairPrepareSaveDirMkdir PROPERTIES
	LABELS "keypair"
	FIXTURES_SETUP KeyPairSaveDir
	DEPENDS KeyPairPrepareSaveDir
)

add_test(
	NAME KeyPairCleanupSaveDir
	COMMAND ${CMAKE_COMMAND} -E rm -rf "${KEYPAIR_SAVE_DIR}"
)
set_tests_properties(KeyPairCleanupSaveDir PROPERTIES
	LABELS "keypair"
	FIXTURES_CLEANUP KeyPairSaveDir
)

add_executable(KeyPairSaveThenLoadTests keypair_save_then_load_test.cxx)
target_link_libraries(KeyPairSaveThenLoadTests StormByte::Crypto tests)
target_compile_definitions(KeyPairSaveThenLoadTests PRIVATE
	STORMBYTE_TEST_KEYS_DIR="${KEYPAIR_SAVE_DIR}"
	STORMBYTE_TEST_KEYS_PASSWORD="${KEYPAIR_TEST_PASS}"
)
add_test(NAME KeyPairSaveThenLoadTests COMMAND KeyPairSaveThenLoadTests)
set_tests_properties(KeyPairSaveThenLoadTests PROPERTIES
	LABELS "keypair"
	FIXTURES_REQUIRED KeyPairSaveDir
)

# --- Invalid / garbage Load (self-contained, no fixtures) --------------------
add_executable(KeyPairInvalidLoadTests keypair_invalid_load_test.cxx)
target_link_libraries(KeyPairInvalidLoadTests StormByte::Crypto tests)
target_compile_definitions(KeyPairInvalidLoadTests PRIVATE
	STORMBYTE_TEST_KEYS_DIR="${KEYPAIR_INVALID_DIR}"
	STORMBYTE_TEST_KEYS_PASSWORD="${KEYPAIR_TEST_PASS}"
)
add_test(NAME KeyPairInvalidLoadTests COMMAND KeyPairInvalidLoadTests)
set_tests_properties(KeyPairInvalidLoadTests PROPERTIES
	LABELS "keypair"
)

# --- In-memory Save/Load (self-contained, no fixtures) -----------------------
add_executable(KeyPairMemoryTests keypair_memory_test.cxx)
target_link_libraries(KeyPairMemoryTests StormByte::Crypto tests)
target_compile_definitions(KeyPairMemoryTests PRIVATE
	STORMBYTE_TEST_KEYS_DIR="${CMAKE_BINARY_DIR}/test/keys_memory"
	STORMBYTE_TEST_KEYS_PASSWORD="${KEYPAIR_TEST_PASS}"
)
add_test(NAME KeyPairMemoryTests COMMAND KeyPairMemoryTests)
set_tests_properties(KeyPairMemoryTests PROPERTIES
	LABELS "keypair"
)
