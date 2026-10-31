include(GNUInstallDirs)

if(WIN32)
	set(WITH_OPENSSL "BUNDLED" CACHE STRING "OpenSSL mode: SYSTEM, BUNDLED" FORCE)
else()
	set(WITH_OPENSSL "BUNDLED" CACHE STRING "OpenSSL mode: SYSTEM, BUNDLED")
endif()
set_property(CACHE WITH_OPENSSL PROPERTY STRINGS SYSTEM BUNDLED)
if(NOT WITH_OPENSSL STREQUAL "SYSTEM" AND NOT WITH_OPENSSL STREQUAL "BUNDLED")
	message(FATAL_ERROR "WITH_OPENSSL must be SYSTEM or BUNDLED")
endif()

if(WITH_OPENSSL STREQUAL "SYSTEM")
	set(OPENSSL_USE_STATIC_LIBS OFF)
	find_package(OpenSSL 3.0 REQUIRED COMPONENTS SSL Crypto)
	add_library(OpenSSL INTERFACE IMPORTED GLOBAL)
	target_link_libraries(OpenSSL INTERFACE OpenSSL::SSL OpenSSL::Crypto)
	return()
endif()

if(WIN32)
	set(_openssl_link "LINK={ws2_32;crypt32}")
	set(_openssl_options "ALIAS=OpenSSL;TOOLCHAIN=msvc;${_openssl_link}")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	set(_openssl_link "LINK={pthread;dl}")
	set(_openssl_options "ALIAS=OpenSSL;${_openssl_link}")
else()
	set(_openssl_options "ALIAS=OpenSSL")
endif()

buildmaster_component(
	BundledOpenSSL
	"OpenSSL 3.5.9"
	"${CMAKE_CURRENT_LIST_DIR}/cmake-port"
	"OPENSSL_SOURCE=${CMAKE_CURRENT_LIST_DIR}/src;OPENSSL_TARGET_VERSION=3.5.9;OPENSSL_INSTALL=ON;OPENSSL_LIBDIR=${CMAKE_INSTALL_LIBDIR}"
	static
	"ssl;crypto"
	"${_openssl_options}"
)

buildmaster_link(StormByte-Crypto OpenSSL)
