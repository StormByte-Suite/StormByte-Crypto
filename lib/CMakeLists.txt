include(GNUInstallDirs)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

file(GLOB_RECURSE STORMBYTE_CRYPTO_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_LIST_DIR}/*.cxx")

if(BUILD_SHARED_LIBS)
	set(_mode shared)
else()
	set(_mode static)
endif()

buildmaster_component(
	StormByte-Crypto
	"StormByte Suite - Crypto"
	"${STORMBYTE_CRYPTO_SOURCES}"
	""
	${_mode}
	"StormByte-Crypto"
	"BACKEND=host;ALIAS=StormByte::Crypto"
)

if(BUILD_SHARED_LIBS)
	target_compile_definitions(StormByte-Crypto PUBLIC STORMBYTE_CRYPTO_SHARED)
endif()

set_target_properties(StormByte-Crypto PROPERTIES
	LINKER_LANGUAGE CXX
	SOVERSION ${CMAKE_PROJECT_VERSION}
	VERSION ${CMAKE_PROJECT_VERSION}
	POSITION_INDEPENDENT_CODE ON
	C_VISIBILITY_PRESET hidden
	CXX_VISIBILITY_PRESET hidden
	VISIBILITY_INLINES_HIDDEN ON
)

if(BUILD_SHARED_LIBS AND APPLE)
	target_link_options(StormByte-Crypto PRIVATE
		"LINKER:-hidden-lssl"
		"LINKER:-hidden-lcrypto"
	)
elseif(BUILD_SHARED_LIBS AND UNIX)
	target_link_options(StormByte-Crypto PRIVATE
		"LINKER:--exclude-libs,libssl.a:libcrypto.a"
	)
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
	target_compile_options(StormByte-Crypto PRIVATE
		/EHsc
		$<$<CONFIG:Release>:/O2>
		$<$<CONFIG:Debug>:/Od>
	)
else()
	target_compile_options(StormByte-Crypto PRIVATE
		$<$<CONFIG:Debug>:-pipe -g -ggdb -Wall -Wextra -Wnon-virtual-dtor -pedantic -pedantic-errors -O0>
	)
endif()

if(WIN32)
	target_compile_definitions(StormByte-Crypto PUBLIC UNICODE NOMINMAX)
	target_link_libraries(StormByte-Crypto PRIVATE crypt32)
elseif(APPLE)
	target_link_libraries(StormByte-Crypto PRIVATE "-framework Security" "-framework CoreFoundation")
endif()

target_include_directories(StormByte-Crypto
	SYSTEM BEFORE PUBLIC
		"${CMAKE_CURRENT_LIST_DIR}/public"
		"${CMAKE_CURRENT_LIST_DIR}/private"
)
