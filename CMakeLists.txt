cmake_minimum_required(VERSION 3.28)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)
# Crypto++ on Windows must use MSVC, not clang-cl
# (https://github.com/llvm/llvm-project/issues/63492).
# MSVC has no /std:c++26; cap at 23 until that changes
# or Crypto++ builds with clang-cl.
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" _sb_ver)
string(STRIP "${_sb_ver}" _sb_ver)

project("StormByte C++ Library: Crypto module"
	VERSION ${_sb_ver}
	DESCRIPTION "StormByte-Crypto is the cryptography module of the StormByte C++ suite."
	HOMEPAGE_URL "https://github.com/StormByte-Suite/StormByte-Crypto"
)

option(BUILD_SHARED_LIBS "Build shared libraries" ON)

include(cmake/optimizations.cmake)
include(cmake/asan.cmake)
cmake_policy(SET CMP0079 NEW)

include(cmake/load_buildmaster.cmake)
add_subdirectory(doc)
add_subdirectory(thirdparty)
add_subdirectory(lib)
add_subdirectory(test)

include(cmake/install.cmake)
