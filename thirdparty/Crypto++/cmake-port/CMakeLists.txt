cmake_minimum_required(VERSION 3.12)
project(cryptopp VERSION 8.9.0 LANGUAGES C CXX)

set(CRYPTOPP_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src")

option(CRYPTOPP_DISABLE_ASM "Disable Crypto++ assembly and SIMD backends" OFF)

set(_cryptopp_rel_sources
	cryptlib.cpp
	cpu.cpp
	integer.cpp
	3way.cpp
	adler32.cpp
	algebra.cpp
	algparam.cpp
	allocate.cpp
	arc4.cpp
	aria.cpp
	ariatab.cpp
	asn.cpp
	authenc.cpp
	base32.cpp
	base64.cpp
	basecode.cpp
	bfinit.cpp
	blake2.cpp
	blake2b_simd.cpp
	blake2s_simd.cpp
	blowfish.cpp
	blumshub.cpp
	camellia.cpp
	cast.cpp
	casts.cpp
	cbcmac.cpp
	ccm.cpp
	chacha.cpp
	chacha_avx.cpp
	chacha_simd.cpp
	chachapoly.cpp
	cham.cpp
	cham_simd.cpp
	channels.cpp
	cmac.cpp
	crc.cpp
	crc_simd.cpp
	darn.cpp
	default.cpp
	des.cpp
	dessp.cpp
	dh.cpp
	dh2.cpp
	dll.cpp
	donna_32.cpp
	donna_64.cpp
	donna_sse.cpp
	dsa.cpp
	eax.cpp
	ec2n.cpp
	eccrypto.cpp
	ecp.cpp
	elgamal.cpp
	emsa2.cpp
	eprecomp.cpp
	esign.cpp
	files.cpp
	filters.cpp
	fips140.cpp
	fipstest.cpp
	gcm.cpp
	gcm_simd.cpp
	gf256.cpp
	gf2_32.cpp
	gf2n.cpp
	gf2n_simd.cpp
	gfpcrypt.cpp
	gost.cpp
	gzip.cpp
	hc128.cpp
	hc256.cpp
	hex.cpp
	hight.cpp
	hmac.cpp
	hrtimer.cpp
	ida.cpp
	idea.cpp
	iterhash.cpp
	kalyna.cpp
	kalynatab.cpp
	keccak.cpp
	keccak_core.cpp
	keccak_simd.cpp
	lea.cpp
	lea_simd.cpp
	lsh256.cpp
	lsh256_avx.cpp
	lsh256_sse.cpp
	lsh512.cpp
	lsh512_avx.cpp
	lsh512_sse.cpp
	luc.cpp
	mars.cpp
	marss.cpp
	md2.cpp
	md4.cpp
	md5.cpp
	misc.cpp
	modes.cpp
	mqueue.cpp
	mqv.cpp
	nbtheory.cpp
	neon_simd.cpp
	oaep.cpp
	osrng.cpp
	padlkrng.cpp
	panama.cpp
	pkcspad.cpp
	poly1305.cpp
	polynomi.cpp
	ppc_simd.cpp
	primetab.cpp
	pssr.cpp
	pubkey.cpp
	queue.cpp
	rabbit.cpp
	rabin.cpp
	randpool.cpp
	rc2.cpp
	rc5.cpp
	rc6.cpp
	rdrand.cpp
	rdtables.cpp
	rijndael.cpp
	rijndael_simd.cpp
	ripemd.cpp
	rng.cpp
	rsa.cpp
	rw.cpp
	safer.cpp
	salsa.cpp
	scrypt.cpp
	seal.cpp
	seed.cpp
	serpent.cpp
	sha.cpp
	sha3.cpp
	sha_simd.cpp
	shacal2.cpp
	shacal2_simd.cpp
	shake.cpp
	shark.cpp
	sharkbox.cpp
	simeck.cpp
	simon.cpp
	simon128_simd.cpp
	skipjack.cpp
	sm3.cpp
	sm4.cpp
	sm4_simd.cpp
	sosemanuk.cpp
	speck.cpp
	speck128_simd.cpp
	square.cpp
	squaretb.cpp
	sse_simd.cpp
	strciphr.cpp
	tea.cpp
	tftables.cpp
	threefish.cpp
	tiger.cpp
	tigertab.cpp
	ttmac.cpp
	tweetnacl.cpp
	twofish.cpp
	vmac.cpp
	wake.cpp
	whrlpool.cpp
	xed25519.cpp
	xtr.cpp
	xtrcrypt.cpp
	xts.cpp
	zdeflate.cpp
	zinflate.cpp
	zlib.cpp
)

set(cryptopp_SOURCES)
foreach(_f IN LISTS _cryptopp_rel_sources)
	list(APPEND cryptopp_SOURCES "${CRYPTOPP_SRC}/${_f}")
endforeach()

string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _cpu)

set(_cryptopp_x86 FALSE)
set(_cryptopp_arm64 FALSE)
set(_cryptopp_arm32 FALSE)
set(_cryptopp_ppc FALSE)
if(_cpu MATCHES "^(x86_64|amd64|i.86|x86)$")
	set(_cryptopp_x86 TRUE)
elseif(_cpu MATCHES "^(aarch64|arm64)$")
	set(_cryptopp_arm64 TRUE)
elseif(_cpu MATCHES "^arm")
	set(_cryptopp_arm32 TRUE)
elseif(_cpu MATCHES "^(ppc|powerpc)")
	set(_cryptopp_ppc TRUE)
endif()

# --- ISA por fichero (GNU/Clang). En MSVC x64 SSE2 es baseline; AVX sí pide /arch. ---
function(_cryptopp_file_opts rel flags)
	if(flags AND EXISTS "${CRYPTOPP_SRC}/${rel}")
		set_source_files_properties("${CRYPTOPP_SRC}/${rel}"
			PROPERTIES COMPILE_OPTIONS "${flags}"
		)
	endif()
endfunction()

if(NOT CRYPTOPP_DISABLE_ASM)
	if(_cryptopp_x86 AND NOT MSVC)
		_cryptopp_file_opts(sse_simd.cpp     "-msse2")
		_cryptopp_file_opts(chacha_simd.cpp  "-msse2")
		_cryptopp_file_opts(donna_sse.cpp    "-msse2")

		_cryptopp_file_opts(cham_simd.cpp    "-mssse3")
		_cryptopp_file_opts(keccak_simd.cpp  "-mssse3")
		_cryptopp_file_opts(lea_simd.cpp     "-mssse3")
		_cryptopp_file_opts(simon128_simd.cpp "-mssse3")
		_cryptopp_file_opts(speck128_simd.cpp "-mssse3")
		_cryptopp_file_opts(lsh256_sse.cpp   "-mssse3")
		_cryptopp_file_opts(lsh512_sse.cpp   "-mssse3")

		_cryptopp_file_opts(blake2s_simd.cpp "-msse4.1")
		_cryptopp_file_opts(blake2b_simd.cpp "-msse4.1")

		_cryptopp_file_opts(crc_simd.cpp     "-msse4.2")

		_cryptopp_file_opts(gcm_simd.cpp     "-mssse3;-mpclmul")
		_cryptopp_file_opts(gf2n_simd.cpp    "-mpclmul")

		_cryptopp_file_opts(rijndael_simd.cpp "-msse4.1;-maes")
		_cryptopp_file_opts(sm4_simd.cpp      "-mssse3;-maes")

		_cryptopp_file_opts(sha_simd.cpp     "-msse4.2;-msha")
		_cryptopp_file_opts(shacal2_simd.cpp "-msse4.2;-msha")

		_cryptopp_file_opts(chacha_avx.cpp   "-mavx2")
		_cryptopp_file_opts(lsh256_avx.cpp   "-mavx2")
		_cryptopp_file_opts(lsh512_avx.cpp   "-mavx2")
	elseif(_cryptopp_x86 AND MSVC)
		_cryptopp_file_opts(chacha_avx.cpp   "/arch:AVX2")
		_cryptopp_file_opts(lsh256_avx.cpp   "/arch:AVX2")
		_cryptopp_file_opts(lsh512_avx.cpp   "/arch:AVX2")
	elseif(_cryptopp_arm32)
		_cryptopp_file_opts(neon_simd.cpp    "-march=armv7-a;-mfpu=neon")
		_cryptopp_file_opts(gcm_simd.cpp     "-march=armv7-a;-mfpu=neon")
		_cryptopp_file_opts(blake2s_simd.cpp "-march=armv7-a;-mfpu=neon")
		_cryptopp_file_opts(blake2b_simd.cpp "-march=armv7-a;-mfpu=neon")
		_cryptopp_file_opts(chacha_simd.cpp  "-march=armv7-a;-mfpu=neon")
		_cryptopp_file_opts(lea_simd.cpp     "-march=armv7-a;-mfpu=neon")
		_cryptopp_file_opts(simon128_simd.cpp "-march=armv7-a;-mfpu=neon")
		_cryptopp_file_opts(speck128_simd.cpp "-march=armv7-a;-mfpu=neon")
		_cryptopp_file_opts(crc_simd.cpp     "-march=armv7-a;-mfpu=neon")
		_cryptopp_file_opts(sha_simd.cpp     "-march=armv7-a;-mfpu=neon")
		_cryptopp_file_opts(shacal2_simd.cpp "-march=armv7-a;-mfpu=neon")
		_cryptopp_file_opts(rijndael_simd.cpp "-march=armv7-a;-mfpu=neon")
	elseif(_cryptopp_arm64 AND NOT MSVC)
		# Mismos flags que el GNUmakefile upstream. ASIMD es baseline, pero
		# CRC y Crypto (AES/PMULL/SHA) son opcionales en ARMv8.0-8.2: sin
		# ellos GCC/Clang rechazan los intrínsecos. cpu.cpp despacha en runtime.
		foreach(_f IN ITEMS neon_simd.cpp blake2s_simd.cpp blake2b_simd.cpp
				chacha_simd.cpp cham_simd.cpp lea_simd.cpp simon128_simd.cpp
				speck128_simd.cpp sm4_simd.cpp)
			_cryptopp_file_opts(${_f} "-march=armv8-a")
		endforeach()
		_cryptopp_file_opts(crc_simd.cpp      "-march=armv8-a+crc")
		_cryptopp_file_opts(rijndael_simd.cpp "-march=armv8-a+crypto")
		_cryptopp_file_opts(gcm_simd.cpp      "-march=armv8-a+crypto")
		_cryptopp_file_opts(gf2n_simd.cpp     "-march=armv8-a+crypto")
		_cryptopp_file_opts(sha_simd.cpp      "-march=armv8-a+crypto")
		_cryptopp_file_opts(shacal2_simd.cpp  "-march=armv8-a+crypto")
	elseif(_cryptopp_ppc)
		_cryptopp_file_opts(ppc_simd.cpp     "-maltivec")
	endif()
	# MSVC ARM64 expone los intrínsecos ARMv8 sin flags.
endif()

# cpu.cpp solo usa getauxval() con glibc; en musl cae a un stub que devuelve 0
# y la detección ARM depende de sondas SIGILL (la de PMULL upstream siempre
# falla). musl tiene getauxval desde 1.1.0.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	set_property(SOURCE "${CRYPTOPP_SRC}/cpu.cpp" APPEND PROPERTY
		COMPILE_DEFINITIONS CRYPTOPP_GETAUXV_AVAILABLE=1
	)
endif()

set(cryptopp_ASM)
if(NOT CRYPTOPP_DISABLE_ASM AND MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8)
	enable_language(ASM_MASM)
	foreach(_asm IN ITEMS x64masm.asm x64dll.asm rdrand.asm rdseed.asm)
		if(EXISTS "${CRYPTOPP_SRC}/${_asm}")
			list(APPEND cryptopp_ASM "${CRYPTOPP_SRC}/${_asm}")
		endif()
	endforeach()
	if(cryptopp_ASM)
		set_source_files_properties(${cryptopp_ASM} PROPERTIES
			LANGUAGE ASM_MASM
			COMPILE_DEFINITIONS "_M_X64"
		)
	endif()
endif()

if(NOT CRYPTOPP_DISABLE_ASM AND _cryptopp_arm32 AND NOT MSVC)
	foreach(_s IN ITEMS aes_armv4.S sha1_armv4.S sha256_armv4.S sha512_armv4.S)
		if(EXISTS "${CRYPTOPP_SRC}/${_s}")
			list(APPEND cryptopp_ASM "${CRYPTOPP_SRC}/${_s}")
		endif()
	endforeach()
endif()

add_library(cryptopp ${cryptopp_SOURCES} ${cryptopp_ASM})
add_library(cryptopp::cryptopp ALIAS cryptopp)

set_target_properties(cryptopp PROPERTIES
	OUTPUT_NAME cryptopp
	CXX_STANDARD 11
	CXX_STANDARD_REQUIRED ON
	POSITION_INDEPENDENT_CODE ON
	VERSION ${PROJECT_VERSION}
	SOVERSION 8
)

target_include_directories(cryptopp
	PUBLIC
		"$<BUILD_INTERFACE:${CRYPTOPP_SRC}>"
		"$<INSTALL_INTERFACE:include/cryptopp>"
)

if(CRYPTOPP_DISABLE_ASM)
	target_compile_definitions(cryptopp PUBLIC CRYPTOPP_DISABLE_ASM=1)
endif()

if(WIN32)
	target_compile_definitions(cryptopp PRIVATE
		_WIN32_WINNT=0x0A00
		WIN32_LEAN_AND_MEAN
		NOMINMAX
	)
	target_link_libraries(cryptopp PRIVATE advapi32)
endif()

if(BUILD_SHARED_LIBS)
	target_compile_definitions(cryptopp PRIVATE CRYPTOPP_EXPORTS)
endif()

include(GNUInstallDirs)

file(GLOB cryptopp_HEADERS "${CRYPTOPP_SRC}/*.h")

install(TARGETS cryptopp
	EXPORT cryptopp-targets
	ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

install(FILES ${cryptopp_HEADERS}
	DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/cryptopp"
)

install(EXPORT cryptopp-targets
	NAMESPACE cryptopp::
	DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/cryptopp"
)
