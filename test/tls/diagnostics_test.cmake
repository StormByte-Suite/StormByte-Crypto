foreach(enabled IN ITEMS 0 1)
	execute_process(
		COMMAND "${CMAKE_COMMAND}" -E env "STORMBYTE_TLS_DIAGNOSTICS=${enabled}" "${TLS_SESSION_TEST}"
		RESULT_VARIABLE status
		OUTPUT_VARIABLE output
		ERROR_VARIABLE diagnostic)
	if(NOT status EQUAL 0)
		message(FATAL_ERROR "TLS session behavior changed with diagnostics=${enabled}: ${output}${diagnostic}")
	endif()
	if(enabled)
		foreach(expected IN ITEMS
			"\\[StormByte-Crypto TLS\\] peer verification:"
			"\\[StormByte-Crypto TLS\\] SSL_do_handshake:"
			"\\[StormByte-Crypto TLS\\] session failure:")
			if(NOT diagnostic MATCHES "${expected}")
				message(FATAL_ERROR "Missing TLS diagnostic ${expected}: ${diagnostic}")
			endif()
		endforeach()
	elseif(diagnostic MATCHES "\\[StormByte-Crypto TLS\\]")
		message(FATAL_ERROR "TLS diagnostics must be disabled unless explicitly enabled")
	endif()
endforeach()
