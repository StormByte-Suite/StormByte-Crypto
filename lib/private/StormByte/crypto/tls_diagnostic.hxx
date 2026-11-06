// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-StormByte-Commercial
#pragma once

#include <cstdio>
#include <cstdlib>

#ifdef WINDOWS
#include <windows.h>
#endif

namespace StormByte::Crypto::Detail {
	inline void TLSDiagnostic(const char* stage, unsigned long code, const char* detail) noexcept {
		const auto enabled = std::getenv("STORMBYTE_TLS_DIAGNOSTICS");
		if (!enabled || enabled[0] != '1' || enabled[1] != '\0')
			return;
		char message[512];
		std::snprintf(message, sizeof(message), "[StormByte-Crypto TLS] %s: code=0x%08lx %s\n",
			stage, code, detail ? detail : "");
		std::fputs(message, stderr);
		std::fflush(stderr);
#ifdef WINDOWS
		OutputDebugStringA(message);
#endif
	}
}
