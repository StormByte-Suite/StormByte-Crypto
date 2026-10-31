/*
 * Copyright (C) 2024-2026 David C. Manuelda (StormBytePP)
 *
 * This file is part of StormByte-Crypto.
 *
 * StormByte-Crypto original source is dual-licensed:
 *
 * 1. GNU Lesser General Public License v3.0 (or later)
 *    You may redistribute and/or modify this file under the terms of the
 *    GNU Lesser General Public License as published by the Free Software
 *    Foundation, either version 3 of the License, or (at your option)
 *    any later version.
 *
 * 2. Commercial license
 *    Alternatively, this file may be used under the terms of a commercial
 *    license agreement with the copyright holder
 *    (David C. Manuelda <StormByte@gmail.com>).
 *
 * Both licenses apply only to original StormByte-Crypto source in this
 * repository. They do not cover other StormByte modules or any third-party
 * material shipped with this repository (including everything under
 * thirdparty/, in particular Crypto++, bundled libbzip2, the StormByte-Buffer
 * tree and the StormByte suite it vendors), which remains under its own license.
 *
 * Neither license grants any patent rights. Any patent licenses required
 * to use this software or third-party components must be obtained separately
 * from the patent holders.
 *
 * StormByte-Crypto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * version 3 along with StormByte-Crypto. If not, see
 * <https://www.gnu.org/licenses/lgpl-3.0.html>.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-StormByte-Commercial
 */

#pragma once

#include <StormByte/crypto/x509/certificate.hxx>

/**
 * @namespace StormByte::Crypto::X509::Detail
 * @brief Private, offline platform trust implementation.
 */
namespace StormByte::Crypto::X509::Detail {
#ifdef STORMBYTE_CRYPTO_TRUST_TESTING
	/**
	 * @brief Test-only native intersection with isolated fixture system anchors.
	 * @param leaf Server certificate.
	 * @param intermediates Untrusted issuer candidates.
	 * @param anchors Exclusive admission roots.
	 * @param at Validation time.
	 * @param systemAnchors Exclusive memory/object-scoped simulated OS trust.
	 * @return Whether both native policies accept the same admitted root.
	 * @note Compiled only into the native test executable, never the production library.
	 */
	bool NativeTrustPathForTest(const Certificate& leaf, std::span<const Certificate> intermediates,
		std::span<const Certificate> anchors, TimePoint at, std::span<const Certificate> systemAnchors);
#else
	/**
	 * @brief Applies scoped native TLS policy and optional intersection with native OS trust.
	 * @param leaf Server certificate; SAN was independently checked by the caller.
	 * @param intermediates Untrusted issuer candidates.
	 * @param anchors Exclusive admission roots.
	 * @param at Validation time.
	 * @param requireSystem Whether normal OS root admission/distrust must also accept.
	 * @return Whether native policy accepts; no revocation assertion.
	 */
	bool NativeTrustPath(const Certificate& leaf, std::span<const Certificate> intermediates,
		std::span<const Certificate> anchors, TimePoint at, bool requireSystem);
#endif
}
