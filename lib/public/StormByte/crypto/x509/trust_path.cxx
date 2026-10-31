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

#include <StormByte/crypto/x509/bundled_roots.hxx>
#include <StormByte/crypto/x509/native_trust.hxx>
#include <StormByte/crypto/x509/trust_path.hxx>

#include <cryptopp/sha.h>

#include <algorithm>
#include <array>
#include <string_view>

using namespace StormByte::Crypto::X509;

namespace {
	/**
	 * @brief Checks request bounds and independently enforces strict SAN identity.
	 * @param leaf Server leaf.
	 * @param intermediates Untrusted issuer candidates.
	 * @param identity Expected DNS or IP identity.
	 * @return Whether the request can proceed to platform path validation.
	 */
	bool ValidRequest(const Certificate& leaf, std::span<const Certificate> intermediates,
		const SubjectAltName& identity) {
		if (leaf.Der().empty() || leaf.IsCA() || intermediates.size() > 16
			|| !leaf.VerifyTLSPurpose(TLSRole::Server))
			return false;
		for (const auto& certificate : intermediates)
			if (certificate.Der().empty())
				return false;
		const auto bytes = identity.Value().span();
		if (identity.Type() == SubjectAltNameType::DNS)
			return static_cast<bool>(leaf.VerifyDNSName(
				std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size())));
		if (identity.Type() == SubjectAltNameType::IP)
			return static_cast<bool>(leaf.VerifyIPAddress(bytes));
		return false;
	}
}

const char* StormByte::Crypto::X509::BundledTLSRootsRevision() noexcept {
	return Detail::BundleRevision;
}

const char* StormByte::Crypto::X509::BundledTLSRootsSHA256() noexcept {
	return Detail::BundleSHA256;
}

ExpectedBundledTLSRoots StormByte::Crypto::X509::LoadBundledTLSRoots() {
	constexpr std::string_view pem(Detail::BundledRoots, sizeof(Detail::BundledRoots) - 1);
	std::array<CryptoPP::byte, CryptoPP::SHA256::DIGESTSIZE> digest{};
	CryptoPP::SHA256 hash;
	hash.CalculateDigest(digest.data(), reinterpret_cast<const CryptoPP::byte*>(pem.data()), pem.size());
	constexpr std::string_view hex = "0123456789abcdef";
	for (std::size_t i = 0; i < digest.size(); ++i)
		if (hex[digest[i] >> 4] != Detail::BundleSHA256[2 * i]
			|| hex[digest[i] & 15] != Detail::BundleSHA256[2 * i + 1])
			return StormByte::Unexpected(TrustPathError::BundleInvalid);
	auto roots = LoadAll(std::as_bytes(std::span(pem.data(), pem.size())));
	if (static_cast<std::size_t>(roots.size()) != Detail::BundleRootCount)
		return StormByte::Unexpected(TrustPathError::BundleInvalid);
	for (const auto& root : roots)
		if (root.Der().empty() || !root.IsCA())
			return StormByte::Unexpected(TrustPathError::BundleInvalid);
	return roots;
}

ExpectedTrustPath StormByte::Crypto::X509::ValidateBundledTLSPath(const Certificate& leaf,
	std::span<const Certificate> intermediates, TimePoint at, const SubjectAltName& identity) {
	if (!ValidRequest(leaf, intermediates, identity))
		return StormByte::Unexpected(TrustPathError::InvalidRequest);
	auto roots = LoadBundledTLSRoots();
	if (!roots)
		return StormByte::Unexpected(*roots.error());
#ifdef WINDOWS
	if (!Detail::NativeTrustPath(leaf, intermediates, *roots, at, true))
		return StormByte::Unexpected(TrustPathError::NativePolicyRejected);
#elifdef MACOS
	if (!Detail::NativeTrustPath(leaf, intermediates, *roots, at, true))
		return StormByte::Unexpected(TrustPathError::NativePolicyRejected);
#else
	const auto& last = intermediates.empty() ? leaf : intermediates.back();
	bool matched = false;
	for (const auto& root : *roots) {
		if (!last.IsIssuedBy(root))
			continue;
		matched = true;
		if (TLSPeerVerifier::Verify(leaf, intermediates, root, at, TLSRole::Server, &identity))
			return {};
	}
	return StormByte::Unexpected(matched ? TrustPathError::PeerPathRejected : TrustPathError::RootNotAdmitted);
#endif
#ifdef WINDOWS
	return {};
#elifdef MACOS
	return {};
#endif
}

ExpectedTrustPath StormByte::Crypto::X509::ValidateCustomCATLSPath(const Certificate& leaf,
	std::span<const Certificate> intermediates, const Certificate& anchor,
	TimePoint at, const SubjectAltName& identity) {
	if (!ValidRequest(leaf, intermediates, identity) || anchor.Der().empty() || !anchor.IsCA())
		return StormByte::Unexpected(TrustPathError::InvalidRequest);
#ifdef WINDOWS
	if (!Detail::NativeTrustPath(leaf, intermediates, std::span(&anchor, 1), at, false))
		return StormByte::Unexpected(TrustPathError::NativePolicyRejected);
#elifdef MACOS
	if (!Detail::NativeTrustPath(leaf, intermediates, std::span(&anchor, 1), at, false))
		return StormByte::Unexpected(TrustPathError::NativePolicyRejected);
#else
	if (!TLSPeerVerifier::Verify(leaf, intermediates, anchor, at, TLSRole::Server, &identity))
		return StormByte::Unexpected(TrustPathError::PeerPathRejected);
#endif
	return {};
}

ExpectedPaymentPeer StormByte::Crypto::X509::VerifyPaymentPeer(const Certificate& leaf,
	std::span<const Certificate> intermediates, TimePoint at, const SubjectAltName& identity) {
	if (!ValidateBundledTLSPath(leaf, intermediates, at, identity))
		return StormByte::Unexpected(PaymentPeerError::TrustPathRejected);
	return StormByte::Unexpected(PaymentPeerError::RevocationUnavailable);
}
