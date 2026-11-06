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

#include <StormByte/crypto/x509/native_trust.hxx>
#include <StormByte/crypto/tls_diagnostic.hxx>

#include <algorithm>
#include <cstdio>
#include <limits>
#include <memory>
#include <type_traits>

#ifdef WINDOWS
#ifndef CERT_CHAIN_PARA_HAS_EXTRA_FIELDS
#define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS
#endif
#include <windows.h>
#include <wincrypt.h>
#elifdef MACOS
#include <Security/Security.h>
#endif

using namespace StormByte::Crypto::X509;

#ifdef WINDOWS
namespace {
	/**
	 * @brief Closes a scoped memory certificate store.
	 * @param store Owned handle.
	 */
	void CloseStore(void* store) noexcept {
		CertCloseStore(store, 0);
	}

	/**
	 * @brief Owned native memory store; never an OS store.
	 */
	using Store = std::unique_ptr<void, decltype(&CloseStore)>;

	/**
	 * @brief Owned exclusive chain engine.
	 */
	using Engine = std::unique_ptr<void, decltype(&CertFreeCertificateChainEngine)>;

	/**
	 * @brief Owned native chain evaluation result.
	 */
	using Chain = std::unique_ptr<const CERT_CHAIN_CONTEXT, decltype(&CertFreeCertificateChain)>;

	/**
	 * @brief Builds an isolated store of public certificates.
	 * @param certificates Public certificate objects.
	 * @return Memory store or null on error.
	 */
	Store MemoryStore(std::span<const Certificate> certificates) {
		Store store(CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, nullptr), CloseStore);
		if (!store) {
			StormByte::Crypto::Detail::TLSDiagnostic("CertOpenStore", GetLastError(), "");
			return store;
		}
		for (const auto& certificate : certificates) {
			const auto der = certificate.Der().span();
			if (der.empty() || der.size() > std::numeric_limits<DWORD>::max()
				|| !CertAddEncodedCertificateToStore(store.get(), X509_ASN_ENCODING,
					reinterpret_cast<const BYTE*>(der.data()), static_cast<DWORD>(der.size()),
					CERT_STORE_ADD_ALWAYS, nullptr)) {
					StormByte::Crypto::Detail::TLSDiagnostic("memory certificate import", GetLastError(), "");
					return Store(nullptr, CloseStore);
			}
		}
		return store;
	}

	/**
	 * @brief Creates an engine with an exclusive memory root set.
	 * @param roots Admission store.
	 * @return Owned engine or null on error.
	 */
	Engine ExclusiveEngine(HCERTSTORE roots) {
		CERT_CHAIN_ENGINE_CONFIG config{};
		config.cbSize = sizeof(config);
		config.hExclusiveRoot = roots;
		config.dwFlags = CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_DISABLE_AIA;
		config.dwExclusiveFlags = CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG;
		HCERTCHAINENGINE engine = nullptr;
		if (!CertCreateCertificateChainEngine(&config, &engine)) {
			StormByte::Crypto::Detail::TLSDiagnostic("CertCreateCertificateChainEngine", GetLastError(), "");
			return Engine(nullptr, CertFreeCertificateChainEngine);
		}
		return Engine(engine, CertFreeCertificateChainEngine);
	}

	/**
	 * @brief Evaluates native server TLS policy without revocation or network fetching.
	 * @param engine Exclusive engine with caller-selected trust anchors.
	 * @param leaf Server leaf.
	 * @param issuers Untrusted memory candidates.
	 * @param at Validation time.
	 * @return Successful owned chain or null; terminal-root admission is checked separately.
	 */
	Chain Evaluate(HCERTCHAINENGINE engine, const Certificate& leaf, HCERTSTORE issuers, TimePoint at) {
		const auto scope = "exclusive bundled/custom roots";
		StormByte::Crypto::Detail::TLSDiagnostic("Windows chain evaluation", 0, scope);
		const auto der = leaf.Der().span();
		if (der.empty() || der.size() > std::numeric_limits<DWORD>::max())
			return Chain(nullptr, CertFreeCertificateChain);
		std::unique_ptr<const CERT_CONTEXT, decltype(&CertFreeCertificateContext)> context(
			CertCreateCertificateContext(X509_ASN_ENCODING, reinterpret_cast<const BYTE*>(der.data()),
				static_cast<DWORD>(der.size())), CertFreeCertificateContext);
		const auto seconds = at.time_since_epoch().count();
		constexpr std::int64_t Offset = 11644473600;
		if (!context || seconds < -Offset
			|| seconds > static_cast<std::int64_t>(std::numeric_limits<std::uint64_t>::max() / 10000000) - Offset)
			return Chain(nullptr, CertFreeCertificateChain);
		const auto ticks = static_cast<std::uint64_t>(seconds + Offset) * 10000000;
		FILETIME time{static_cast<DWORD>(ticks), static_cast<DWORD>(ticks >> 32)};
		CERT_CHAIN_PARA parameters{};
		parameters.cbSize = sizeof(parameters);
		CERT_STRONG_SIGN_PARA strong{};
		strong.cbSize = sizeof(strong);
		strong.dwInfoChoice = CERT_STRONG_SIGN_OID_INFO_CHOICE;
		strong.pszOID = const_cast<LPSTR>(szOID_CERT_STRONG_SIGN_OS_CURRENT);
		parameters.pStrongSignPara = &strong;
		LPSTR usage = const_cast<LPSTR>(szOID_PKIX_KP_SERVER_AUTH);
		parameters.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
		parameters.RequestedUsage.Usage.cUsageIdentifier = 1;
		parameters.RequestedUsage.Usage.rgpszUsageIdentifier = &usage;
		PCCERT_CHAIN_CONTEXT raw = nullptr;
		if (!CertGetCertificateChain(engine, context.get(), &time, issuers, &parameters,
			CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_DISABLE_AIA
				| CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE | CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY,
			nullptr, &raw)) {
			StormByte::Crypto::Detail::TLSDiagnostic("CertGetCertificateChain", GetLastError(), scope);
			return Chain(nullptr, CertFreeCertificateChain);
		}
		Chain chain(raw, CertFreeCertificateChain);
		if (chain->TrustStatus.dwErrorStatus != CERT_TRUST_NO_ERROR) {
			StormByte::Crypto::Detail::TLSDiagnostic("Windows chain trust status",
				chain->TrustStatus.dwErrorStatus, scope);
			for (DWORD index = 0; index < chain->cChain; ++index) {
				const auto simple = chain->rgpChain[index];
				for (DWORD element = 0; element < simple->cElement; ++element) {
					const auto errors = simple->rgpElement[element]->TrustStatus.dwErrorStatus;
					if (errors) {
						char position[128];
						std::snprintf(position, sizeof(position), "%s; chain=%lu certificate=%lu (leaf=0)",
							scope, static_cast<unsigned long>(index), static_cast<unsigned long>(element));
						StormByte::Crypto::Detail::TLSDiagnostic("Windows certificate trust status", errors, position);
					}
				}
			}
			return Chain(nullptr, CertFreeCertificateChain);
		}
		SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl{};
		ssl.cbSize = sizeof(ssl);
		ssl.dwAuthType = AUTHTYPE_SERVER;
		CERT_CHAIN_POLICY_PARA policy{};
		policy.cbSize = sizeof(policy);
		policy.pvExtraPolicyPara = &ssl;
		CERT_CHAIN_POLICY_STATUS status{};
		status.cbSize = sizeof(status);
		if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain.get(), &policy, &status)) {
			StormByte::Crypto::Detail::TLSDiagnostic("CertVerifyCertificateChainPolicy", GetLastError(), scope);
			return Chain(nullptr, CertFreeCertificateChain);
		}
		if (status.dwError != 0) {
			StormByte::Crypto::Detail::TLSDiagnostic("Windows SSL policy status", status.dwError, scope);
			return Chain(nullptr, CertFreeCertificateChain);
		}
		return chain;
	}

	/**
	 * @brief Returns the terminal root only for one unambiguous simple chain.
	 * @param chain Evaluated chain.
	 * @return Borrowed DER bytes, or an empty span.
	 */
	std::span<const std::byte> Terminal(const Chain& chain) {
		if (!chain || chain->cChain != 1 || chain->rgpChain[0]->cElement == 0)
			return {};
		const auto simple = chain->rgpChain[0];
		const auto root = simple->rgpElement[simple->cElement - 1]->pCertContext;
		return {reinterpret_cast<const std::byte*>(root->pbCertEncoded), root->cbCertEncoded};
	}

	/**
	 * @brief Applies native TLS policy with exclusive caller-selected anchors.
	 * @param leaf Server certificate.
	 * @param intermediates Untrusted issuers.
	 * @param anchors Exclusive permitted roots.
	 * @param at Validation time.
	 * @return Path-only acceptance with no OS-root union.
	 */
	bool ValidateNative(const Certificate& leaf, std::span<const Certificate> intermediates,
		std::span<const Certificate> anchors, TimePoint at) {
		if (anchors.empty())
			return false;
		auto roots = MemoryStore(anchors);
		auto issuers = MemoryStore(intermediates);
		if (!roots || !issuers)
			return false;
		auto engine = ExclusiveEngine(roots.get());
		if (!engine)
			return false;
		auto scoped = Evaluate(engine.get(), leaf, issuers.get(), at);
		const auto root = Terminal(scoped);
		if (root.empty() || !std::any_of(anchors.begin(), anchors.end(), [&](const Certificate& anchor) {
			return anchor.IsCA() && anchor.IsValidAt(at) && std::ranges::equal(root, anchor.Der().span());
		})) {
			StormByte::Crypto::Detail::TLSDiagnostic("native root admission", 0, "exclusive chain rejected or terminal root not admitted");
			return false;
		}
		return true;
	}
}
#elifdef MACOS
namespace {
	/**
	 * @brief Releases an owned Core Foundation/Security object.
	 * @param object Owned reference.
	 */
	void Release(CFTypeRef object) noexcept {
		CFRelease(object);
	}

	/**
	 * @brief Typed scoped ownership for native objects; never writes to a keychain.
	 * @tparam T Native reference type.
	 */
	template<typename T>
	using Owner = std::unique_ptr<std::remove_pointer_t<T>, decltype(&Release)>;

	/**
	 * @brief Builds a scoped native certificate array.
	 * @param certificates Public certificates.
	 * @return Owned array, or null on conversion error.
	 */
	Owner<CFMutableArrayRef> CertificateArray(std::span<const Certificate> certificates) {
		Owner<CFMutableArrayRef> array(CFArrayCreateMutable(nullptr, 0, &kCFTypeArrayCallBacks), Release);
		if (!array)
			return array;
		for (const auto& certificate : certificates) {
			const auto der = certificate.Der().span();
			if (der.empty() || der.size() > static_cast<std::size_t>(std::numeric_limits<CFIndex>::max()))
				return Owner<CFMutableArrayRef>(nullptr, Release);
			Owner<SecCertificateRef> item(nullptr, Release);
			Owner<CFDataRef> data(CFDataCreate(nullptr, reinterpret_cast<const UInt8*>(der.data()),
				static_cast<CFIndex>(der.size())), Release);
			if (!data)
				return Owner<CFMutableArrayRef>(nullptr, Release);
			item.reset(SecCertificateCreateWithData(nullptr, data.get()));
			if (!item)
				return Owner<CFMutableArrayRef>(nullptr, Release);
			CFArrayAppendValue(array.get(), item.get());
		}
		return array;
	}

	/**
	 * @brief Evaluates native SSL server policy with network fetching disabled.
	 * @param certificates Leaf and untrusted intermediates.
	 * @param anchors Exclusive scoped anchors.
	 * @param at Validation time.
	 * @return Successful owned SecTrust object or null.
	 */
	Owner<SecTrustRef> Evaluate(CFArrayRef certificates, CFArrayRef anchors, TimePoint at) {
		Owner<SecPolicyRef> policy(SecPolicyCreateSSL(true, nullptr), Release);
		if (!policy)
			return Owner<SecTrustRef>(nullptr, Release);
		SecTrustRef raw = nullptr;
		if (SecTrustCreateWithCertificates(certificates, policy.get(), &raw) != errSecSuccess)
			return Owner<SecTrustRef>(nullptr, Release);
		Owner<SecTrustRef> trust(raw, Release);
		Owner<CFDateRef> date(CFDateCreate(nullptr,
			static_cast<CFAbsoluteTime>(at.time_since_epoch().count()) - kCFAbsoluteTimeIntervalSince1970), Release);
		if (!date || SecTrustSetVerifyDate(trust.get(), date.get()) != errSecSuccess
			|| SecTrustSetNetworkFetchAllowed(trust.get(), false) != errSecSuccess)
			return Owner<SecTrustRef>(nullptr, Release);
		if (SecTrustSetAnchorCertificates(trust.get(), anchors) != errSecSuccess
			|| SecTrustSetAnchorCertificatesOnly(trust.get(), true) != errSecSuccess)
			return Owner<SecTrustRef>(nullptr, Release);
		CFErrorRef rawError = nullptr;
		const bool accepted = SecTrustEvaluateWithError(trust.get(), &rawError);
		Owner<CFErrorRef> error(rawError, Release);
		if (!accepted) {
			StormByte::Crypto::Detail::TLSDiagnostic("macOS SecTrustEvaluateWithError",
				error ? static_cast<unsigned long>(CFErrorGetCode(error.get())) : 0,
				"exclusive bundled/custom roots");
			return Owner<SecTrustRef>(nullptr, Release);
		}
		return trust;
	}

	/**
	 * @brief Copies the DER of a successful native chain's terminal root.
	 * @param trust Evaluated trust.
	 * @return Owned terminal certificate bytes or null.
	 */
	Owner<CFDataRef> Terminal(const Owner<SecTrustRef>& trust) {
		if (!trust)
			return Owner<CFDataRef>(nullptr, Release);
		Owner<CFArrayRef> chain(SecTrustCopyCertificateChain(trust.get()), Release);
		if (!chain || CFArrayGetCount(chain.get()) == 0)
			return Owner<CFDataRef>(nullptr, Release);
		auto root = static_cast<SecCertificateRef>(const_cast<void*>(
			CFArrayGetValueAtIndex(chain.get(), CFArrayGetCount(chain.get()) - 1)));
		return Owner<CFDataRef>(SecCertificateCopyData(root), Release);
	}

	/**
	 * @brief Applies native TLS policy with exclusive caller-selected anchors.
	 * @param leaf Server certificate.
	 * @param intermediates Untrusted issuers.
	 * @param anchors Exclusive permitted roots.
	 * @param at Validation time.
	 * @return Path-only acceptance with no OS-root union or keychain mutation.
	 */
	bool ValidateNative(const Certificate& leaf, std::span<const Certificate> intermediates,
		std::span<const Certificate> anchors, TimePoint at) {
		if (anchors.empty())
			return false;
		auto certificates = CertificateArray(std::span(&leaf, 1));
		auto issuers = CertificateArray(intermediates);
		auto roots = CertificateArray(anchors);
		if (!certificates || !issuers || !roots)
			return false;
		CFArrayAppendArray(certificates.get(), issuers.get(), CFRangeMake(0, CFArrayGetCount(issuers.get())));
		auto scoped = Evaluate(certificates.get(), roots.get(), at);
		auto root = Terminal(scoped);
		if (!root)
			return false;
		const std::span bytes(reinterpret_cast<const std::byte*>(CFDataGetBytePtr(root.get())),
			static_cast<std::size_t>(CFDataGetLength(root.get())));
		if (!std::any_of(anchors.begin(), anchors.end(), [&](const Certificate& anchor) {
			return anchor.IsCA() && anchor.IsValidAt(at) && std::ranges::equal(bytes, anchor.Der().span());
		}))
			return false;
		return true;
	}
}
#endif

#if defined(WINDOWS) || defined(MACOS)
bool StormByte::Crypto::X509::Detail::NativeTrustPath(const Certificate& leaf,
	std::span<const Certificate> intermediates, std::span<const Certificate> anchors,
	TimePoint at) {
	return ValidateNative(leaf, intermediates, anchors, at);
}
#endif
