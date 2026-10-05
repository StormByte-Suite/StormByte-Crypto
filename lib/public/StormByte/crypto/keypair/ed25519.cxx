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

#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/engine/keypair/api.hxx>
#include <StormByte/crypto/keypair/ed25519.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/crypto/random.hxx>

#include <queue.h>
#include <xed25519.h>

using namespace StormByte::Crypto::KeyPair;

ED25519::ED25519(std::string_view publicKey, StormByte::Safe::Optional<Secure::Password> privateKey):
	Generic(Type::ED25519, StormByte::Safe::String{publicKey}, std::move(privateKey)) {}

ED25519::~ED25519() noexcept = default;

ED25519::PointerType ED25519::Clone() const {
	return MakePointer<ED25519>(*this);
}

ED25519::PointerType ED25519::Move() {
	return MakePointer<ED25519>(std::move(*this));
}

ED25519::PointerType ED25519::Generate(unsigned short /*bits*/) noexcept {
	try {
		CryptoPP::ed25519::Signer signer(RNG());
		CryptoPP::ed25519::Verifier verifier(signer);
		CryptoPP::ByteQueue pubQueue;
		verifier.GetPublicKey().Save(pubQueue);
		CryptoPP::SecByteBlock pub(pubQueue.CurrentSize());
		pubQueue.Get(pub.data(), pub.size());
		auto pubStr = Engine::KeyPair::EncodeSecBlockBase64(pub);
		Helpers::SecureWipe(pub);
		CryptoPP::ByteQueue privQueue;
		signer.GetPrivateKey().Save(privQueue);
		CryptoPP::SecByteBlock priv(privQueue.CurrentSize());
		privQueue.Get(priv.data(), priv.size());
		Secure::Password privPwd = Engine::KeyPair::PasswordFromSecBlock(priv);
		return MakePointer<ED25519>(pubStr, std::move(privPwd));
	} catch (...) {
		return nullptr;
	}
}
