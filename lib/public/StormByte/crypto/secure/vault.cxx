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

#include <StormByte/crypto/secure/vault.hxx>

#include <string_view>

using namespace StormByte::Crypto::Secure;

Vault::Vault() = default;

Vault::Vault(Vault&& other) noexcept = default;

Vault::~Vault() noexcept = default;

Vault& Vault::operator=(Vault&& other) noexcept = default;

void Vault::Store(std::string_view name, Password password) {
	m_passwords.insert_or_assign(StormByte::Safe::String{name}, std::move(password));
}

ExpectedPassword Vault::Get(std::string_view name) const {
	auto iterator = m_passwords.find(StormByte::Safe::String{name});
	if (iterator == m_passwords.end())
		return StormByte::Unexpected<VaultException>("Password '{}' not found", name);
	return iterator->second;
}

bool Vault::Contains(std::string_view name) const {
	return m_passwords.contains(StormByte::Safe::String{name});
}

void Vault::Remove(std::string_view name) {
	m_passwords.erase(StormByte::Safe::String{name});
}

void Vault::Clear() noexcept {
	m_passwords.clear();
}

StormByte::Size Vault::Size() const noexcept {
	return StormByte::Size { m_passwords.size() };
}

bool Vault::Empty() const noexcept {
	return m_passwords.empty();
}
