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

#include <StormByte/crypto/helpers/secure_content.hxx>
#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/secure/password.hxx>

#include <cstring>

using namespace StormByte::Crypto::Secure;

Password::Password() noexcept = default;

Password::Password(StormByte::Safe::String& value) noexcept
	: Password(value.data(), StormByte::ByteSize{static_cast<std::size_t>(value.size())}) {
	StormByte::Crypto::Helpers::SecureWipe(value);
}

Password::Password(const char* value) noexcept
	: Password(value, StormByte::ByteSize{value ? std::strlen(value) : 0}) {}

Password::Password(const void* data, StormByte::ByteSize size) noexcept
	: m_data(StormByte::Safe::Shared<StormByte::Crypto::Helpers::SecureContent>::MakePointer<StormByte::Crypto::Helpers::SecureContent>(data, static_cast<std::size_t>(size))) {}

Password::Password(const Password& other) = default;

Password::Password(Password&& other) noexcept = default;

Password::~Password() = default;

Password& Password::operator=(const Password& other) = default;

Password& Password::operator=(Password&& other) noexcept = default;

StormByte::ByteSize Password::Size() const noexcept {
	return m_data ? StormByte::ByteSize { m_data->Size() } : StormByte::ByteSize { 0 };
}

bool Password::Empty() const noexcept {
	return Size() == StormByte::ByteSize { 0 };
}

Password::operator bool() const noexcept {
	return !Empty();
}

bool Password::operator==(const Password& other) const noexcept {
	if (!m_data || !other.m_data)
		return Empty() && other.Empty();
	return m_data->Equal(*other.m_data);
}

bool Password::operator!=(const Password& other) const noexcept {
	return !(*this == other);
}
