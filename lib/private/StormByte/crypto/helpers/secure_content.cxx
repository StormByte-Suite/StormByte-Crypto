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
#include <cstring>
using namespace StormByte::Crypto::Helpers;
SecureContent::SecureContent(const void* data, std::size_t size) noexcept
	: m_block(size)
{
	if (size > 0 && data)
		std::memcpy(m_block.data(), data, size);
}

SecureContent::~SecureContent() noexcept {
	Wipe();
}

void SecureContent::Wipe() noexcept {
	if (m_block.size() > 0)
		m_block.CleanNew(0);
}

std::size_t SecureContent::Size() const noexcept {
	return m_block.size();
}

const unsigned char* SecureContent::Data() const noexcept {
	return m_block.data();
}

bool SecureContent::Equal(const SecureContent& other) const noexcept {
	if (m_block.size() != other.m_block.size())
		return false;
	unsigned char diff = 0;
	for (std::size_t i = 0; i < m_block.size(); ++i)
		diff |= static_cast<unsigned char>(m_block[i] ^ other.m_block[i]);
	return diff == 0;
}
