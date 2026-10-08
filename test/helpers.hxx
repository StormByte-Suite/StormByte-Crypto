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

#include <StormByte/buffer/consumer.hxx>
#include <StormByte/buffer/fifo.hxx>
#include <StormByte/safe/binary.hxx>
#include <StormByte/safe/string.hxx>

#include <iostream>
#include <thread>

/**
 * @brief Drain a consumer until its producer closes.
 * @param consumer Consumer to drain.
 * @return Collected bytes.
 */
inline StormByte::Buffer::FIFO ReadAllFromConsumer(StormByte::Buffer::Consumer consumer) {
	StormByte::Buffer::FIFO data;
	while (!consumer.EoF()) {
		const StormByte::ByteSize available = consumer.Available();
		if (available == StormByte::ByteSize{0}) {
			std::this_thread::yield();
			continue;
		}

		StormByte::Safe::Binary bytes;
		if (!consumer.Read(available, bytes)) {
			std::cerr << "ReadAllFromConsumer: Read returned false, EoF=" << consumer.EoF()
				<< " writable=" << consumer.IsWritable() << std::endl;
			return data;
		}
		if (bytes.empty())
			std::cerr << "ReadAllFromConsumer: read zero bytes despite available data" << std::endl;

		data.Write(std::move(bytes));
	}
	return data;
}

/**
 * @brief Decode byte contents without discarding embedded NUL characters.
 * @param data Bytes to decode.
 * @return Text containing all bytes.
 */
inline StormByte::Safe::String DeserializeString(const StormByte::Safe::Binary& data) {
	if (data.empty())
		return {};
	return StormByte::Safe::String(std::string_view(reinterpret_cast<const char*>(data.data()), static_cast<std::size_t>(data.size())));
}

/**
 * @brief Decode all bytes held in a FIFO.
 * @param buffer Buffer to read.
 * @return Text containing the buffer contents.
 */
inline StormByte::Safe::String DeserializeString(const StormByte::Buffer::FIFO& buffer) {
	StormByte::Safe::Binary data;
	if (!const_cast<StormByte::Buffer::FIFO&>(buffer).Read(StormByte::ByteSize{0}, data))
		return {};
	return DeserializeString(data);
}
