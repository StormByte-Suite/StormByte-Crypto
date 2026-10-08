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

#include <StormByte/safe/binary.hxx>
#include <StormByte/type_traits/safe.hxx>

#include <span>

/**
 * @namespace StormByte::Crypto::Engine::Hasher
 * @brief Private hasher implementation.
 */
namespace StormByte::Crypto::Engine::Hasher {
	/**
	 * @struct Ops
	 * @brief Chunk-oriented hash engine whose concrete lifetime stays in Crypto.
	 */
	struct Ops {
		/**
		 * @brief Construct an engine interface.
		 */
		Ops() = default;

		/**
		 * @brief Engine interfaces cannot be copied.
		 * @param other Source interface.
		 */
		Ops(const Ops&) = delete;

		/**
		 * @brief Engine interfaces cannot be moved.
		 * @param other Source interface.
		 */
		Ops(Ops&&) = delete;

		/**
		 * @brief Destroy the concrete engine in Crypto.
		 */
		virtual ~Ops() = default;

		/**
		 * @brief Engine interfaces cannot be copy-assigned.
		 * @param other Source interface.
		 * @return This interface.
		 */
		Ops& operator=(const Ops&) = delete;

		/**
		 * @brief Engine interfaces cannot be move-assigned.
		 * @param other Source interface.
		 * @return This interface.
		 */
		Ops& operator=(Ops&&) = delete;

		/**
		 * @brief Feed one borrowed chunk synchronously.
		 * @param input Input bytes, not retained.
		 */
		virtual void Update(std::span<const std::byte> input) = 0;

		/**
		 * @brief Finish and write the hexadecimal digest.
		 * @param output Base-owned destination.
		 * @return Whether finalization succeeded.
		 */
		virtual bool Finalize(Safe::Binary& output) = 0;
	};
}

/**
 * @brief Register only the private engine interface, not arbitrary derivatives.
 * @note Concrete destruction is retained by the Crypto-created Safe owner.
 *       The provider module must remain loaded for the owner's lifetime.
 */
STORMBYTE_DECLARE_MAYBE_SAFE(StormByte::Crypto::Engine::Hasher::Ops);