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

#include <StormByte/safe/function.hxx>
#include <StormByte/safe/heap.hxx>
#include <StormByte/type_traits.hxx>

#include <memory>
#include <utility>

/**
 * @namespace StormByte
 * @brief Root namespace of the StormByte suite.
 */
namespace StormByte {
	/**
	 * @namespace StormByte::Crypto
	 * @brief Crypto module of the StormByte suite.
	 */
	namespace Crypto {
		/**
		 * @namespace StormByte::Crypto::Helpers
		 * @brief Private helpers of the Crypto module.
		 */
		namespace Helpers {
			/**
			 * @brief Construct a private callback context on Base's heap.
			 * @tparam Context Creator-module context type.
			 * @tparam Source Forwarded source context type.
			 * @param source Context to copy or move into Base-owned storage.
			 * @return Constructed context; released by the creator module.
			 * @throws StormByte::Exception Base allocation failure.
			 */
			template<class Context, class Source>
			Context* AllocateCallback(Source&& source) {
				void* storage = Safe::Heap::Allocate(sizeof(Context));
				try {
					return std::construct_at(static_cast<Context*>(storage), std::forward<Source>(source));
				} catch (...) {
					Safe::Heap::Free(storage);
					throw;
				}
			}

			/**
			 * @brief Bind a private void callback to the real Safe context lifecycle.
			 * @tparam Args Safe callback argument types.
			 * @tparam Callable Copyable creator-module callable type.
			 * @param callable Operation whose captures remain owned by Crypto.
			 * @return Callback with independent context cloning and matching release.
			 * @throws StormByte::Exception Base allocation or callback construction failure.
			 * @note Crypto and Base must remain loaded until every callback copy is released.
			 */
			template<class... Args, Type::CopyConstructible Callable>
			Safe::Function<void(Args...)> MakeCallback(Callable callable) {
				auto release = +[](void* context) noexcept {
					std::destroy_at(static_cast<Callable*>(context));
					Safe::Heap::Free(context);
				};
				Callable* context = AllocateCallback<Callable>(std::move(callable));
				try {
					return Safe::Function<void(Args...)>(context,
						+[](void* state, Args... args) -> Safe::Status {
							(*static_cast<Callable*>(state))(std::forward<Args>(args)...);
							return Safe::Status::Success;
						},
						+[](const void* state) noexcept -> void* {
							try {
								return AllocateCallback<Callable>(*static_cast<const Callable*>(state));
							} catch (...) {
								return nullptr;
							}
						}, release);
				} catch (...) {
					release(context);
					throw;
				}
			}
		}
	}
}