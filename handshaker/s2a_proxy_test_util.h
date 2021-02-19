/*
 *
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef HANDSHAKER_S2A_PROXY_TEST_UTIL_H_
#define HANDSHAKER_S2A_PROXY_TEST_UTIL_H_

#include "handshaker/s2a_context.h"
#include "handshaker/s2a_proxy.h"

namespace s2a {
namespace s2a_proxy {

std::unique_ptr<s2a_context::S2AContext> CreateTestContext();

std::unique_ptr<S2AProxy> CreateTestProxy(bool has_handshake_result,
                                          bool is_client);

}  // namespace s2a_proxy
}  // namespace s2a

#endif  // HANDSHAKER_S2A_PROXY_TEST_UTIL_H_
