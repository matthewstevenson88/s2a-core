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

#ifndef INCLUDE_ACCESS_TOKEN_MANAGER_FACTORY_H_
#define INCLUDE_ACCESS_TOKEN_MANAGER_FACTORY_H_

#include <memory>

#include "absl/status/statusor.h"
#include "include/access_token_manager.h"

namespace s2a {
namespace token_manager {

// |BuildAccessTokenManager| creates a new instance of the access token manager
// based on whatever implementation is linked-in. If no access token manager is
// linked-in, returns an error status.
//
// This API is thread-safe.
absl::StatusOr<std::unique_ptr<AccessTokenManagerInterface>>
BuildAccessTokenManager();

}  // namespace token_manager
}  // namespace s2a

#endif  // INCLUDE_ACCESS_TOKEN_MANAGER_FACTORY_H_
