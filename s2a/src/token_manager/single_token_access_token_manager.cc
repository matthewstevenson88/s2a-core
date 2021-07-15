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

#include "s2a/src/token_manager/single_token_access_token_manager.h"

#include <cstdlib>

#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "s2a/include/access_token_manager_factory.h"

namespace s2a {
namespace token_manager {

SingleTokenAccessTokenManager::SingleTokenAccessTokenManager() {
  const char* token = std::getenv(kAccessTokenEnvironmentVariable);
  if (token == nullptr) {
    token_ = absl::Status(absl::StatusCode::kNotFound,
                          absl::StrFormat("%s environment variable not found.",
                                          kAccessTokenEnvironmentVariable));
  } else {
    token_ = std::string(token);
  }
}

absl::StatusOr<std::string> SingleTokenAccessTokenManager::GetDefaultToken() {
  return token_;
}

absl::StatusOr<std::string> SingleTokenAccessTokenManager::GetToken(
    const s2a_options::S2AOptions::Identity& identity) {
  return token_;
}

std::string SingleTokenAccessTokenManager::DebugName() const {
  return "SingleTokenAccessTokenManager";
}

absl::StatusOr<std::unique_ptr<AccessTokenManagerInterface>>
BuildAccessTokenManager() {
  return absl::make_unique<SingleTokenAccessTokenManager>();
}

}  // namespace token_manager
}  // namespace s2a
