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

#include "src/token_manager/fake_access_token_manager.h"

namespace s2a {
namespace token_manager {
namespace testing {

FakeAccessTokenManager::FakeAccessTokenManager() {}

absl::StatusOr<std::string> FakeAccessTokenManager::GetDefaultToken() {
  return kFakeS2AAccessToken;
}

absl::StatusOr<std::string> FakeAccessTokenManager::GetToken(
    const s2a_options::S2AOptions::Identity& identity) {
  return kFakeS2AAccessToken;
}

std::string FakeAccessTokenManager::DebugName() const {
  return "FakeAccessTokenManager";
}

}  // namespace testing

absl::StatusOr<std::unique_ptr<AccessTokenManagerInterface>>
BuildAccessTokenManager() {
  return absl::make_unique<testing::FakeAccessTokenManager>();
}

}  // namespace token_manager
}  // namespace s2a
