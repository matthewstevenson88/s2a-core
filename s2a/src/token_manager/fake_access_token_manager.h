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

#ifndef S2A_SRC_TOKEN_MANAGER_FAKE_ACCESS_TOKEN_MANAGER_H_
#define S2A_SRC_TOKEN_MANAGER_FAKE_ACCESS_TOKEN_MANAGER_H_

#include <string>

#include "s2a/include/access_token_manager.h"

namespace s2a {
namespace token_manager {
namespace testing {

constexpr char kFakeS2AAccessToken[] = "fake_s2a_access_token";

// A fake |AccessTokenManager| for use in tests.
class FakeAccessTokenManager : public AccessTokenManagerInterface {
 public:
  FakeAccessTokenManager();

  // Copy and copy assignment of |FakeAccessTokenManager| are disallowed.
  FakeAccessTokenManager(const FakeAccessTokenManager& other) = delete;
  FakeAccessTokenManager& operator=(const FakeAccessTokenManager& other) =
      delete;

  // |GetDefaultToken| always returns |kFakeS2AAccessToken|.
  absl::StatusOr<std::string> GetDefaultToken() override;

  // |GetToken| always returns |kFakeS2AAccessToken|.
  absl::StatusOr<std::string> GetToken(
      const s2a_options::S2AOptions::Identity& identity) override;

  std::string DebugName() const override;
};

}  // namespace testing
}  // namespace token_manager
}  // namespace s2a

#endif  // S2A_SRC_TOKEN_MANAGER_FAKE_ACCESS_TOKEN_MANAGER_H_
