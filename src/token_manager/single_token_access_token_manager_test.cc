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

#include "src/token_manager/single_token_access_token_manager.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "include/access_token_manager_factory.h"
#include "include/s2a_options.h"

namespace s2a {
namespace token_manager {
namespace {

TEST(SingleTokenAccessTokenManagerTest, FromEnvironmentVariable) {
  // The |S2A_ACCESS_TOKEN| environment variable should be set to
  // "s2a_access_token_from_env_variable" in `env` attribute of this `cc_test`
  // rule.
  s2a_options::S2AOptions::Identity identity =
      s2a_options::S2AOptions::Identity::GetEmptyIdentity();
  SingleTokenAccessTokenManager manager;
  absl::StatusOr<std::string> token = manager.GetToken(identity);
  EXPECT_TRUE(token.ok());
  EXPECT_EQ(*token, "s2a_access_token_from_env_variable");
}

TEST(SingleTokenAccessTokenManagerTest, BuilderSuccess) {
  absl::StatusOr<std::unique_ptr<AccessTokenManagerInterface>> manager =
      BuildAccessTokenManager();
  EXPECT_TRUE(manager.ok());
  EXPECT_EQ((*manager)->DebugName(), "SingleTokenAccessTokenManager");
}

}  // namespace
}  // namespace token_manager
}  // namespace s2a
