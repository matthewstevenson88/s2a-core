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

#include "token_manager/fake_access_token_manager.h"

#include "options/s2a_options.h"
#include "token_manager/access_token_manager_factory.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace s2a {
namespace token_manager {
namespace testing {
namespace {

using ::absl::StatusOr;

TEST(FakeAccessTokenManagerTest, GetToken) {
  s2a_options::S2AOptions::Identity identity =
      s2a_options::S2AOptions::Identity::GetEmptyIdentity();
  FakeAccessTokenManager manager;
  StatusOr<std::string> token = manager.GetToken(identity);
  EXPECT_TRUE(token.ok());
  EXPECT_EQ(*token, kFakeS2AAccessToken);
}

TEST(FakeAccessTokenManagerTest, BuilderSuccess) {
  absl::StatusOr<std::unique_ptr<AccessTokenManagerInterface>> manager =
      BuildAccessTokenManager();
  EXPECT_TRUE(manager.ok());
  EXPECT_EQ((*manager)->DebugName(), "FakeAccessTokenManager");
}

}  // namespace
}  // namespace testing
}  // namespace token_manager
}  // namespace s2a
