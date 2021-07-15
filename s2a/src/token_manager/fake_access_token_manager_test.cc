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

#include "s2a/src/token_manager/fake_access_token_manager.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "s2a/include/access_token_manager_factory.h"
#include "s2a/include/s2a_options.h"

namespace s2a {
namespace token_manager {
namespace testing {
namespace {

using ::absl::StatusOr;

TEST(FakeAccessTokenManagerTest, GetDefaultToken) {
  FakeAccessTokenManager manager;
  StatusOr<std::string> token = manager.GetDefaultToken();
  EXPECT_TRUE(token.ok());
  EXPECT_EQ(*token, kFakeS2AAccessToken);
}

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
