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

#ifndef TOKEN_MANAGER_SINGLE_TOKEN_ACCESS_TOKEN_MANAGER_H_
#define TOKEN_MANAGER_SINGLE_TOKEN_ACCESS_TOKEN_MANAGER_H_

#include "token_manager/access_token_manager.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace s2a {
namespace token_manager {

#define S2A_SINGLE_TOKEN_ACCESS_TOKEN_MANAGER

// The environment variable that stores the access token that will be attached
// to requests to S2A.
constexpr char kAccessTokenEnvironmentVariable[] = "S2A_ACCESS_TOKEN";

// Fetches a single access token via an environment variable.
class SingleTokenAccessTokenManager : public AccessTokenManagerInterface {
 public:
  SingleTokenAccessTokenManager();

  // Copy and copy assignment of |SingleTokenAccessTokenManager| are disallowed.
  SingleTokenAccessTokenManager(const SingleTokenAccessTokenManager& other) =
      delete;
  SingleTokenAccessTokenManager& operator=(
      const SingleTokenAccessTokenManager& other) = delete;

  // |GetToken| fetches an access token for an application to authenticate to
  // the S2A, or returns an error status if a token can not be retrieved. The
  // |identity| is ignored.
  absl::StatusOr<std::string> GetToken(
      const s2a_options::S2AOptions::Identity& identity) override;

  std::string DebugName() const override;

 private:
  absl::StatusOr<std::string> token_;
};

}  // namespace token_manager
}  // namespace s2a

#endif  // TOKEN_MANAGER_SINGLE_TOKEN_ACCESS_TOKEN_MANAGER_H_
