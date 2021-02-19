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

#ifndef TOKEN_MANAGER_ACCESS_TOKEN_MANAGER_H_
#define TOKEN_MANAGER_ACCESS_TOKEN_MANAGER_H_

#include "options/s2a_options.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace s2a {
namespace token_manager {

// |AccessTokenManagerInterface| defines the APIs that should be implemented by
// all access token managers. Access token managers are the entities responsible
// for fetching access tokens provided by an application in order to
// authenticate to the S2A.
//
// All implementations must be thread-safe.
class AccessTokenManagerInterface {
 public:
  virtual ~AccessTokenManagerInterface() = default;

  // |GetToken| fetches an access token for an application with identity
  // |identity| to authenticate to the S2A, or returns an error status if a
  // token can not be retrieved.
  virtual absl::StatusOr<std::string> GetToken(
      const s2a_options::S2AOptions::Identity& identity) = 0;

  // |DebugName| returns the debug name of this instance of the access token
  // manager. The result of this API should only be used in debugging and/or
  // logging.
  virtual std::string DebugName() const = 0;
};

}  // namespace token_manager
}  // namespace s2a

#endif  // TOKEN_MANAGER_ACCESS_TOKEN_MANAGER_H_
