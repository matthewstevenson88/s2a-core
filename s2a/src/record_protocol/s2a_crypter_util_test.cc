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

#include "s2a/src/record_protocol/s2a_crypter_util.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "s2a/src/test_util/s2a_test_util.h"

namespace s2a {
namespace {

using ::absl::Status;
using ::absl::StatusCode;
using ::s2a::test_util::StatusIs;
using Ciphersuite = ::s2a::s2a_options::S2AOptions::Ciphersuite;

TEST(S2ACrypterUtilTest, HashFunctionIsNullptr) {
  EXPECT_THAT(CiphersuiteToHashFunction(Ciphersuite::AES_128_GCM_SHA256,
                                        /*hash_function=*/nullptr),
              StatusIs(StatusCode::kInvalidArgument,
                       "|hash_function| must not be nullptr."));
}

TEST(S2ACrypterUtilTest, CiphersuiteToHashFunction) {
  const struct {
    std::string description;
    Ciphersuite ciphersuite;
    hkdf::HashFunction hash_function;
    Status status;
  } tests[] = {
      {"AES-128-GCM-SHA256: ", Ciphersuite::AES_128_GCM_SHA256,
       hkdf::HashFunction::SHA256_hash_function, Status()},
      {"AES-256-GCM-SHA384: ", Ciphersuite::AES_256_GCM_SHA384,
       hkdf::HashFunction::SHA384_hash_function, Status()},
      {"CHACHA20-POLY1305-SHA256: ", Ciphersuite::CHACHA20_POLY1305_SHA256,
       hkdf::HashFunction::SHA256_hash_function, Status()},
  };
  for (size_t i = 0; i < sizeof(tests) / sizeof(*tests); i++) {
    // The value of |hash_function| must be initialized, but the initial value
    // is ignored.
    hkdf::HashFunction hash_function = hkdf::HashFunction::SHA256_hash_function;
    EXPECT_THAT(CiphersuiteToHashFunction(tests[i].ciphersuite, &hash_function),
                StatusIs(tests[i].status.code(), tests[i].status.message()));
    EXPECT_THAT(hash_function, tests[i].hash_function) << tests[i].description;
  }
}

}  // namespace
}  // namespace s2a
