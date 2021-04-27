/*
 *
 * Copyright 2021 Google LLC
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

#ifndef SRC_TEST_UTIL_S2A_TEST_UTIL_H_
#define SRC_TEST_UTIL_S2A_TEST_UTIL_H_

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace s2a {
namespace test_util {

// Matches an |absl::Status| with the specified |absl::StatusCode| 'code'.
MATCHER_P(StatusIs, code, "") {
  if (arg.code() == code) {
    return true;
  }
  return false;
}

// Matches an |absl::Status| with the specified |absl::StatusCode| 'code' and
// error message 'message_macher'.
MATCHER_P2(StatusIs, code, message_matcher, "") {
  return (arg.code() == code) &&
         testing::Matches(message_matcher)(arg.message());
}

}  // namespace test_util
}  // namespace s2a

#endif  // SRC_TEST_UTIL_S2A_TEST_UTIL_H_
