# Copyright 2020 Google LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Description:
#   This BUILD file contains targets and tests for the S2A client's options.

licenses(["notice"])

cc_library(
    name = "s2a_options",
    srcs = ["s2a_options.cc"],
    hdrs = ["s2a_options.h"],
    visibility = ["//visibility:public"],
    deps = [
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/hash",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:variant",
    ],
)

cc_test(
    name = "s2a_options_test",
    srcs = ["s2a_options_test.cc"],
    deps = [
        ":s2a_options",
        "@com_google_googletest//:gtest_main",
    ],
)
