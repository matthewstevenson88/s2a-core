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
#   This BUILD file contains targets for the S2A client libraries's
#   access token manager and its environment-specific implementations.

licenses(["notice"])

# TODO(matthewstevenson88) Use a registry to build access token managers.
cc_library(
    name = "access_token_manager",
    hdrs = [
        "access_token_manager.h",
        "access_token_manager_factory.h",
    ],
    visibility = ["//handshaker:__pkg__"],
    deps = [
        "//options:s2a_options",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "single_token_access_token_manager",
    srcs = ["single_token_access_token_manager.cc"],
    hdrs = ["single_token_access_token_manager.h"],
    deps = [
        ":access_token_manager",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_library(
    name = "fake_access_token_manager",
    testonly = 1,
    srcs = ["fake_access_token_manager.cc"],
    hdrs = ["fake_access_token_manager.h"],
    visibility = [
        "//handshaker:__pkg__",
    ],
    deps = [
        ":access_token_manager",
        "@com_google_absl//absl/status:statusor",
    ],
)

cc_test(
    name = "fake_access_token_manager_test",
    srcs = ["fake_access_token_manager_test.cc"],
    deps = [
        ":access_token_manager",
        ":fake_access_token_manager",
        "//options:s2a_options",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "single_token_access_token_manager_test",
    srcs = ["single_token_access_token_manager_test.cc"],
    env = {
        "S2A_ACCESS_TOKEN": "s2a_access_token_from_env_variable",
    },
    deps = [
        ":access_token_manager",
        ":single_token_access_token_manager",
        "//options:s2a_options",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest_main",
    ],
)
