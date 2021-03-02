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
#   This BUILD file contains targets for the S2A client's handshaker modules.

load("//:acl.bzl", "approved_s2a_core_users")

licenses(["notice"])

cc_library(
    name = "s2a_proxy",
    srcs = [
        "s2a_proxy.cc",
    ],
    hdrs = [
        "s2a_proxy.h",
    ],
    visibility = approved_s2a_core_users,
    deps = [
        ":s2a_context",
        ":s2a_util",
        "//:s2a_constants",
        "//channel:s2a_channel",
        "//frame_protector:s2a_frame_protector",
        "//options:s2a_options",
        "//proto:common_upb_proto",
        "//proto:s2a_upb_proto",
        "//token_manager:access_token_manager",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/types:variant",
        "@upb",
    ],
)

cc_library(
    name = "s2a_util",
    srcs = [
        "s2a_util.cc",
    ],
    hdrs = [
        "s2a_util.h",
    ],
    deps = [
        "//options:s2a_options",
        "//proto:common_upb_proto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/types:variant",
        "@upb",
    ],
)

cc_library(
    name = "s2a_proxy_test_util",
    testonly = 1,
    srcs = [
        "s2a_proxy_test_util.cc",
    ],
    hdrs = [
        "s2a_proxy_test_util.h",
    ],
    visibility = approved_s2a_core_users,
    deps = [
        ":s2a_context",
        ":s2a_proxy",
        "//options:s2a_options",
        "//proto:common_upb_proto",
        "//proto:s2a_upb_proto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/types:variant",
        "@upb",
    ],
)

cc_library(
    name = "s2a_context",
    srcs = ["s2a_context.cc"],
    hdrs = ["s2a_context.h"],
    visibility = approved_s2a_core_users,
    deps = [
        ":s2a_util",
        "//options:s2a_options",
        "//proto:common_upb_proto",
        "//proto:s2a_context_upb_proto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/types:variant",
        "@upb",
    ],
)

cc_test(
    name = "s2a_context_test",
    srcs = ["s2a_context_test.cc"],
    deps = [
        ":s2a_context",
        ":s2a_util",
        "//options:s2a_options",
        "//proto:common_upb_proto",
        "//proto:s2a_context_upb_proto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/types:variant",
        "@com_google_googletest//:gtest_main",
        "@upb",
    ],
)

cc_test(
    name = "s2a_proxy_test",
    srcs = ["s2a_proxy_test.cc"],
    deps = [
        ":s2a_context",
        ":s2a_proxy",
        "//:s2a_constants",
        "//frame_protector:s2a_frame_protector",
        "//proto:common_upb_proto",
        "//proto:s2a_upb_proto",
        "//token_manager:fake_access_token_manager",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest_main",
        "@upb",
    ],
)

cc_test(
    name = "s2a_util_test",
    srcs = ["s2a_util_test.cc"],
    deps = [
        ":s2a_util",
        "//options:s2a_options",
        "//proto:common_upb_proto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/types:variant",
        "@com_google_googletest//:gtest_main",
        "@upb",
    ],
)
