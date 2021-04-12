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
#   This BUILD file contains targets for the S2A client's record protocol.

load("//:acl.bzl", "approved_s2a_core_users")

licenses(["notice"])

cc_library(
    name = "handshake_message_handler",
    srcs = [
        "handshake_message_handler.cc",
    ],
    hdrs = [
        "handshake_message_handler.h",
    ],
    deps = [
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/types:variant",
    ],
)

cc_test(
    name = "handshake_message_handler_test",
    srcs = ["handshake_message_handler_test.cc"],
    deps = [
        ":handshake_message_handler",
        "//test_util:s2a_test_util",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "s2a_crypter",
    srcs = [
        "s2a_crypter.cc",
        "s2a_crypter_util.cc",
        "s2a_half_connection.cc",
    ],
    hdrs = [
        "s2a_crypter.h",
        "s2a_crypter_util.h",
        "s2a_half_connection.h",
    ],
    visibility = approved_s2a_core_users,
    deps = [
        "//channel:s2a_channel",
        ":handshake_message_handler",
        # TODO(matthewstevenson88): Switch to link in the UPB ticket sender.
        ":s2a_upb_ticket_sender",
        ":s2a_ticket_sender",
        "//:s2a_constants",
        "//options:s2a_options",
        "//crypto:hkdf",
        "//crypto:s2a_aead_crypter",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/types:variant",
    ],
)

cc_test(
    name = "s2a_crypter_test",
    srcs = ["s2a_crypter_test.cc"],
    deps = [
        ":handshake_message_handler",
        ":s2a_crypter",
        "//test_util:s2a_test_util",
        # TODO(matthewstevenson88): Switch to link in the UPB ticket sender.
        ":s2a_upb_ticket_sender",
        ":s2a_ticket_sender",
        "//:s2a_constants",
        "//options:s2a_options",
        "//test_util:s2a_test_data",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "s2a_crypter_roundtrip_test",
    srcs = ["s2a_crypter_roundtrip_test.cc"],
    deps = [
        ":s2a_crypter",
        "//:s2a_constants",
        "//options:s2a_options",
        "//test_util:s2a_test_data",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "s2a_crypter_util_test",
    srcs = ["s2a_crypter_util_test.cc"],
    deps = [
        ":s2a_crypter",
        "//test_util:s2a_test_util",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "s2a_half_connection_test",
    srcs = ["s2a_half_connection_test.cc"],
    deps = [
        ":s2a_crypter",
        "//:s2a_constants",
        "//options:s2a_options",
        "//test_util:s2a_test_util",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "s2a_ticket_sender",
    hdrs = [
        "s2a_ticket_sender.h",
    ],
    visibility = approved_s2a_core_users,
    deps = [
        "//channel:s2a_channel",
        "//options:s2a_options",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "s2a_upb_ticket_sender",
    srcs = [
        "s2a_upb_ticket_sender.cc",
    ],
    deps = [
        ":s2a_ticket_sender",
        "//options:s2a_options",
        "//proto/upb-generated/proto:common_upb_proto",
        "//proto/upb-generated/proto:s2a_upb_proto",
        "@com_google_absl//absl/strings",
        "@upb",
    ],
)

cc_test(
    name = "s2a_upb_ticket_sender_test",
    srcs = [
        "s2a_upb_ticket_sender_test.cc",
    ],
    deps = [
        ":s2a_ticket_sender",
        ":s2a_upb_ticket_sender",
        "//proto/upb-generated/proto:common_upb_proto",
        "//proto/upb-generated/proto:s2a_upb_proto",
        "@com_google_googletest//:gtest_main",
        "@upb",
    ],
)
