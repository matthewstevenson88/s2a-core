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
#   Bazel targets for the S2A's C++ client libraries. Users MUST only use the
#   targets marked as public APIs; otherwise, users risk being broken.

load(":acl.bzl", "approved_s2a_core_users")
load("@rules_foreign_cc//foreign_cc:configure.bzl", "configure_make")

licenses(["notice"])

exports_files(["LICENSE"])

# ---------------- Public APIs. ----------------

# Monolithic target for users that want simpler dependency management.
cc_library(
    name = "s2a_core",
    srcs = [
        "s2a/src/frame_protector/s2a_frame_protector.cc",
        "s2a/src/handshaker/s2a_context.cc",
        "s2a/src/handshaker/s2a_proxy.cc",
        "s2a/src/options/s2a_options.cc",
    ],
    hdrs = [
        "s2a/include/access_token_manager.h",
        "s2a/include/access_token_manager_factory.h",
        "s2a/include/s2a_channel_factory_interface.h",
        "s2a/include/s2a_channel_interface.h",
        "s2a/include/s2a_constants.h",
        "s2a/include/s2a_context.h",
        "s2a/include/s2a_frame_protector.h",
        "s2a/include/s2a_options.h",
        "s2a/include/s2a_proxy.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":s2a_crypter",
        ":s2a_ticket_sender",
        ":s2a_util",
        "//s2a/src/proto/upb-generated/proto:common_upb_proto",
        "//s2a/src/proto/upb-generated/proto:s2a_context_upb_proto",
        "//s2a/src/proto/upb-generated/proto:s2a_upb_proto",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/hash",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/types:variant",
        "@upb"
    ],
)

cc_library(
    name = "s2a_channel",
    hdrs = [
        "s2a/include/s2a_channel_factory_interface.h",
        "s2a/include/s2a_channel_interface.h",
    ],
    visibility = approved_s2a_core_users,
    deps = [
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
    ],
)

cc_library(
    name = "s2a_constants",
    hdrs = ["s2a/include/s2a_constants.h"],
    visibility = approved_s2a_core_users,
    deps = [
        "//s2a/src/proto/upb-generated/proto:common_upb_proto",
        "//s2a/src/proto/upb-generated/proto:s2a_context_upb_proto",
        "//s2a/src/proto/upb-generated/proto:s2a_upb_proto",
    ],
)

cc_library(
    name = "s2a_options",
    srcs = ["s2a/src/options/s2a_options.cc"],
    hdrs = ["s2a/include/s2a_options.h"],
    visibility = approved_s2a_core_users,
    deps = [
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/hash",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:variant",
    ],
)

cc_library(
    name = "access_token_manager",
    hdrs = [
        "s2a/include/access_token_manager.h",
        "s2a/include/access_token_manager_factory.h",
    ],
    visibility = approved_s2a_core_users,
    deps = [
        ":s2a_options",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "s2a_frame_protector",
    srcs = [
        "s2a/src/frame_protector/s2a_frame_protector.cc",
    ],
    hdrs = [
        "s2a/include/s2a_frame_protector.h",
    ],
    visibility = approved_s2a_core_users,
    deps = [
        ":s2a_channel",
        ":s2a_constants",
        ":s2a_crypter",
        ":s2a_options",
        ":s2a_ticket_sender",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/types:variant",
    ],
)

cc_library(
    name = "s2a_context",
    srcs = ["s2a/src/handshaker/s2a_context.cc"],
    hdrs = ["s2a/include/s2a_context.h"],
    visibility = approved_s2a_core_users,
    deps = [
        ":s2a_options",
        ":s2a_util",
        "//s2a/src/proto/upb-generated/proto:common_upb_proto",
        "//s2a/src/proto/upb-generated/proto:s2a_context_upb_proto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/types:variant",
        "@upb",
    ],
)

cc_library(
    name = "s2a_proxy",
    srcs = [
        "s2a/src/handshaker/s2a_proxy.cc",
    ],
    hdrs = [
        "s2a/include/s2a_proxy.h",
    ],
    visibility = approved_s2a_core_users,
    deps = [
        ":access_token_manager",
        ":s2a_channel",
        ":s2a_context",
        ":s2a_constants",
        ":s2a_frame_protector",
        ":s2a_options",
        ":s2a_util",
        "//s2a/src/proto/upb-generated/proto:common_upb_proto",
        "//s2a/src/proto/upb-generated/proto:s2a_upb_proto",
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

# ---------------- Internal APIs. ----------------

cc_library(
    name = "hkdf",
    srcs = [
        "s2a/src/crypto/hkdf.cc",
    ],
    hdrs = ["s2a/src/crypto/hkdf.h"],
    deps = [
        "@boringssl//:crypto",
        "@com_google_absl//absl/status",
    ],
)

cc_library(
    name = "s2a_aead_crypter",
    srcs = [
        "s2a/src/crypto/aes_gcm_crypter.cc",
        "s2a/src/crypto/chacha_poly_crypter_boringssl.cc",
        "s2a/src/crypto/chacha_poly_crypter_openssl.cc",
        "s2a/src/crypto/s2a_aead_crypter.cc",
    ],
    hdrs = [
        "s2a/src/crypto/s2a_aead_constants.h",
        "s2a/src/crypto/s2a_aead_crypter.h",
    ],
    deps = [
        ":s2a_aead_crypter_util",
        "@boringssl//:crypto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:variant",
    ],
)

cc_library(
    name = "s2a_aead_crypter_util",
    srcs = [
        "s2a/src/crypto/s2a_aead_crypter_util.cc",
    ],
    hdrs = ["s2a/src/crypto/s2a_aead_crypter_util.h"],
    deps = [
        "@boringssl//:crypto",
    ],
)

cc_library(
    name = "s2a_util",
    srcs = [
        "s2a/src/handshaker/s2a_util.cc",
    ],
    hdrs = [
        "s2a/src/handshaker/s2a_util.h",
    ],
    deps = [
        ":s2a_options",
        "//s2a/src/proto/upb-generated/proto:common_upb_proto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/types:variant",
        "@upb",
    ],
)

cc_library(
    name = "handshake_message_handler",
    srcs = [
        "s2a/src/record_protocol/handshake_message_handler.cc",
    ],
    hdrs = [
        "s2a/src/record_protocol/handshake_message_handler.h",
    ],
    deps = [
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/types:variant",
    ],
)

cc_library(
    name = "s2a_crypter",
    srcs = [
        "s2a/src/record_protocol/s2a_crypter.cc",
        "s2a/src/record_protocol/s2a_crypter_util.cc",
        "s2a/src/record_protocol/s2a_half_connection.cc",
    ],
    hdrs = [
        "s2a/src/record_protocol/s2a_crypter.h",
        "s2a/src/record_protocol/s2a_crypter_util.h",
        "s2a/src/record_protocol/s2a_half_connection.h",
    ],
    visibility = approved_s2a_core_users,
    deps = [
        ":handshake_message_handler",
        # TODO(matthewstevenson88): Switch to link in the UPB ticket sender.
        ":s2a_upb_ticket_sender",
        ":s2a_ticket_sender",
        ":s2a_channel",
        ":s2a_constants",
        ":s2a_options",
        ":hkdf",
        ":s2a_aead_crypter",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/types:variant",
    ],
)

cc_library(
    name = "s2a_ticket_sender",
    hdrs = [
        "s2a/src/record_protocol/s2a_ticket_sender.h",
    ],
    visibility = approved_s2a_core_users,
    deps = [
        ":s2a_channel",
        ":s2a_options",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "s2a_upb_ticket_sender",
    srcs = [
        "s2a/src/record_protocol/s2a_upb_ticket_sender.cc",
    ],
    deps = [
        ":s2a_options",
        ":s2a_ticket_sender",
        "//s2a/src/proto/upb-generated/proto:common_upb_proto",
        "//s2a/src/proto/upb-generated/proto:s2a_upb_proto",
        "@com_google_absl//absl/strings",
        "@upb",
    ],
)

# TODO(matthewstevenson88) Use a registry to build access token managers.
cc_library(
    name = "single_token_access_token_manager",
    srcs = ["s2a/src/token_manager/single_token_access_token_manager.cc"],
    hdrs = ["s2a/src/token_manager/single_token_access_token_manager.h"],
    visibility = approved_s2a_core_users,
    deps = [
        ":access_token_manager",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)

# ---------------- src/crypto tests and test utilities. ----------------

# Built against BoringSSL.

cc_library(
    name = "s2a_aead_crypter_test_util",
    srcs = ["s2a/src/crypto/s2a_aead_crypter_test_util.cc"],
    hdrs = ["s2a/src/crypto/s2a_aead_crypter_test_util.h"],
    deps = [
        ":s2a_aead_crypter",
        "@com_google_absl//absl/base:core_headers",
    ],
)

cc_test(
    name = "hkdf_test",
    srcs = ["s2a/src/crypto/hkdf_test.cc"],
    deps = [
        ":hkdf",
        ":s2a_test_util",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "s2a_aead_crypter_test",
    srcs = ["s2a/src/crypto/s2a_aead_crypter_test.cc"],
    deps = [
        ":s2a_aead_crypter",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "aes_gcm_crypter_test",
    srcs = ["s2a/src/crypto/aes_gcm_crypter_test.cc"],
    deps = [
        ":s2a_aead_crypter",
        ":s2a_aead_crypter_test_util",
        ":s2a_test_util",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "chacha_poly_crypter_test",
    srcs = ["s2a/src/crypto/chacha_poly_crypter_test.cc"],
    deps = [
        ":s2a_aead_crypter",
        ":s2a_aead_crypter_test_util",
        ":s2a_test_util",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "s2a_aead_crypter_util_test",
    srcs = [
        "s2a/src/crypto/s2a_aead_crypter_util_test.cc",
    ],
    deps = [
        ":s2a_aead_crypter_util",
        "@boringssl//:crypto",
        "@boringssl//:ssl",
        "@com_google_googletest//:gtest_main",
    ],
)

# Built against OpenSSL.

config_setting(
    name = "darwin_build",
    values = {"cpu" : "darwin"},
)

configure_make(
    name = "openssl",
    configure_command = "config",
    configure_options = select({
        ":darwin_build" : [
            "shared", "ARFLAGS=r",
            "enable-ec_nistp_64_gcc_128",
            "no-ssl2", "no-ssl3", "no-comp"
            ],
        "//conditions:default" : []
    }),
    lib_source = "@openssl//:all",
    configure_env_vars = select({
        ":darwin_build" : {
            "OSX_DEPLOYMENT_TARGET" : "10.14",
            "AR" : "",
        },
        "//conditions:default" : {}
    }),
    out_shared_libs = select({
        ":darwin_build" : [
            "libssl.dylib",
            "libcrypto.dylib",
        ],
        "//conditions:default" : [
            "libssl.so",
            "libcrypto.so",
        ],
    }),
    tags = ["openssl"],
)

cc_library(
    name = "aes_gcm_crypter_openssl",
    testonly = 1,
    srcs = [
        "s2a/src/crypto/aes_gcm_crypter.cc",
        "s2a/src/crypto/s2a_aead_crypter.cc",
    ],
    hdrs = [
        "s2a/src/crypto/s2a_aead_constants.h",
        "s2a/src/crypto/s2a_aead_crypter.h",
    ],
    tags = ["openssl"],
    deps = [
        ":openssl",
        ":s2a_aead_crypter_util",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:variant",
    ],
)

cc_library(
    name = "chacha_poly_crypter_openssl",
    testonly = 1,
    srcs = [
        "s2a/src/crypto/chacha_poly_crypter_openssl.cc",
        "s2a/src/crypto/s2a_aead_crypter.cc",
        "s2a/src/crypto/s2a_aead_crypter_util.cc",
    ],
    hdrs = [
        "s2a/src/crypto/s2a_aead_constants.h",
        "s2a/src/crypto/s2a_aead_crypter.h",
        "s2a/src/crypto/s2a_aead_crypter_util.h",
    ],
    tags = ["openssl"],
    deps = [
        ":openssl",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:variant",
    ],
)

cc_library(
    name = "hkdf_openssl",
    testonly = 1,
    srcs = [
        "s2a/src/crypto/hkdf.cc",
    ],
    hdrs = ["s2a/src/crypto/hkdf.h"],
    tags = ["openssl"],
    deps = [
        ":openssl",
        "@com_google_absl//absl/status",
    ],
)

cc_library(
    name = "s2a_aead_crypter_util_openssl",
    testonly = 1,
    srcs = [
        "s2a/src/crypto/s2a_aead_crypter_util.cc",
    ],
    hdrs = ["s2a/src/crypto/s2a_aead_crypter_util.h"],
    tags = ["openssl"],
    deps = [
        ":openssl",
    ],
)

cc_test(
    name = "aes_gcm_crypter_openssl_test",
    srcs = ["s2a/src/crypto/aes_gcm_crypter_test.cc"],
    tags = ["openssl"],
    deps = [
        ":aes_gcm_crypter_openssl",
        ":s2a_aead_crypter_test_util",
        ":s2a_test_util",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "chacha_poly_crypter_openssl_test",
    srcs = ["s2a/src/crypto/chacha_poly_crypter_test.cc"],
    tags = ["openssl"],
    deps = [
        ":chacha_poly_crypter_openssl",
        ":s2a_aead_crypter_test_util",
        ":s2a_test_util",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "hkdf_openssl_test",
    srcs = ["s2a/src/crypto/hkdf_test.cc"],
    tags = ["openssl"],
    deps = [
        ":hkdf_openssl",
        ":s2a_test_util",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "s2a_aead_crypter_util_openssl_test",
    srcs = [
        "s2a/src/crypto/s2a_aead_crypter_util_test.cc",
    ],
    tags = ["openssl"],
    deps = [
        ":s2a_aead_crypter_util_openssl",
        ":openssl",
        "@com_google_googletest//:gtest_main",
    ],
)

# ---------------- src/frame_protector tests and test utilities. ----------------

cc_test(
    name = "s2a_frame_protector_test",
    srcs = ["s2a/src/frame_protector/s2a_frame_protector_test.cc"],
    deps = [
        ":s2a_constants",
        ":s2a_frame_protector",
        ":s2a_crypter",
        ":s2a_test_data",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest_main",
    ],
)

# ---------------- src/handshaker tests and test utilities. ----------------

cc_library(
    name = "s2a_proxy_test_util",
    testonly = 1,
    srcs = [
        "s2a/src/handshaker/s2a_proxy_test_util.cc",
    ],
    hdrs = [
        "s2a/src/handshaker/s2a_proxy_test_util.h",
    ],
    visibility = approved_s2a_core_users,
    deps = [
        ":s2a_context",
        ":s2a_proxy",
        ":s2a_options",
        "//s2a/src/proto/upb-generated/proto:common_upb_proto",
        "//s2a/src/proto/upb-generated/proto:s2a_upb_proto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/types:variant",
        "@upb",
    ],
)

cc_test(
    name = "s2a_context_test",
    srcs = ["s2a/src/handshaker/s2a_context_test.cc"],
    deps = [
        ":s2a_context",
        ":s2a_util",
        ":s2a_options",
        "//s2a/src/proto/upb-generated/proto:common_upb_proto",
        "//s2a/src/proto/upb-generated/proto:s2a_context_upb_proto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/types:variant",
        "@com_google_googletest//:gtest_main",
        "@upb",
    ],
)

cc_test(
    name = "s2a_proxy_test",
    srcs = ["s2a/src/handshaker/s2a_proxy_test.cc"],
    deps = [
        ":s2a_context",
        ":s2a_proxy",
        ":s2a_constants",
        ":s2a_frame_protector",
        "//s2a/src/proto/upb-generated/proto:common_upb_proto",
        "//s2a/src/proto/upb-generated/proto:s2a_upb_proto",
        ":fake_access_token_manager",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest_main",
        "@upb",
    ],
)

cc_test(
    name = "s2a_util_test",
    srcs = ["s2a/src/handshaker/s2a_util_test.cc"],
    deps = [
        ":s2a_util",
        ":s2a_options",
        "//s2a/src/proto/upb-generated/proto:common_upb_proto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/types:variant",
        "@com_google_googletest//:gtest_main",
        "@upb",
    ],
)

# ---------------- src/options tests and test utilities. ----------------

cc_test(
    name = "s2a_options_test",
    srcs = ["s2a/src/options/s2a_options_test.cc"],
    deps = [
        ":s2a_options",
        "@com_google_googletest//:gtest_main",
    ],
)

# ---------------- src/record_protocol tests and test utilities. ----------------

cc_test(
    name = "s2a_crypter_test",
    srcs = ["s2a/src/record_protocol/s2a_crypter_test.cc"],
    deps = [
        ":handshake_message_handler",
        ":s2a_crypter",
        ":s2a_test_util",
        # TODO(matthewstevenson88): Switch to link in the UPB ticket sender.
        ":s2a_upb_ticket_sender",
        ":s2a_ticket_sender",
        ":s2a_constants",
        ":s2a_options",
        ":s2a_test_data",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "s2a_crypter_roundtrip_test",
    srcs = ["s2a/src/record_protocol/s2a_crypter_roundtrip_test.cc"],
    deps = [
        ":s2a_crypter",
        ":s2a_constants",
        ":s2a_options",
        ":s2a_test_data",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "s2a_crypter_util_test",
    srcs = ["s2a/src/record_protocol/s2a_crypter_util_test.cc"],
    deps = [
        ":s2a_crypter",
        ":s2a_test_util",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "s2a_half_connection_test",
    srcs = ["s2a/src/record_protocol/s2a_half_connection_test.cc"],
    deps = [
        ":s2a_crypter",
        ":s2a_constants",
        ":s2a_options",
        ":s2a_test_util",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "s2a_upb_ticket_sender_test",
    srcs = [
        "s2a/src/record_protocol/s2a_upb_ticket_sender_test.cc",
    ],
    deps = [
        ":s2a_ticket_sender",
        ":s2a_upb_ticket_sender",
        "//s2a/src/proto/upb-generated/proto:common_upb_proto",
        "//s2a/src/proto/upb-generated/proto:s2a_upb_proto",
        "@com_google_googletest//:gtest_main",
        "@upb",
    ],
)

# ---------------- src/test_util tests and test utilities. ----------------

cc_library(
    name = "s2a_test_data",
    hdrs = [
        "s2a/src/test_util/s2a_test_data.h",
    ],
    visibility = approved_s2a_core_users,
)

cc_library(
    name = "s2a_test_util",
    testonly = 1,
    hdrs = [
        "s2a/src/test_util/s2a_test_util.h",
    ],
    deps = [
        "@com_google_googletest//:gtest",
    ],
)

# ---------------- src/token_manager tests and test utilities. ----------------

cc_library(
    name = "fake_access_token_manager",
    testonly = 1,
    srcs = ["s2a/src/token_manager/fake_access_token_manager.cc"],
    hdrs = ["src/token_manager/fake_access_token_manager.h"],
    visibility = approved_s2a_core_users,
    deps = [
        ":access_token_manager",
        "@com_google_absl//absl/status:statusor",
    ],
)

cc_test(
    name = "fake_access_token_manager_test",
    srcs = ["s2a/src/token_manager/fake_access_token_manager_test.cc"],
    deps = [
        ":fake_access_token_manager",
        ":access_token_manager",
        ":s2a_options",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "single_token_access_token_manager_test",
    srcs = ["s2a/src/token_manager/single_token_access_token_manager_test.cc"],
    deps = [
        ":single_token_access_token_manager",
        ":access_token_manager",
        ":s2a_options",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest_main",
    ],
)

