# Copyright 2021 Google LLC

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
#   This BUILD file contains proto targets for the S2A client libraries.

load("@upb//bazel:upb_proto_library.bzl", "upb_proto_library")

licenses(["notice"])

proto_library(
    name = "common_proto",
    srcs = ["common.proto"],
)

proto_library(
    name = "s2a_proto",
    srcs = ["s2a.proto"],
    deps = [":common_proto"],
)

proto_library(
    name = "s2a_context_proto",
    srcs = ["s2a_context.proto"],
    deps = [":common_proto"],
)

upb_proto_library(
    name = "s2a_upb_proto",
    visibility = ["//:__subpackages__"],
    deps = [":s2a_proto"],
)

upb_proto_library(
    name = "s2a_context_upb_proto",
    visibility = ["//:__subpackages__"],
    deps = [":s2a_context_proto"],
)

upb_proto_library(
    name = "common_upb_proto",
    visibility = ["//:__subpackages__"],
    deps = [":common_proto"],
)
