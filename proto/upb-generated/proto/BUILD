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
#  This BUILD file contains targets for pre-generated UPB files.

cc_library(
    name = "common_upb_proto",
    srcs = ["common.upb.c"],
    hdrs = ["common.upb.h"],
    visibility = ["//:__subpackages__"],
    deps = ["@upb"],
)

cc_library(
    name = "s2a_upb_proto",
    srcs = ["s2a.upb.c"],
    hdrs = ["s2a.upb.h"],
    visibility = ["//:__subpackages__"],
    deps = [
        ":common_upb_proto",
        "@upb",
    ],
)

cc_library(
    name = "s2a_context_upb_proto",
    srcs = ["s2a_context.upb.c"],
    hdrs = ["s2a_context.upb.h"],
    visibility = ["//:__subpackages__"],
    deps = [
        ":common_upb_proto",
        "@upb",
    ],
)

