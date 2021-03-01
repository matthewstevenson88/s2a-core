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
#   This BUILD file contains test utilities for the S2A's client libraries.

licenses(["notice"])

cc_library(
    name = "s2a_test_data",
    hdrs = [
        "s2a_test_data.h",
    ],
    visibility = ["//:__subpackages__"],
)

cc_library(
    name = "s2a_test_util",
    testonly = 1,
    hdrs = [
        "s2a_test_util.h",
    ],
    visibility = [
        "//:__subpackages__",
    ],
    deps = [
        "@com_google_googletest//:gtest",
    ],
)
