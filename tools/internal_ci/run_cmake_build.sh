#!/bin/bash

# Copyright 2021 Google LLC
#
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

# Fail on any error.
set -e

# Display commands being run.
set -x

readonly PLATFORM="$(uname | tr '[:upper:]' '[:lower:]')"

git submodule update --init --recursive

case "${PLATFORM}" in
  'linux')
    echo "================================= Running cmake"
    cmake --version
    cmake . -DDEFINE_S2A_CORE_USE_NEW_UPB_APIS=1 -DCMAKE_CXX_STANDARD=11
    ls -l
  ;;
  'darwin')
    brew install openssl
    brew link openssl --force
    echo "================================= Running cmake"
    cmake --version
    cmake . -DDEFINE_S2A_CORE_USE_NEW_UPB_APIS=1 -DS2A_CORE_FIND_OPENSSL="true" -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl -DOPENSSL_LIBRARIES=/usr/local/opt/openssl/lib -DCMAKE_CXX_STANDARD=11
  ;;
  *)
    echo "Unsupported platform, unable to run cmake."
    exit 1
  ;;
esac

echo "================================= Building with make"
make all
