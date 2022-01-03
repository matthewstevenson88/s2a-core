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
    # If we ever need to switch to use OpenSSL for the GCP Ubuntu Kokoro tests,
    # then we need to upgrade the OpenSSL version, because they come with 1.0.2g
    # by default (which does have not the ChaChaPoly cipher).

    openssl version -a

    echo "================================= Running cmake"
    cmake --version
    # The -Wno-unused-result flag is needed because of BoringSSL.
    cmake . -DCMAKE_CXX_STANDARD=11 -DCMAKE_CXX_FLAGS="-Wno-unused-result"
  ;;
  'darwin')
    # Make /usr/local writeable for Homebrew.
    sudo chown -R `whoami` /usr/local/*

    # Remove files and directories that Homebrew will try to overwrite.
    rm '/usr/local/bin/2to3'
    rm '/usr/local/bin/idle3'
    rm '/usr/local/bin/protoc'
    rm '/usr/local/bin/pydoc3'
    rm '/usr/local/bin/python3'
    rm '/usr/local/bin/python3-config'
    rm -Rf '/usr/local/include/google/protobuf'

    # Clean re-install of XCode's command line tools.
    sudo rm -Rf '/Library/Developer/CommandLineTools'
    xcode-select -p &> /dev/null
    if [ $? -ne 0 ]; then
      echo "Xcode CLI tools not found. Installing them..."
      touch /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress;
      PROD=$(softwareupdate -l |
        grep "\*.*Command Line" |
        head -n 1 | awk -F"*" '{print $2}' |
        sed -e 's/^ *//' |
        tr -d '\n')
      softwareupdate -i "$PROD" -v;
    else
      echo "Xcode CLI tools OK"
fi

    # Update Homebrew and unlink ilmbase, which will be re-linked when openssl
    # is installed.
    git -C /usr/local/Homebrew/Library/Taps/homebrew/homebrew-core fetch --unshallow
    git -C /usr/local/Homebrew/Library/Taps/homebrew/homebrew-cask fetch --unshallow
    brew update
    brew unlink ilmbase

    # Install OpenSSL. (LibreSSL is the default SSL library for newer MacOS
    # versions.)
    brew install openssl@1.1
    brew link openssl@1.1 --force

    echo "================================= Running cmake"
    cmake --version
    cmake . -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl -DOPENSSL_LIBRARIES=/usr/local/opt/openssl/lib -DCMAKE_CXX_STANDARD=11
  ;;
  *)
    echo "Unsupported platform, unable to run cmake."
    exit 1
  ;;
esac

echo "================================= Building with make"
make all
