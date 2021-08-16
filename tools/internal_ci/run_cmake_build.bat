:: Copyright 2021 Google LLC
::
:: Licensed under the Apache License, Version 2.0 (the "License");
:: you may not use this file except in compliance with the License.
:: You may obtain a copy of the License at
::
::    https://www.apache.org/licenses/LICENSE-2.0
::
:: Unless required by applicable law or agreed to in writing, software
:: distributed under the License is distributed on an "AS IS" BASIS,
:: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
:: See the License for the specific language governing permissions and
:: limitations under the License.


choco install -y openssl
openssl version

cd github/s2a-core
git submodule update --init --recursive
mkdir s2a-cmake-build && cd s2a-cmake-build

echo "================================= Running cmake"
cmake --version
cmake .. -DOPENSSL_ROOT_DIR="C:\ProgramData\chocolatey\lib\openssl" -DCMAKE_CXX_STANDARD=11 -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON || goto :error

echo "================================= Building"
ls -l
cmake --build . --target s2a_core || goto :error
