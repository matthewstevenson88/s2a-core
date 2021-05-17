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

cd github/s2a-core
git submodule update --init --recursive
echo "================================= Running cmake"
cmake --version
cmake . -DDEFINE_S2A_CORE_USE_NEW_UPB_APIS=1 -DCMAKE_CXX_STANDARD=11 || goto :error
echo "================================= Building"
msbuild ALL_BUID.vcxproj
