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

# This file was generated with help from:
#  https://github.com/google/bazel-to-cmake

cmake_minimum_required(VERSION 3.1)

if(${CMAKE_VERSION} VERSION_LESS 3.12)
    cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
else()
    cmake_policy(VERSION 3.12)
endif()

cmake_minimum_required (VERSION 3.0)
cmake_policy(SET CMP0048 NEW)

project(s2a_core)


# Prevent CMake from setting -rdynamic on Linux (!!).
SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
SET(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")

# Set default build type.
if(NOT CMAKE_BUILD_TYPE)
  message(STATUS "Setting build type to 'RelWithDebInfo' as none was specified.")
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING
      "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel."
      FORCE)
endif()

# When using Ninja, compiler output won't be colorized without this.
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG(-fdiagnostics-color=always SUPPORTS_COLOR_ALWAYS)
if(SUPPORTS_COLOR_ALWAYS)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fdiagnostics-color=always")
endif()

# Implement ASAN/UBSAN options
if(UPB_ENABLE_ASAN)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=address")
endif()

if(UPB_ENABLE_UBSAN)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=undefined")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=address")
endif()

if(DEFINE_S2A_CORE_USE_NEW_UPB_APIS)
  add_definitions(-DS2A_CORE_USE_NEW_UPB_APIS)
endif()

include_directories(.)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_CURRENT_BINARY_DIR}/third_party/abseil-cpp)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/third_party/upb)

if (S2A_CORE_FIND_OPENSSL STREQUAL "true")
  find_package(OpenSSL REQUIRED)
  set(S2A_CORE_SSL_LIBRARIES OpenSSL::Crypto)
elseif (NOT S2A_CORE_SSL_LIBRARIES)
  include_directories(${CMAKE_CURRENT_BINARY_DIR}/third_party/boringssl)
  set(S2A_CORE_SSL_LIBRARIES crypto)
endif()

if(APPLE)
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -undefined dynamic_lookup -flat_namespace")
elseif(UNIX)
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--build-id")
endif()

enable_testing()

add_library(common_upb
  src/proto/upb-generated/proto/common.upb.c
  src/proto/upb-generated/proto/common.upb.h)
target_link_libraries(common_upb
  upb)
add_library(s2a_upb
  src/proto/upb-generated/proto/s2a.upb.c
  src/proto/upb-generated/proto/s2a.upb.h)
target_link_libraries(s2a_upb
  common_upb
  upb)
add_library(s2a_context_upb
  src/proto/upb-generated/proto/s2a_context.upb.c
  src/proto/upb-generated/proto/s2a_context.upb.h)
target_link_libraries(s2a_context_upb
  common_upb
  upb)
add_library(s2a_channel INTERFACE)
target_link_libraries(s2a_channel INTERFACE
  absl_status
  absl_statusor)
add_library(s2a_constants INTERFACE)
target_link_libraries(s2a_constants INTERFACE
  common_upb
  s2a_context_upb
  s2a_upb)
add_library(s2a_options
  src/options/s2a_options.cc
  include/s2a_options.h)
target_link_libraries(s2a_options
  absl_flat_hash_set
  absl_hash
  absl_strings
  absl_variant)
add_library(access_token_manager INTERFACE)
target_link_libraries(access_token_manager INTERFACE
  s2a_options
  absl_status
  absl_statusor
  absl_strings)
add_library(s2a_frame_protector
  src/frame_protector/s2a_frame_protector.cc
  include/s2a_frame_protector.h)
target_link_libraries(s2a_frame_protector
  s2a_channel
  s2a_constants
  s2a_crypter
  s2a_options
  s2a_ticket_sender
  absl_memory
  absl_status
  absl_statusor
  absl_str_format
  absl_synchronization
  absl_variant)
add_library(s2a_context
  src/handshaker/s2a_context.cc
  include/s2a_context.h)
target_link_libraries(s2a_context
  s2a_options
  s2a_util
  common_upb
  s2a_context_upb
  absl_memory
  absl_status
  absl_statusor
  absl_variant
  upb)
add_library(s2a_proxy
  src/handshaker/s2a_proxy.cc
  include/s2a_proxy.h)
target_link_libraries(s2a_proxy
  access_token_manager
  s2a_channel
  s2a_context
  s2a_constants
  s2a_frame_protector
  s2a_options
  s2a_util
  common_upb
  s2a_upb
  absl_flat_hash_map
  absl_memory
  absl_status
  absl_statusor
  absl_str_format
  absl_synchronization
  absl_variant
  upb)
add_library(hkdf
  src/crypto/hkdf.cc
  src/crypto/hkdf.h)
target_link_libraries(hkdf
  ${S2A_CORE_SSL_LIBRARIES}
  absl_status)
add_library(s2a_aead_crypter
  src/crypto/aes_gcm_crypter.cc
  src/crypto/chacha_poly_crypter_boringssl.cc
  src/crypto/s2a_aead_crypter.cc
  src/crypto/s2a_aead_constants.h
  src/crypto/s2a_aead_crypter.h)
target_link_libraries(s2a_aead_crypter
  s2a_aead_crypter_util
  ${S2A_CORE_SSL_LIBRARIES}
  absl_memory
  absl_status
  absl_strings
  absl_variant)
add_library(s2a_aead_crypter_util
  src/crypto/s2a_aead_crypter_util.cc
  src/crypto/s2a_aead_crypter_util.h)
target_link_libraries(s2a_aead_crypter_util
  ${S2A_CORE_SSL_LIBRARIES})
add_library(s2a_util
  src/handshaker/s2a_util.cc
  src/handshaker/s2a_util.h)
target_link_libraries(s2a_util
  s2a_options
  common_upb
  absl_status
  absl_variant
  upb)
add_library(handshake_message_handler
  src/record_protocol/handshake_message_handler.cc
  src/record_protocol/handshake_message_handler.h)
target_link_libraries(handshake_message_handler
  absl_core_headers
  absl_memory
  absl_status
  absl_variant)
add_library(s2a_crypter
  src/record_protocol/s2a_crypter.cc
  src/record_protocol/s2a_crypter_util.cc
  src/record_protocol/s2a_half_connection.cc
  src/record_protocol/s2a_crypter.h
  src/record_protocol/s2a_crypter_util.h
  src/record_protocol/s2a_half_connection.h)
target_link_libraries(s2a_crypter
  handshake_message_handler
  s2a_upb_ticket_sender
  s2a_ticket_sender
  s2a_channel
  s2a_constants
  s2a_options
  hkdf
  s2a_aead_crypter
  absl_core_headers
  absl_memory
  absl_status
  absl_str_format
  absl_synchronization
  absl_variant)
add_library(s2a_ticket_sender INTERFACE)
target_link_libraries(s2a_ticket_sender INTERFACE
  s2a_channel
  s2a_options
  absl_strings)
add_library(s2a_upb_ticket_sender
  src/record_protocol/s2a_upb_ticket_sender.cc)
target_link_libraries(s2a_upb_ticket_sender
  s2a_options
  s2a_ticket_sender
  common_upb
  s2a_upb
  absl_strings
  upb)
add_library(single_token_access_token_manager
  src/token_manager/single_token_access_token_manager.cc
  src/token_manager/single_token_access_token_manager.h)
target_link_libraries(single_token_access_token_manager
  access_token_manager
  absl_flag
  absl_status
  absl_statusor
  absl_strings
  absl_str_format)
add_library(s2a_aead_crypter_test_util
  src/crypto/s2a_aead_crypter_test_util.cc
  src/crypto/s2a_aead_crypter_test_util.h)
target_link_libraries(s2a_aead_crypter_test_util
  s2a_aead_crypter
  absl_core_headers)
add_library(s2a_proxy_test_util
  src/handshaker/s2a_proxy_test_util.cc
  src/handshaker/s2a_proxy_test_util.h)
target_link_libraries(s2a_proxy_test_util
  s2a_context
  s2a_proxy
  s2a_options
  common_upb
  s2a_upb
  absl_memory
  absl_status
  absl_variant
  upb)
add_library(s2a_test_data INTERFACE)
add_library(s2a_test_util INTERFACE)
target_link_libraries(s2a_test_util INTERFACE
  com_google_googletest//:gtest)
add_library(fake_access_token_manager
  src/token_manager/fake_access_token_manager.cc
  src/token_manager/fake_access_token_manager.h)
target_link_libraries(fake_access_token_manager
  access_token_manager
  absl_statusor)

# Monolithic target for users that want simpler dependency management.
add_library(s2a_core_monolith
  include/access_token_manager.h
  include/access_token_manager_factory.h
  include/s2a_channel_factory_interface.h
  include/s2a_channel_interface.h
  include/s2a_constants.h
  src/handshaker/s2a_context.cc
  include/s2a_context.h
  src/frame_protector/s2a_frame_protector.cc
  include/s2a_frame_protector.h
  src/options/s2a_options.cc
  include/s2a_options.h
  src/handshaker/s2a_proxy.cc
  include/s2a_proxy.h)
target_link_libraries(
  s2a_crypter
  s2a_ticket_sender
  s2a_util
  common_upb
  s2a_upb
  s2a_context_upb
  absl_flat_hash_set
  absl_flat_hash_map
  absl_hash
  absl_memory
  absl_status
  absl_statusor
  absl_strings
  absl_str_format
  absl_synchronization
  absl_variant
  upb
)
