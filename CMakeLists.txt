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

cmake_minimum_required(VERSION 3.5)

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

if (S2A_CORE_ABSL_DIR)
  include_directories(${S2A_CORE_ABSL_DIR})
  set(_S2A_CORE_ABSL_INCLUDE_DIR ${S2A_CORE_ABSL_DIR})
else()
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/third_party/abseil-cpp)
  set(_S2A_CORE_ABSL_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/abseil-cpp)
endif()

if (S2A_CORE_UPB_INCLUDE_DIR)
  include_directories(${S2A_CORE_UPB_INCLUDE_DIR})
else()
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/third_party/upb)
endif()

if (NOT S2A_CORE_UPB_LIBRARY)
  set(S2A_CORE_UPB_LIBRARY upb)
endif()

if (S2A_CORE_SSL_INCLUDE_DIR)
  include_directories(${S2A_CORE_SSL_INCLUDE_DIR})
else()
  find_package(OpenSSL REQUIRED)
  set(S2A_CORE_SSL_LIBRARIES OpenSSL::Crypto)
  set(S2A_CORE_SSL_INCLUDE_DIR ${OPENSSL_INCLUDE_DIR})
endif()

if(APPLE)
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -undefined dynamic_lookup -flat_namespace")
elseif(UNIX)
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--build-id")
endif()

enable_testing()

add_library(common_upb
  s2a/src/proto/upb-generated/proto/common.upb.c
  s2a/src/proto/upb-generated/proto/common.upb.h)
target_link_libraries(common_upb
  ${S2A_CORE_UPB_LIBRARY})
add_library(s2a_upb
  s2a/src/proto/upb-generated/proto/s2a.upb.c
  s2a/src/proto/upb-generated/proto/s2a.upb.h)
target_link_libraries(s2a_upb
  common_upb
  ${S2A_CORE_UPB_LIBRARY})
add_library(s2a_context_upb
  s2a/src/proto/upb-generated/proto/s2a_context.upb.c
  s2a/src/proto/upb-generated/proto/s2a_context.upb.h)
target_link_libraries(s2a_context_upb
  common_upb
  ${S2A_CORE_UPB_LIBRARY})
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
  s2a/src/options/s2a_options.cc
  s2a/include/s2a_options.h)
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
  s2a/src/frame_protector/s2a_frame_protector.cc
  s2a/include/s2a_frame_protector.h)
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
  s2a/src/handshaker/s2a_context.cc
  s2a/include/s2a_context.h)
target_link_libraries(s2a_context
  s2a_options
  s2a_util
  common_upb
  s2a_context_upb
  absl_memory
  absl_status
  absl_statusor
  absl_variant
  ${S2A_CORE_UPB_LIBRARY})
add_library(s2a_proxy
  s2a/src/handshaker/s2a_proxy.cc
  s2a/include/s2a_proxy.h)
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
  ${S2A_CORE_UPB_LIBRARY})
add_library(hkdf
  s2a/src/crypto/hkdf.cc
  s2a/src/crypto/hkdf.h)
target_include_directories(hkdf PRIVATE
  ${_S2A_CORE_ABSL_INCLUDE_DIR}
  ${S2A_CORE_SSL_INCLUDE_DIR})
target_link_libraries(hkdf
  ${S2A_CORE_SSL_LIBRARIES}
  absl_status)

set(_S2A_CORE_AEAD_CRYPTER_SOURCES)
list(APPEND _S2A_CORE_AEAD_CRYPTER_SOURCES
  s2a/src/crypto/aes_gcm_crypter.cc
  s2a/src/crypto/s2a_aead_crypter.cc
  s2a/src/crypto/chacha_poly_crypter_boringssl.cc
  s2a/src/crypto/chacha_poly_crypter_openssl.cc)
add_library(s2a_aead_crypter
  ${_S2A_CORE_AEAD_CRYPTER_SOURCES})
target_include_directories(s2a_aead_crypter PRIVATE
  ${_S2A_CORE_ABSL_INCLUDE_DIR}
  ${S2A_CORE_SSL_INCLUDE_DIR})
target_link_libraries(s2a_aead_crypter
  s2a_aead_crypter_util
  ${S2A_CORE_SSL_LIBRARIES}
  absl_memory
  absl_status
  absl_strings
  absl_variant)
add_library(s2a_aead_crypter_util
  s2a/src/crypto/s2a_aead_crypter_util.cc
  s2a/src/crypto/s2a_aead_crypter_util.h)
target_include_directories(s2a_aead_crypter_util PRIVATE
  ${_S2A_CORE_ABSL_INCLUDE_DIR}
  ${S2A_CORE_SSL_INCLUDE_DIR})
target_link_libraries(s2a_aead_crypter_util
  ${S2A_CORE_SSL_LIBRARIES})
add_library(s2a_util
  s2a/src/handshaker/s2a_util.cc
  s2a/src/handshaker/s2a_util.h)
target_link_libraries(s2a_util
  s2a_options
  common_upb
  absl_status
  absl_variant
  ${S2A_CORE_UPB_LIBRARY})
add_library(handshake_message_handler
  s2a/src/record_protocol/handshake_message_handler.cc
  s2a/src/record_protocol/handshake_message_handler.h)
target_link_libraries(handshake_message_handler
  absl_core_headers
  absl_memory
  absl_status
  absl_variant)
add_library(s2a_crypter
  s2a/src/record_protocol/s2a_crypter.cc
  s2a/src/record_protocol/s2a_crypter_util.cc
  s2a/src/record_protocol/s2a_half_connection.cc
  s2a/src/record_protocol/s2a_crypter.h
  s2a/src/record_protocol/s2a_crypter_util.h
  s2a/src/record_protocol/s2a_half_connection.h)
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
  s2a/src/record_protocol/s2a_upb_ticket_sender.cc)
target_link_libraries(s2a_upb_ticket_sender
  s2a_options
  s2a_ticket_sender
  common_upb
  s2a_upb
  absl_strings
  ${S2A_CORE_UPB_LIBRARY})
add_library(single_token_access_token_manager
  s2a/src/token_manager/single_token_access_token_manager.cc
  s2a/src/token_manager/single_token_access_token_manager.h)
target_link_libraries(single_token_access_token_manager
  access_token_manager
  absl_flag
  absl_status
  absl_statusor
  absl_strings
  absl_str_format)
add_library(s2a_aead_crypter_test_util
  s2a/src/crypto/s2a_aead_crypter_test_util.cc
  s2a/src/crypto/s2a_aead_crypter_test_util.h)
target_link_libraries(s2a_aead_crypter_test_util
  s2a_aead_crypter
  absl_core_headers)
add_library(s2a_proxy_test_util
  s2a/src/handshaker/s2a_proxy_test_util.cc
  s2a/src/handshaker/s2a_proxy_test_util.h)
target_link_libraries(s2a_proxy_test_util
  s2a_context
  s2a_proxy
  s2a_options
  common_upb
  s2a_upb
  absl_memory
  absl_status
  absl_variant
  ${S2A_CORE_UPB_LIBRARY})
add_library(s2a_test_data INTERFACE)
add_library(s2a_test_util INTERFACE)
target_link_libraries(s2a_test_util INTERFACE
  com_google_googletest//:gtest)
add_library(fake_access_token_manager
  s2a/src/token_manager/fake_access_token_manager.cc
  s2a/src/token_manager/fake_access_token_manager.h)
target_link_libraries(fake_access_token_manager
  access_token_manager
  absl_statusor)

set(S2A_CORE_SOURCES
    s2a/src/crypto/aes_gcm_crypter.cc
    s2a/src/crypto/chacha_poly_crypter_boringssl.cc
    s2a/src/crypto/chacha_poly_crypter_openssl.cc
    s2a/src/crypto/hkdf.cc
    s2a/src/crypto/s2a_aead_crypter.cc
    s2a/src/crypto/s2a_aead_crypter_util.cc
    s2a/src/frame_protector/s2a_frame_protector.cc
    s2a/src/handshaker/s2a_context.cc
    s2a/src/handshaker/s2a_proxy.cc
    s2a/src/handshaker/s2a_util.cc
    s2a/src/options/s2a_options.cc
    s2a/src/proto/upb-generated/proto/common.upb.c
    s2a/src/proto/upb-generated/proto/s2a.upb.c
    s2a/src/proto/upb-generated/proto/s2a_context.upb.c
    s2a/src/record_protocol/handshake_message_handler.cc
    s2a/src/record_protocol/s2a_crypter.cc
    s2a/src/record_protocol/s2a_crypter_util.cc
    s2a/src/record_protocol/s2a_half_connection.cc
    s2a/src/record_protocol/s2a_upb_ticket_sender.cc
    s2a/src/token_manager/single_token_access_token_manager.cc
)

add_library(s2a_core ${S2A_CORE_SOURCES})
target_include_directories(s2a_core PRIVATE
  ${_S2A_CORE_ABSL_INCLUDE_DIR}
  ${S2A_CORE_SSL_INCLUDE_DIR})

add_library(s2a_core::s2a_core ALIAS s2a_core)

set(S2A_CORE_HEADERS
    s2a/include/access_token_manager.h
    s2a/include/access_token_manager_factory.h
    s2a/include/s2a_channel_factory_interface.h
    s2a/include/s2a_constants.h
    s2a/include/s2a_context.h
    s2a/include/s2a_frame_protector.h
    s2a/include/s2a_options.h
    s2a/include/s2a_proxy.h
    s2a/src/crypto/hkdf.h
    s2a/src/crypto/s2a_aead_constants.h
    s2a/src/crypto/s2a_aead_crypter.h
    s2a/src/crypto/s2a_aead_crypter_util.h
    s2a/src/handshaker/s2a_util.h
    s2a/src/proto/upb-generated/proto/common.upb.h
    s2a/src/proto/upb-generated/proto/s2a.upb.h
    s2a/src/proto/upb-generated/proto/s2a_context.upb.h
    s2a/src/record_protocol/handshake_message_handler.h
    s2a/src/record_protocol/s2a_crypter.h
    s2a/src/record_protocol/s2a_crypter_util.h
    s2a/src/record_protocol/s2a_half_connection.h
    s2a/src/record_protocol/s2a_ticket_sender.h
    s2a/src/token_manager/single_token_access_token_manager.h
)

message(STATUS "S2A Core CMake includes destination is CMAKE_INSTALL_INCLUDEDIR=${CMAKE_INSTALL_INCLUDEDIR}")
message(STATUS "S2A Core CMake library destination is CMAKE_INSTALL_LIBDIR=${CMAKE_INSTALL_LIBDIR}")
message(STATUS "S2A Core CMake runtime destination is CMAKE_INSTALL_BINDIR=${CMAKE_INSTALL_BINDIR}")
install(FILES ${S2A_CORE_HEADERS}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/s2a_core)
install(TARGETS s2a_core EXPORT s2a_coreConfig
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT s2a_coreConfig
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/s2a_core NAMESPACE s2a_core::)
