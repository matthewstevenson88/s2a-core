/*
 *
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "handshaker/s2a_util.h"

#include "proto/common.upb.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "upb/upb.hpp"

namespace s2a {
namespace s2a_util {
namespace {

using ::absl::Status;
using ::absl::StatusCode;
using Ciphersuite = ::s2a::s2a_options::S2AOptions::Ciphersuite;
using Identity = ::s2a::s2a_options::S2AOptions::Identity;
using IdentityType = ::s2a::s2a_options::S2AOptions::IdentityType;
using TlsVersion = ::s2a::s2a_options::S2AOptions::TlsVersion;

constexpr char kHostname[] = "hostname";
constexpr char kSpiffeId[] = "spiffe_id";

TEST(S2AUtilTest, ConvertTlsVersionToProto) {
  const struct {
    std::string description;
    TlsVersion input_tls_version;
    Status output_status;
    s2a_proto_TLSVersion output_tls_version;
  } tests[] = {
      {"TLS 1.2.", TlsVersion::TLS1_2, Status(), s2a_proto_TLS1_2},
      {"TLS 1.3.", TlsVersion::TLS1_3, Status(), s2a_proto_TLS1_3},
      {"Unsupported TLS version.", static_cast<TlsVersion>(3),
       Status(StatusCode::kFailedPrecondition, "Unsupported TLS version."),
       s2a_proto_TLS1_2},
  };
  for (size_t i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
    absl::variant<Status, s2a_proto_TLSVersion> tls_version_status =
        ConvertTlsVersionToProto(tests[i].input_tls_version);
    if (tests[i].output_status.ok()) {
      ASSERT_EQ(tls_version_status.index(), 1) << tests[i].description;
      EXPECT_EQ(absl::get<1>(tls_version_status), tests[i].output_tls_version)
          << tests[i].description;
    } else {
      ASSERT_EQ(tls_version_status.index(), 0) << tests[i].description;
      EXPECT_EQ(absl::get<0>(tls_version_status), tests[i].output_status)
          << tests[i].description;
    }
  }
}

TEST(S2AUtilTest, ConvertCiphersuiteToProto) {
  const struct {
    std::string description;
    Ciphersuite input_ciphersuite;
    Status output_status;
    s2a_proto_Ciphersuite output_ciphersuite;
  } tests[] = {
      {"AES-128-GCM-SHA256.", Ciphersuite::AES_128_GCM_SHA256, Status(),
       s2a_proto_AES_128_GCM_SHA256},
      {"AES-256-GCM-SHA384.", Ciphersuite::AES_256_GCM_SHA384, Status(),
       s2a_proto_AES_256_GCM_SHA384},
      {"CHACHA20-POLY1305-SHA256.", Ciphersuite::CHACHA20_POLY1305_SHA256,
       Status(), s2a_proto_CHACHA20_POLY1305_SHA256},
      {"Unsupported ciphersuite.", static_cast<Ciphersuite>(4),
       Status(StatusCode::kFailedPrecondition, "Unsupported ciphersuite."),
       s2a_proto_AES_128_GCM_SHA256},
  };
  for (size_t i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
    absl::variant<Status, s2a_proto_Ciphersuite> ciphersuite_status =
        ConvertCiphersuiteToProto(tests[i].input_ciphersuite);
    if (tests[i].output_status.ok()) {
      ASSERT_EQ(ciphersuite_status.index(), 1) << tests[i].description;
      EXPECT_EQ(absl::get<1>(ciphersuite_status), tests[i].output_ciphersuite)
          << tests[i].description;
    } else {
      ASSERT_EQ(ciphersuite_status.index(), 0) << tests[i].description;
      EXPECT_EQ(absl::get<0>(ciphersuite_status), tests[i].output_status)
          << tests[i].description;
    }
  }
}

TEST(S2AUtilTest, ConvertIdentityToProtoFailsBecauseArenaIsNullptr) {
  absl::variant<Status, s2a_proto_Identity*> identity_status =
      ConvertIdentityToProto(/*arena=*/nullptr,
                             Identity::FromSpiffeId(kSpiffeId));
  ASSERT_EQ(identity_status.index(), 0);
  EXPECT_EQ(
      absl::get<0>(identity_status),
      Status(StatusCode::kInvalidArgument, "|arena| must not be nullptr."));
}

TEST(S2AUtilTest, ConvertIdentityToProtoSpiffeId) {
  upb::Arena arena;
  Identity spiffe_id = Identity::FromSpiffeId(kSpiffeId);
  absl::variant<Status, s2a_proto_Identity*> identity_status =
      ConvertIdentityToProto(arena.ptr(), spiffe_id);
  ASSERT_EQ(identity_status.index(), 1);
  s2a_proto_Identity* identity = absl::get<1>(identity_status);
  EXPECT_TRUE(s2a_proto_Identity_has_spiffe_id(identity));
  EXPECT_EQ(ParseUpbStrview(s2a_proto_Identity_spiffe_id(identity)), kSpiffeId);
}

TEST(S2AUtilTest, ConvertIdentityToProtoHostname) {
  upb::Arena arena;
  Identity hostname = Identity::FromHostname(kHostname);
  absl::variant<Status, s2a_proto_Identity*> identity_status =
      ConvertIdentityToProto(arena.ptr(), hostname);
  ASSERT_EQ(identity_status.index(), 1);
  s2a_proto_Identity* identity = absl::get<1>(identity_status);
  EXPECT_TRUE(s2a_proto_Identity_has_hostname(identity));
  EXPECT_EQ(ParseUpbStrview(s2a_proto_Identity_hostname(identity)), kHostname);
}

TEST(S2AUtilTest, ConvertIdentityToProtoUnknownType) {
  upb::Arena arena;
  absl::variant<Status, s2a_proto_Identity*> identity_status =
      ConvertIdentityToProto(arena.ptr(), Identity::GetEmptyIdentity());
  ASSERT_EQ(identity_status.index(), 1);
  EXPECT_EQ(absl::get<1>(identity_status), nullptr);
}

TEST(S2AUtilTest, ConvertFromProtoToTlsVersion) {
  const struct {
    std::string description;
    s2a_proto_TLSVersion input_tls_version;
    Status output_status;
    TlsVersion output_tls_version;
  } tests[] = {
      {"TLS 1.2.", s2a_proto_TLS1_2, Status(), TlsVersion::TLS1_2},
      {"TLS 1.3.", s2a_proto_TLS1_3, Status(), TlsVersion::TLS1_3},
      {"Unsupported TLS version.", static_cast<s2a_proto_TLSVersion>(3),
       Status(StatusCode::kFailedPrecondition, "Unsupported TLS version."),
       TlsVersion::TLS1_2},
  };
  for (size_t i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
    absl::variant<Status, TlsVersion> tls_version_status =
        ConvertFromProtoToTlsVersion(tests[i].input_tls_version);
    if (tests[i].output_status.ok()) {
      ASSERT_EQ(tls_version_status.index(), 1) << tests[i].description;
      EXPECT_EQ(absl::get<1>(tls_version_status), tests[i].output_tls_version);
    } else {
      ASSERT_EQ(tls_version_status.index(), 0) << tests[i].description;
      EXPECT_EQ(absl::get<0>(tls_version_status), tests[i].output_status)
          << tests[i].description;
    }
  }
}

TEST(S2AUtilTest, ConvertFromProtoToCiphersuite) {
  const struct {
    std::string description;
    s2a_proto_Ciphersuite input_ciphersuite;
    Status output_status;
    Ciphersuite output_ciphersuite;
  } tests[] = {
      {"AES-128-GCM-SHA256.", s2a_proto_AES_128_GCM_SHA256, Status(),
       Ciphersuite::AES_128_GCM_SHA256},
      {"AES-256-GCM-SHA384.", s2a_proto_AES_256_GCM_SHA384, Status(),
       Ciphersuite::AES_256_GCM_SHA384},
      {"CHACHA20-POLY1305-SHA256.", s2a_proto_CHACHA20_POLY1305_SHA256,
       Status(), Ciphersuite::CHACHA20_POLY1305_SHA256},
      {"Unsupported ciphersuite.", static_cast<s2a_proto_Ciphersuite>(4),
       Status(StatusCode::kFailedPrecondition, "Unsupported ciphersuite."),
       Ciphersuite::CHACHA20_POLY1305_SHA256},
  };
  for (size_t i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
    absl::variant<Status, Ciphersuite> ciphersuite_status =
        ConvertFromProtoToCiphersuite(tests[i].input_ciphersuite);
    if (tests[i].output_status.ok()) {
      ASSERT_EQ(ciphersuite_status.index(), 1) << tests[i].description;
      EXPECT_EQ(absl::get<1>(ciphersuite_status), tests[i].output_ciphersuite)
          << tests[i].description;
    } else {
      ASSERT_EQ(ciphersuite_status.index(), 0) << tests[i].description;
      EXPECT_EQ(absl::get<0>(ciphersuite_status), tests[i].output_status)
          << tests[i].description;
    }
  }
}

TEST(S2AUtilTest, ConvertFromProtoToIdentityWithSpiffeId) {
  std::string spiffe_id = "spiffe_id";
  upb::Arena arena;
  s2a_proto_Identity* proto_identity = s2a_proto_Identity_new(arena.ptr());
  s2a_proto_Identity_set_spiffe_id(proto_identity,
                                   upb_strview_makez(spiffe_id.c_str()));
  EXPECT_EQ(ConvertFromProtoToIdentity(proto_identity),
            Identity::FromSpiffeId(spiffe_id));
}

TEST(S2AUtilTest, ConvertFromProtoToIdentityWithHostnae) {
  std::string hostname = "hostname";
  upb::Arena arena;
  s2a_proto_Identity* proto_identity = s2a_proto_Identity_new(arena.ptr());
  s2a_proto_Identity_set_hostname(proto_identity,
                                  upb_strview_makez(hostname.c_str()));

  EXPECT_EQ(ConvertFromProtoToIdentity(proto_identity),
            Identity::FromHostname(hostname));
}

TEST(S2AUtilTest, ConvertFromProtoToIdentityWithNone) {
  upb::Arena arena;
  s2a_proto_Identity* proto_identity = s2a_proto_Identity_new(arena.ptr());
  EXPECT_EQ(ConvertFromProtoToIdentity(proto_identity),
            Identity::GetEmptyIdentity());
}

TEST(S2AUtilTest, ConvertFromProtoToIdentityWithNullptr) {
  EXPECT_EQ(ConvertFromProtoToIdentity(/*identity=*/nullptr),
            Identity::GetEmptyIdentity());
}

TEST(S2AUtilTest, ParseUpbStrview) {
  const struct {
    std::string description;
    bool empty_string;
  } tests[] = {
      {"Empty string.", /*empty_string=*/true},
      {"Non-empty string.", /*empty_string=*/false},
  };
  for (size_t i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
    std::string example_string = tests[i].empty_string ? "" : "example_string";
    upb_strview strview = tests[i].empty_string
                              ? upb_strview_make(/*data=*/nullptr, /*size=*/0)
                              : upb_strview_makez(example_string.c_str());
    EXPECT_EQ(ParseUpbStrview(strview), example_string) << tests[i].description;
  }
}

}  // namespace
}  // namespace s2a_util
}  // namespace s2a
