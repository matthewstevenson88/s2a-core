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

#include "include/s2a_context.h"

#include "absl/status/statusor.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "src/handshaker/s2a_util.h"
#include "src/proto/upb-generated/proto/s2a_context.upb.h"

namespace s2a {
namespace s2a_context {
namespace {

using ::absl::Status;
using ::absl::StatusCode;
using Ciphersuite = ::s2a::s2a_options::S2AOptions::Ciphersuite;
using Identity = ::s2a::s2a_options::S2AOptions::Identity;
using IdentityType = ::s2a::s2a_options::S2AOptions::IdentityType;
using TlsVersion = ::s2a::s2a_options::S2AOptions::TlsVersion;

constexpr char kApplicationProtocol[] = "application_protocol";
constexpr TlsVersion kTlsVersion = TlsVersion::TLS1_3;
constexpr Ciphersuite kCiphersuite = Ciphersuite::AES_128_GCM_SHA256;
constexpr char kPeerIdentityString[] = "peer_identity";
constexpr IdentityType kPeerIdentityType = IdentityType::SPIFFE_ID;
constexpr char kLocalIdentityString[] = "local_identity";
constexpr IdentityType kLocalIdentityType = IdentityType::HOSTNAME;
constexpr char kPeerCertFingerprint[] = "peer_cert_fingerprint";
constexpr char kLocalCertFingerprint[] = "local_cert_fingerprint";
constexpr bool kIsHandshakeResumed = true;

void CheckSerializedContext(const std::vector<char>& serialized_context,
                            bool valid_peer_identity_type,
                            bool valid_local_identity_type,
                            bool is_handshake_resumed) {
  upb::Arena arena;
  s2a_proto_S2AContext* context = s2a_proto_S2AContext_parse(
      serialized_context.data(), serialized_context.size(), arena.ptr());
  ASSERT_NE(context, nullptr);
  EXPECT_EQ(s2a_util::ParseUpbStrview(
                s2a_proto_S2AContext_application_protocol(context)),
            kApplicationProtocol);
  EXPECT_EQ(s2a_proto_S2AContext_tls_version(context), s2a_proto_TLS1_3);
  EXPECT_EQ(s2a_proto_S2AContext_ciphersuite(context),
            s2a_proto_AES_128_GCM_SHA256);
  if (valid_peer_identity_type) {
    EXPECT_TRUE(s2a_proto_Identity_has_spiffe_id(
        s2a_proto_S2AContext_peer_identity(context)));
    EXPECT_EQ(s2a_util::ParseUpbStrview(s2a_proto_Identity_spiffe_id(
                  s2a_proto_S2AContext_peer_identity(context))),
              kPeerIdentityString);
  } else {
    EXPECT_EQ(s2a_proto_S2AContext_peer_identity(context), nullptr);
  }
  if (valid_local_identity_type) {
    EXPECT_TRUE(s2a_proto_Identity_has_hostname(
        s2a_proto_S2AContext_local_identity(context)));
    EXPECT_EQ(s2a_util::ParseUpbStrview(s2a_proto_Identity_hostname(
                  s2a_proto_S2AContext_local_identity(context))),
              kLocalIdentityString);
  } else {
    EXPECT_EQ(s2a_proto_S2AContext_local_identity(context), nullptr);
  }
  EXPECT_EQ(s2a_util::ParseUpbStrview(
                s2a_proto_S2AContext_peer_cert_fingerprint(context)),
            kPeerCertFingerprint);
  EXPECT_EQ(s2a_util::ParseUpbStrview(
                s2a_proto_S2AContext_local_cert_fingerprint(context)),
            kLocalCertFingerprint);
  EXPECT_EQ(s2a_proto_S2AContext_is_handshake_resumed(context),
            is_handshake_resumed);
}

TEST(S2AContextTest, CreateAndGetterMethodsSuccess) {
  S2AContext context(kApplicationProtocol, kTlsVersion, kCiphersuite,
                     Identity::FromSpiffeId(kPeerIdentityString),
                     Identity::FromHostname(kLocalIdentityString),
                     kPeerCertFingerprint, kLocalCertFingerprint,
                     kIsHandshakeResumed);
  EXPECT_EQ(context.ApplicationProtocol(), kApplicationProtocol);
  EXPECT_EQ(context.TlsVersion(), kTlsVersion);
  EXPECT_EQ(context.Ciphersuite(), kCiphersuite);
  EXPECT_EQ(context.PeerIdentity(),
            Identity::FromSpiffeId(kPeerIdentityString));
  EXPECT_EQ(context.LocalIdentity(),
            Identity::FromHostname(kLocalIdentityString));
  EXPECT_EQ(context.PeerCertFingerprint(), kPeerCertFingerprint);
  EXPECT_EQ(context.LocalCertFingerprint(), kLocalCertFingerprint);
  EXPECT_EQ(context.IsHandshakeResumed(), kIsHandshakeResumed);
}

TEST(S2AContextTest, GetSerializedContext) {
  const struct {
    std::string description;
    bool valid_tls_version;
    bool valid_ciphersuite;
    bool valid_peer_identity_type;
    bool valid_local_identity_type;
    bool is_handshake_resumed;
    Status status;
  } tests[] = {
      {"Success with handshake resumed.", /*valid_tls_version=*/true,
       /*valid_ciphersuite=*/true,
       /*valid_peer_identity_type=*/true, /*valid_local_identity_type=*/true,
       /*is_handshake_resumed=*/true, Status()},
      {"Success with handshake not resumed.", /*valid_tls_version=*/true,
       /*valid_ciphersuite=*/true,
       /*valid_peer_identity_type=*/true, /*valid_local_identity_type=*/true,
       /*is_handshake_resumed=*/false, Status()},
      {"Invalid TLS version.", /*valid_tls_version=*/false,
       /*valid_ciphersuite=*/true, /*valid_peer_identity_type=*/true,
       /*valid_local_identity_type=*/true, /*is_handshake_resumed=*/false,
       Status(StatusCode::kFailedPrecondition, "Unsupported TLS version.")},
      {"Invalid ciphersuite.", /*valid_tls_version=*/true,
       /*valid_ciphersuite=*/false, /*valid_peer_identity_type=*/true,
       /*valid_local_identity_type=*/true, /*is_handshake_resumed=*/false,
       Status(StatusCode::kFailedPrecondition, "Unsupported ciphersuite.")},
      {"Invalid peer identity type.", /*valid_tls_version=*/true,
       /*valid_ciphersuite=*/true, /*valid_peer_identity_type=*/false,
       /*valid_local_identity_type=*/true, /*is_handshake_resumed=*/false,
       Status()},
      {"Invalid local identity type.", /*valid_tls_version=*/true,
       /*valid_ciphersuite=*/true, /*valid_peer_identity_type=*/true,
       /*valid_local_identity_type=*/false, /*is_handshake_resumed=*/false,
       Status()},
  };
  for (size_t i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
    S2AContext context(
        kApplicationProtocol,
        tests[i].valid_tls_version ? kTlsVersion : static_cast<TlsVersion>(3),
        tests[i].valid_ciphersuite ? kCiphersuite : static_cast<Ciphersuite>(4),
        tests[i].valid_peer_identity_type
            ? Identity::FromSpiffeId(kPeerIdentityString)
            : Identity::GetEmptyIdentity(),
        tests[i].valid_local_identity_type
            ? Identity::FromHostname(kLocalIdentityString)
            : Identity::GetEmptyIdentity(),
        kPeerCertFingerprint, kLocalCertFingerprint,
        tests[i].is_handshake_resumed);
    absl::variant<Status, std::unique_ptr<std::vector<char>>>
        serialized_context_status = context.GetSerializedContext();
    if (tests[i].status.ok()) {
      ASSERT_EQ(serialized_context_status.index(), 1) << tests[i].description;
      CheckSerializedContext(*absl::get<1>(serialized_context_status),
                             tests[i].valid_peer_identity_type,
                             tests[i].valid_local_identity_type,
                             tests[i].is_handshake_resumed);
    } else {
      ASSERT_EQ(serialized_context_status.index(), 0) << tests[i].description;
      EXPECT_EQ(absl::get<0>(serialized_context_status), tests[i].status);
    }
  }
}

TEST(S2AContextTest, GetS2AContextFromSerializedContextSuccess) {
  S2AContext context(kApplicationProtocol, kTlsVersion, kCiphersuite,
                     Identity::FromSpiffeId(kPeerIdentityString),
                     Identity::FromHostname(kLocalIdentityString),
                     kPeerCertFingerprint, kLocalCertFingerprint,
                     kIsHandshakeResumed);
  absl::variant<Status, std::unique_ptr<std::vector<char>>>
      serialized_context_status = context.GetSerializedContext();
  ASSERT_EQ(serialized_context_status.index(), 1);
  std::unique_ptr<std::vector<char>> serialized_context =
      std::move(absl::get<1>(serialized_context_status));
  ASSERT_NE(serialized_context, nullptr);

  absl::StatusOr<std::unique_ptr<S2AContext>> s2a_context =
      GetS2AContextFromSerializedContext(serialized_context->data(),
                                         serialized_context->size());
  ASSERT_TRUE(s2a_context.ok());
  EXPECT_EQ((*s2a_context)->ApplicationProtocol(), kApplicationProtocol);
  EXPECT_EQ((*s2a_context)->TlsVersion(), kTlsVersion);
  EXPECT_EQ((*s2a_context)->Ciphersuite(), kCiphersuite);
  EXPECT_EQ((*s2a_context)->PeerIdentity().GetIdentityString(),
            kPeerIdentityString);
  EXPECT_EQ((*s2a_context)->PeerIdentity().GetIdentityType(),
            kPeerIdentityType);
  EXPECT_EQ((*s2a_context)->LocalIdentity().GetIdentityString(),
            kLocalIdentityString);
  EXPECT_EQ((*s2a_context)->LocalIdentity().GetIdentityType(),
            kLocalIdentityType);
  EXPECT_EQ((*s2a_context)->PeerCertFingerprint(), kPeerCertFingerprint);
  EXPECT_EQ((*s2a_context)->LocalCertFingerprint(), kLocalCertFingerprint);
  EXPECT_EQ((*s2a_context)->IsHandshakeResumed(), kIsHandshakeResumed);
}

TEST(S2AContextTest, GetS2AContextFromSerializedContextFailure) {
  std::vector<char> serialized_context = {'n', 'o', 'n', 's',
                                          'e', 'n', 's', 'e'};
  absl::StatusOr<std::unique_ptr<S2AContext>> s2a_context =
      GetS2AContextFromSerializedContext(serialized_context.data(),
                                         serialized_context.size());
  EXPECT_EQ(s2a_context.status(), Status(StatusCode::kInternal,
                                         "Unable to deserialize S2A context."));
}

}  // namespace
}  // namespace s2a_context
}  // namespace s2a
