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

#include "s2a/src/handshaker/s2a_proxy_test_util.h"

#include "absl/memory/memory.h"
#include "s2a/src/proto/upb-generated/s2a/src/proto/common.upb.h"
#include "s2a/src/proto/upb-generated/s2a/src/proto/s2a.upb.h"
#include "upb/upb.hpp"

namespace s2a {
namespace s2a_proxy {
namespace {

using ::s2a::s2a_context::S2AContext;
using Buffer = ::s2a::s2a_proxy::S2AProxy::Buffer;
using ProxyStatus = ::s2a::s2a_proxy::S2AProxy::ProxyStatus;
using S2AOptions = ::s2a::s2a_options::S2AOptions;
using S2AProxyOptions = ::s2a::s2a_proxy::S2AProxy::S2AProxyOptions;
using Ciphersuite = ::s2a::s2a_options::S2AOptions::Ciphersuite;
using Identity = ::s2a::s2a_options::S2AOptions::Identity;
using IdentityType = ::s2a::s2a_options::S2AOptions::IdentityType;
using TlsVersion = ::s2a::s2a_options::S2AOptions::TlsVersion;

constexpr size_t kAes128GcmTrafficSecretSize = 32;
constexpr char kApplicationProtocol[] = "application_protocol";
constexpr Ciphersuite kCiphersuite = Ciphersuite::AES_128_GCM_SHA256;
constexpr size_t kConnectionId = 1234;
constexpr char kHandshakerServiceAddress[] = "handshaker_service_address";
constexpr char kHostname[] = "hostname";
constexpr bool kIsHandshakeResumed = false;
constexpr char kLocalCertFingerprint[] = "local_cert_fingerprint";
constexpr char kLocalIdentityString[] = "local_identity";
constexpr char kPeerCertFingerprint[] = "peer_cert_fingerprint";
constexpr char kPeerIdentityString[] = "peer_identity";
constexpr TlsVersion kTlsVersion = TlsVersion::TLS1_3;

void NoOpLogger(const std::string& message) {}

std::unique_ptr<S2AOptions> CreateTestOptions() {
  auto options = absl::make_unique<S2AOptions>();
  options->set_s2a_address(kHandshakerServiceAddress);
  options->add_supported_ciphersuite(Ciphersuite::AES_128_GCM_SHA256);
  options->add_supported_ciphersuite(Ciphersuite::AES_256_GCM_SHA384);
  options->add_supported_ciphersuite(Ciphersuite::CHACHA20_POLY1305_SHA256);
  options->add_target_spiffe_id(kPeerIdentityString);
  options->add_local_hostname(kLocalIdentityString);
  return options;
}

std::unique_ptr<Buffer> CreateTestSerializedSessionResp() {
  upb::Arena arena;
  s2a_proto_SessionResp* response = s2a_proto_SessionResp_new(arena.ptr());

  // Set the status of the |SessionResp| message.
  s2a_proto_SessionStatus* status =
      s2a_proto_SessionResp_mutable_status(response, arena.ptr());
  s2a_proto_SessionStatus_set_code(status, /*value=*/0);

  // If |contains_result| is true, populate the |SessionResult| message. The
  // in/out keys of the |SessionState| will be 32 bytes since that is the
  // expected length of a traffic secret for the AES-128-GCM-SHA256 ciphersuite.
  std::vector<char> traffic_secret(kAes128GcmTrafficSecretSize);
  s2a_proto_SessionResult* result =
      s2a_proto_SessionResp_mutable_result(response, arena.ptr());
  s2a_proto_SessionResult_set_application_protocol(
      result, upb_strview_makez(kApplicationProtocol));
  s2a_proto_SessionState* state =
      s2a_proto_SessionResult_mutable_state(result, arena.ptr());
  s2a_proto_SessionState_set_tls_version(state, s2a_proto_TLS1_3);
  s2a_proto_SessionState_set_tls_ciphersuite(state,
                                             s2a_proto_AES_128_GCM_SHA256);
  s2a_proto_SessionState_set_in_key(
      state, upb_strview_make(traffic_secret.data(), traffic_secret.size()));
  s2a_proto_SessionState_set_out_key(
      state, upb_strview_make(traffic_secret.data(), traffic_secret.size()));
  s2a_proto_SessionState_set_in_sequence(state, 0);
  s2a_proto_SessionState_set_out_sequence(state, 0);
  s2a_proto_SessionState_set_connection_id(state, kConnectionId);
  s2a_proto_SessionState_set_is_handshake_resumed(state, kIsHandshakeResumed);
  s2a_proto_Identity* peer_identity =
      s2a_proto_SessionResult_mutable_peer_identity(result, arena.ptr());
  s2a_proto_Identity_set_spiffe_id(peer_identity,
                                   upb_strview_makez(kPeerIdentityString));
  s2a_proto_Identity* local_identity =
      s2a_proto_SessionResult_mutable_local_identity(result, arena.ptr());
  s2a_proto_Identity_set_hostname(local_identity,
                                  upb_strview_makez(kLocalIdentityString));
  s2a_proto_SessionResult_set_local_cert_fingerprint(
      result, upb_strview_makez(kLocalCertFingerprint));
  s2a_proto_SessionResult_set_peer_cert_fingerprint(
      result, upb_strview_makez(kPeerCertFingerprint));

  // Serialize the |SessionResp| message and return a copy that is valid outside
  // of |arena|.
  size_t buffer_len = 0;
  char* arena_buffer =
      s2a_proto_SessionResp_serialize(response, arena.ptr(), &buffer_len);
  auto buffer = absl::make_unique<Buffer>(buffer_len);
  memcpy(buffer->data(), arena_buffer, buffer_len);
  return buffer;
}

}  // namespace

std::unique_ptr<S2AContext> CreateTestContext() {
  return absl::WrapUnique(new S2AContext(
      kApplicationProtocol, kTlsVersion, kCiphersuite,
      Identity::FromSpiffeId(kPeerIdentityString),
      Identity::FromHostname(kLocalIdentityString), kPeerCertFingerprint,
      kLocalCertFingerprint, kIsHandshakeResumed));
}

std::unique_ptr<S2AProxy> CreateTestProxy(bool has_handshake_result,
                                          bool is_client) {
  S2AProxyOptions options = {NoOpLogger,
                             is_client,
                             kApplicationProtocol,
                             kHostname,
                             CreateTestOptions(),
                             /*channel_factory=*/nullptr,
                             /*channel_options=*/nullptr};
  auto proxy = S2AProxy::Create(options);
  if (has_handshake_result) {
    ABSL_ASSERT(
        proxy->GetBytesForPeer(CreateTestSerializedSessionResp()).status.ok());
  }
  return proxy;
}

}  // namespace s2a_proxy
}  // namespace s2a
