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

#include "handshaker/s2a_context.h"

#include "handshaker/s2a_util.h"
#include "proto/s2a_context.upb.h"
#include "absl/status/statusor.h"

namespace s2a {
namespace s2a_context {

using ::absl::Status;
using ::absl::StatusCode;
using Ciphersuite = ::s2a::s2a_options::S2AOptions::Ciphersuite;
using Identity = ::s2a::s2a_options::S2AOptions::Identity;
using TlsVersion = ::s2a::s2a_options::S2AOptions::TlsVersion;

S2AContext::S2AContext(const std::string& application_protocol,
                       s2a_options::S2AOptions::TlsVersion tls_version,
                       s2a_options::S2AOptions::Ciphersuite ciphersuite,
                       const s2a_options::S2AOptions::Identity& peer_identity,
                       const s2a_options::S2AOptions::Identity& local_identity,
                       const std::string& peer_cert_fingerprint,
                       const std::string& local_cert_fingerprint,
                       bool is_handshake_resumed)
    : application_protocol_(application_protocol),
      tls_version_(tls_version),
      ciphersuite_(ciphersuite),
      peer_identity_(peer_identity),
      local_identity_(local_identity),
      peer_cert_fingerprint_(peer_cert_fingerprint),
      local_cert_fingerprint_(local_cert_fingerprint),
      is_handshake_resumed_(is_handshake_resumed) {}

std::string S2AContext::ApplicationProtocol() const {
  return application_protocol_;
}

TlsVersion S2AContext::TlsVersion() const { return tls_version_; }

Ciphersuite S2AContext::Ciphersuite() const { return ciphersuite_; }

Identity S2AContext::PeerIdentity() const { return peer_identity_; }

Identity S2AContext::LocalIdentity() const { return local_identity_; }

std::string S2AContext::PeerCertFingerprint() const {
  return peer_cert_fingerprint_;
}

std::string S2AContext::LocalCertFingerprint() const {
  return local_cert_fingerprint_;
}

bool S2AContext::IsHandshakeResumed() const { return is_handshake_resumed_; }

absl::variant<absl::Status, std::unique_ptr<std::vector<char>>>
S2AContext::GetSerializedContext() const {
  upb::Arena arena;
  s2a_proto_S2AContext* context = s2a_proto_S2AContext_new(arena.ptr());
  s2a_proto_S2AContext_set_application_protocol(
      context, upb_strview_makez(application_protocol_.c_str()));

  // Set the TLS version.
  absl::variant<Status, s2a_proto_TLSVersion> tls_version_status =
      s2a_util::ConvertTlsVersionToProto(tls_version_);
  switch (tls_version_status.index()) {
    case 0:
      return absl::get<0>(tls_version_status);
    case 1:
      s2a_proto_S2AContext_set_tls_version(context,
                                           absl::get<1>(tls_version_status));
      break;
    default:
      ABSL_ASSERT(0);  // Unexpected variant case.
  }

  // Set the ciphersuite.
  absl::variant<Status, s2a_proto_Ciphersuite> ciphersuite_status =
      s2a_util::ConvertCiphersuiteToProto(ciphersuite_);
  switch (ciphersuite_status.index()) {
    case 0:
      return absl::get<0>(ciphersuite_status);
    case 1:
      s2a_proto_S2AContext_set_ciphersuite(context,
                                           absl::get<1>(ciphersuite_status));
      break;
    default:
      ABSL_ASSERT(0);  // Unexpected variant case.
  }

  // Set the peer identity.
  absl::variant<Status, s2a_proto_Identity*> peer_identity_status =
      s2a_util::ConvertIdentityToProto(arena.ptr(), peer_identity_);
  switch (peer_identity_status.index()) {
    case 0:
      return absl::get<0>(peer_identity_status);
    case 1:
      s2a_proto_S2AContext_set_peer_identity(
          context, absl::get<1>(peer_identity_status));
      break;
    default:
      ABSL_ASSERT(0);  // Unexpected variant case.
  }

  // Set the local identity.
  absl::variant<Status, s2a_proto_Identity*> local_identity_status =
      s2a_util::ConvertIdentityToProto(arena.ptr(), local_identity_);
  switch (local_identity_status.index()) {
    case 0:
      return absl::get<0>(local_identity_status);
    case 1:
      s2a_proto_S2AContext_set_local_identity(
          context, absl::get<1>(local_identity_status));
      break;
    default:
      ABSL_ASSERT(0);  // Unexpected variant case.
  }

  // Set the peer and local cert fingerprints.
  s2a_proto_S2AContext_set_peer_cert_fingerprint(
      context, upb_strview_makez(peer_cert_fingerprint_.c_str()));
  s2a_proto_S2AContext_set_local_cert_fingerprint(
      context, upb_strview_makez(local_cert_fingerprint_.c_str()));

  // Set the "is handshake resumed" flag.
  s2a_proto_S2AContext_set_is_handshake_resumed(context, is_handshake_resumed_);

  // Serialize |context|.
  size_t buffer_len = 0;
  char* arena_buffer =
      s2a_proto_S2AContext_serialize(context, arena.ptr(), &buffer_len);
  if (arena_buffer == nullptr) {
    return Status(StatusCode::kInternal,
                  "Error when serializing |S2AContext|.");
  }

  // Copy the serialized message to a buffer not tied to the arena.
  auto buffer = absl::make_unique<std::vector<char>>(buffer_len);
  memcpy(buffer->data(), arena_buffer, buffer_len);
  return buffer;
}

absl::StatusOr<std::unique_ptr<S2AContext>> GetS2AContextFromSerializedContext(
    const char* serialized_context, size_t serialized_context_length) {
  upb::Arena arena;
  s2a_proto_S2AContext* context = s2a_proto_S2AContext_parse(
      serialized_context, serialized_context_length, arena.ptr());
  if (context == nullptr) {
    return Status(StatusCode::kInternal, "Unable to deserialize S2A context.");
  }

  // Parse the TLS version.
  absl::variant<Status, s2a_options::S2AOptions::TlsVersion>
      tls_version_status = s2a_util::ConvertFromProtoToTlsVersion(
          static_cast<s2a_proto_TLSVersion>(
              s2a_proto_S2AContext_tls_version(context)));
  switch (tls_version_status.index()) {
    case 0:
      return absl::get<0>(tls_version_status);
    case 1:
      break;
    default:  // Unexpected variant case.
      ABSL_ASSERT(0);
  }

  // Parse the ciphersuite.
  absl::variant<Status, s2a_options::S2AOptions::Ciphersuite>
      ciphersuite_status = s2a_util::ConvertFromProtoToCiphersuite(
          static_cast<s2a_proto_Ciphersuite>(
              s2a_proto_S2AContext_ciphersuite(context)));
  switch (ciphersuite_status.index()) {
    case 0:
      return absl::get<0>(ciphersuite_status);
    case 1:
      break;
    default:  // Unexpected variant case.
      ABSL_ASSERT(0);
  }

  return absl::make_unique<S2AContext>(
      s2a_util::ParseUpbStrview(
          s2a_proto_S2AContext_application_protocol(context)),
      absl::get<1>(tls_version_status), absl::get<1>(ciphersuite_status),
      s2a_util::ConvertFromProtoToIdentity(
          s2a_proto_S2AContext_peer_identity(context)),
      s2a_util::ConvertFromProtoToIdentity(
          s2a_proto_S2AContext_local_identity(context)),
      s2a_util::ParseUpbStrview(
          s2a_proto_S2AContext_peer_cert_fingerprint(context)),
      s2a_util::ParseUpbStrview(
          s2a_proto_S2AContext_local_cert_fingerprint(context)),
      s2a_proto_S2AContext_is_handshake_resumed(context));
}

}  // namespace s2a_context
}  // namespace s2a
