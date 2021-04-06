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

namespace s2a {
namespace s2a_util {

using ::absl::Status;
using ::absl::StatusCode;
using Ciphersuite = ::s2a::s2a_options::S2AOptions::Ciphersuite;
using Identity = ::s2a::s2a_options::S2AOptions::Identity;
using IdentityType = ::s2a::s2a_options::S2AOptions::IdentityType;
using TlsVersion = ::s2a::s2a_options::S2AOptions::TlsVersion;

absl::variant<Status, s2a_proto_TLSVersion> ConvertTlsVersionToProto(
    TlsVersion tls_version) {
  switch (tls_version) {
    case TlsVersion::TLS1_2:
      return s2a_proto_TLS1_2;
    case TlsVersion::TLS1_3:
      return s2a_proto_TLS1_3;
    default:
      return Status(StatusCode::kFailedPrecondition,
                    "Unsupported TLS version.");
  }
}

absl::variant<Status, s2a_proto_Ciphersuite> ConvertCiphersuiteToProto(
    Ciphersuite ciphersuite) {
  switch (ciphersuite) {
    case Ciphersuite::AES_128_GCM_SHA256:
      return s2a_proto_AES_128_GCM_SHA256;
    case Ciphersuite::AES_256_GCM_SHA384:
      return s2a_proto_AES_256_GCM_SHA384;
    case Ciphersuite::CHACHA20_POLY1305_SHA256:
      return s2a_proto_CHACHA20_POLY1305_SHA256;
    default:
      return Status(StatusCode::kFailedPrecondition,
                    "Unsupported ciphersuite.");
  }
}

absl::variant<Status, s2a_proto_Identity*> ConvertIdentityToProto(
    upb_arena* arena, const Identity& identity) {
  if (arena == nullptr) {
    return Status(StatusCode::kInvalidArgument, "|arena| must not be nullptr.");
  }
  s2a_proto_Identity* proto_identity;
  switch (identity.GetIdentityType()) {
    case IdentityType::SPIFFE_ID:
      proto_identity = s2a_proto_Identity_new(arena);
      s2a_proto_Identity_set_spiffe_id(
          proto_identity, upb_strview_makez(identity.GetIdentityCString()));
      return proto_identity;
    case IdentityType::HOSTNAME:
      proto_identity = s2a_proto_Identity_new(arena);
      s2a_proto_Identity_set_hostname(
          proto_identity, upb_strview_makez(identity.GetIdentityCString()));
      return proto_identity;
    case IdentityType::UID:
      proto_identity = s2a_proto_Identity_new(arena);
      s2a_proto_Identity_set_uid(
          proto_identity, upb_strview_makez(identity.GetIdentityCString()));
      return proto_identity;
    default:
      return nullptr;
  }
}

absl::variant<absl::Status, TlsVersion> ConvertFromProtoToTlsVersion(
    s2a_proto_TLSVersion tls_version) {
  switch (tls_version) {
    case s2a_proto_TLS1_2:
      return TlsVersion::TLS1_2;
    case s2a_proto_TLS1_3:
      return TlsVersion::TLS1_3;
    default:
      return Status(StatusCode::kFailedPrecondition,
                    "Unsupported TLS version.");
  }
}

absl::variant<absl::Status, Ciphersuite> ConvertFromProtoToCiphersuite(
    s2a_proto_Ciphersuite ciphersuite) {
  switch (ciphersuite) {
    case s2a_proto_AES_128_GCM_SHA256:
      return Ciphersuite::AES_128_GCM_SHA256;
    case s2a_proto_AES_256_GCM_SHA384:
      return Ciphersuite::AES_256_GCM_SHA384;
    case s2a_proto_CHACHA20_POLY1305_SHA256:
      return Ciphersuite::CHACHA20_POLY1305_SHA256;
    default:
      return Status(StatusCode::kFailedPrecondition,
                    "Unsupported ciphersuite.");
  }
}

Identity ConvertFromProtoToIdentity(const s2a_proto_Identity* identity) {
  if (identity != nullptr && s2a_proto_Identity_has_spiffe_id(identity)) {
    return Identity::FromSpiffeId(
        ParseUpbStrview(s2a_proto_Identity_spiffe_id(identity)));
  } else if (identity != nullptr && s2a_proto_Identity_has_hostname(identity)) {
    return Identity::FromHostname(
        ParseUpbStrview(s2a_proto_Identity_hostname(identity)));
  } else if (identity != nullptr && s2a_proto_Identity_has_uid(identity)) {
    return Identity::FromUid(ParseUpbStrview(s2a_proto_Identity_uid(identity)));
  }
  return Identity::GetEmptyIdentity();
}

std::string ParseUpbStrview(const upb_strview& message) {
  return std::string(message.data, message.size);
}

}  // namespace s2a_util
}  // namespace s2a
