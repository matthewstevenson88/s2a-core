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

#ifndef HANDSHAKER_S2A_CONTEXT_H_
#define HANDSHAKER_S2A_CONTEXT_H_

#include "options/s2a_options.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/variant.h"

namespace s2a {
namespace s2a_context {

// Wrapper around the |S2AContext| proto message. This wrapper allows callers to
// use the |S2AContext| proto message without complications arising from
// incompatible proto compilers.
class S2AContext {
 public:
  S2AContext(const std::string& application_protocol,
             s2a_options::S2AOptions::TlsVersion tls_version,
             s2a_options::S2AOptions::Ciphersuite ciphersuite,
             const s2a_options::S2AOptions::Identity& peer_identity,
             const s2a_options::S2AOptions::Identity& local_identity,
             const std::string& peer_cert_fingerprint,
             const std::string& local_cert_fingerprint,
             bool is_handshake_resumed);

  // |ApplicationProtocol| returns the application protocol negotiated for the
  // connection, e.g., "grpc".
  std::string ApplicationProtocol() const;

  // |TlsVersion| returns the TLS version negotiated for the connection.
  s2a_options::S2AOptions::TlsVersion TlsVersion() const;

  // |Ciphersuite| returns the TLS ciphersuite negotiated for the connection.
  s2a_options::S2AOptions::Ciphersuite Ciphersuite() const;

  // |PeerIdentity| returns the authenticated identity of the peer.
  s2a_options::S2AOptions::Identity PeerIdentity() const;

  // |LocalIdentity| returns the local identity used during session setup.
  s2a_options::S2AOptions::Identity LocalIdentity() const;

  // |PeerCertFingerprint| returns the SHA256 hash of the peer certificate used
  // in the handshake.
  std::string PeerCertFingerprint() const;

  // |LocalCertFingerprint| returns the SHA256 hash of the local certificate
  // used in the handshake.
  std::string LocalCertFingerprint() const;

  // |IsHandshakeResumed| returns true if a cached session was used to resume
  // the handshake.
  bool IsHandshakeResumed() const;

  // |GetSerializedContext| returns the UPB-serialized |S2AContext| proto
  // message, or a status if an error occurs during serialization.
  absl::variant<absl::Status, std::unique_ptr<std::vector<char>>>
  GetSerializedContext() const;

 private:
  const std::string application_protocol_;
  const s2a_options::S2AOptions::TlsVersion tls_version_;
  const s2a_options::S2AOptions::Ciphersuite ciphersuite_;
  const s2a_options::S2AOptions::Identity peer_identity_;
  const s2a_options::S2AOptions::Identity local_identity_;
  const std::string peer_cert_fingerprint_;
  const std::string local_cert_fingerprint_;
  const bool is_handshake_resumed_;
};

// |GetS2AContextFromSerializedContext| returns an |S2AContext| object from a
// UPB-serialized proto message, or a status if an error occurs during
// deserialization.
absl::StatusOr<std::unique_ptr<S2AContext>> GetS2AContextFromSerializedContext(
    const char* serialized_context, size_t serialized_context_length);

}  // namespace s2a_context
}  // namespace s2a

#endif  // HANDSHAKER_S2A_CONTEXT_H_
