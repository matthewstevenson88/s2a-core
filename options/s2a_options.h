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

#ifndef OPTIONS_S2A_OPTIONS_H_
#define OPTIONS_S2A_OPTIONS_H_

#include <string>
#include <vector>

#include "absl/container/flat_hash_set.h"
#include "absl/hash/hash.h"
#include "absl/strings/string_view.h"
#include "absl/types/variant.h"

namespace s2a {
namespace s2a_options {

// |S2AOptions| configures the use of the S2A.
class S2AOptions {
 public:
  enum class TlsVersion { TLS1_2, TLS1_3 };

  enum class Ciphersuite {
    AES_128_GCM_SHA256,
    AES_256_GCM_SHA384,
    CHACHA20_POLY1305_SHA256
  };

  enum class IdentityType { NONE, SPIFFE_ID, HOSTNAME, UID };

  class Identity {
   public:
    // Creates an |Identity| instance of |NONE| type with an empty identity
    // string.
    static Identity GetEmptyIdentity();

    // Creates an |Identity| instance of |HOSTNAME| type.
    static Identity FromHostname(const std::string& hostname);

    // Creates an |Identity| instance of |SPIFFE_ID| type.
    static Identity FromSpiffeId(const std::string& spiffe_id);

    // Creates an |Identity| instance of |UID| type.
    static Identity FromUid(const std::string& uid);

    // Copy constructor of |Identity|.
    Identity(const Identity& other);

    // Copy assignment operator of |Identity|.
    Identity& operator=(const Identity& other) = default;

    bool operator==(const Identity& other) const;

    template <typename H>
    friend H AbslHashValue(H h, const Identity& id) {
      return H::combine(std::move(h), id.GetIdentityType(),
                        id.GetIdentityString());
    }

    std::string GetIdentityString() const;
    const char* GetIdentityCString() const;
    IdentityType GetIdentityType() const;

   private:
    Identity(const std::string& identity, IdentityType type);

    std::string identity_;
    IdentityType type_ = IdentityType::NONE;
  };

  ~S2AOptions();

  // Getters for member fields.
  TlsVersion min_tls_version() const;
  TlsVersion max_tls_version() const;
  const std::string handshaker_service_url() const;
  const std::vector<Ciphersuite>& supported_ciphersuites() const;
  const absl::flat_hash_set<Identity>& local_identities() const;
  const absl::flat_hash_set<Identity>& target_identities() const;

  // The setters for the min and max TLS versions.
  void set_min_tls_version(TlsVersion min_tls_version);
  void set_max_tls_version(TlsVersion max_tls_version);

  /// The setter for the |handshaker_service_url_|.
  void set_handshaker_service_url(const std::string& url);

  // Adds |ciphersuite| to the vector |supported_ciphersuites_|; it does not
  // remove duplicates from the vector, if they exist.
  void add_supported_ciphersuite(Ciphersuite ciphersuite);

  // Adds a SPIFFE ID to the set of local identities.
  void add_local_spiffe_id(const std::string& local_spiffe_id);

  // Adds a hostname to the set of local identities.
  void add_local_hostname(const std::string& local_hostname);

  // Adds a UID to the set of local identities.
  void add_local_uid(const std::string& local_uid);

  // Adds a SPIFFE ID to the set of target identities. This API should only be
  // called at the client-side, and any target identities that are added on the
  // server-side will be ignored.
  void add_target_spiffe_id(const std::string& target_spiffe_id);

  // Adds a hostname to the set of target identities. This API should only be
  // called at the client-side, and any target identities that are added on the
  // server-side will be ignored.
  void add_target_hostname(const std::string& target_hostname);

  // Adds a UID to the set of target identities. This API should only be
  // called at the client-side, and any target identities that are added on the
  // server-side will be ignored.
  void add_target_uid(const std::string& target_uid);

  // Create a deep copy of this |S2AOptions| instance.
  std::unique_ptr<S2AOptions> Copy() const;

 private:
  TlsVersion min_tls_version_ = TlsVersion::TLS1_3;
  TlsVersion max_tls_version_ = TlsVersion::TLS1_3;
  std::string handshaker_service_url_;
  std::vector<Ciphersuite> supported_ciphersuites_;
  absl::flat_hash_set<Identity> target_identities_;
  absl::flat_hash_set<Identity> local_identities_;
};

}  // namespace s2a_options
}  // namespace s2a

#endif  // OPTIONS_S2A_OPTIONS_H_
