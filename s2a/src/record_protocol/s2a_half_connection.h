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

#ifndef S2A_SRC_RECORD_PROTOCOL_S2A_HALF_CONNECTION_H_
#define S2A_SRC_RECORD_PROTOCOL_S2A_HALF_CONNECTION_H_

#include "absl/status/status.h"
#include "absl/synchronization/mutex.h"
#include "absl/types/variant.h"
#include "s2a/include/s2a_constants.h"
#include "s2a/include/s2a_options.h"
#include "s2a/src/crypto/s2a_aead_crypter.h"

namespace s2a {
namespace record_protocol {

// |S2AHalfConnection| represents the state of a TLS 1.3 connection managed by
// the S2A record protocol in a single direction.
class S2AHalfConnection {
 public:
  // Creates an |S2AHalfConnection| that owns an AEAD crypter of type
  // |ciphersuite| and with key derived from |traffic_secret|. The initial
  // sequence number used by the half connection is |sequence|. On failure,
  // returns an error status.
  static absl::variant<absl::Status, std::unique_ptr<S2AHalfConnection>> Create(
      s2a_options::S2AOptions::Ciphersuite ciphersuite, uint64_t sequence,
      const std::vector<uint8_t>& traffic_secret);

  // |Encrypt| encrypts |plaintext| with authentication data |aad|, and writes
  // the resulting ciphertext and tag to |ciphertext_ang_tag|.
  aead_crypter::S2AAeadCrypter::CrypterStatus Encrypt(
      const std::vector<Iovec>& aad,
      const std::vector<Iovec>& plaintext,
      Iovec ciphertext_and_tag);

  // |Decrypt| decrypts |ciphertext_and_tag| using the authentication data
  // |aad|, and writes the resulting plaintext to |plaintext|.
  aead_crypter::S2AAeadCrypter::CrypterStatus Decrypt(
      const std::vector<Iovec>& aad,
      const std::vector<Iovec>& ciphertext_and_tag,
      Iovec plaintext);

  // Advances the traffic secret, and updates |nonce_| and |aead_crypter_|
  // accordingly. On success, returns a |kOk| status. Otherwise, the half
  // connection is left in an unusable state.
  absl::Status UpdateKey();

  // Returns the length (in bytes) of the authentication tag that the AEAD
  // crypter will append to the ciphertext.
  size_t TagLength();

 private:
  S2AHalfConnection(s2a_options::S2AOptions::Ciphersuite ciphersuite,
                    size_t key_size, uint64_t sequence,
                    std::vector<uint8_t>& nonce,
                    std::vector<uint8_t> traffic_secret,
                    std::unique_ptr<aead_crypter::S2AAeadCrypter> aead_crypter);

  // Masks |nonce_| using the bytes of the |sequence_| number, and increments
  // |sequence_|. If |sequence_| overflows after incrementing, then it sets
  // |has_sequence_overflowed_| to true.
  std::vector<uint8_t> NonceMask();

  const s2a_options::S2AOptions::Ciphersuite ciphersuite_;
  const size_t key_size_;

  // |mu_| guards the state of the half connection, which consists of all of
  // the fields below.
  absl::Mutex mu_;
  uint64_t sequence_;
  bool has_sequence_overflowed_ = false;
  bool always_fail_aead_operations_ = false;
  std::vector<uint8_t> nonce_;
  std::vector<uint8_t> traffic_secret_;
  std::unique_ptr<aead_crypter::S2AAeadCrypter> aead_crypter_;
};

}  // namespace record_protocol
}  // namespace s2a

#endif  // S2A_SRC_RECORD_PROTOCOL_S2A_HALF_CONNECTION_H_
