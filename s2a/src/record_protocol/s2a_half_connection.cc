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

#include "s2a/src/record_protocol/s2a_half_connection.h"

#include "absl/memory/memory.h"
#include "s2a/include/s2a_constants.h"
#include "s2a/src/crypto/hkdf.h"
#include "s2a/src/record_protocol/s2a_crypter_util.h"

namespace s2a {
namespace record_protocol {

namespace {
using ::absl::Status;
using ::absl::StatusCode;
using ::s2a::aead_crypter::S2AAeadCrypter;
using Ciphersuite = ::s2a::s2a_options::S2AOptions::Ciphersuite;
using CrypterStatus = ::s2a::aead_crypter::S2AAeadCrypter::CrypterStatus;

// Advances |traffic_secret| following the TLS 1.3 RFC: see
// https://tools.ietf.org/html/rfc8446#section-7.2.
// The |ciphersuite| is used to determine the hash function that is needed.
Status AdvanceSecret(Ciphersuite ciphersuite,
                     std::vector<uint8_t>& traffic_secret) {
  hkdf::HashFunction hash_function;
  const Status status = CiphersuiteToHashFunction(ciphersuite, &hash_function);
  if (!status.ok()) return status;

  static const uint8_t suffix[] = "\x11tls13 traffic upd\x00";
  const size_t suffix_size = 19;
  std::vector<uint8_t> label(2 + suffix_size);
  label[0] = traffic_secret.size() >> 8;
  label[1] = traffic_secret.size();
  memcpy(label.data() + 2, suffix, suffix_size);
  return hkdf::HkdfDeriveSecret(hash_function, traffic_secret, label,
                                traffic_secret);
}

// Writes |out_size| bytes of derived secret to |output|. The derived secret is
// determined by |secret|, |suffix|, and |ciphersuite|.
Status DeriveSecret(Ciphersuite ciphersuite, const std::vector<uint8_t>& suffix,
                    const std::vector<uint8_t>& secret,
                    std::vector<uint8_t>& output) {
  hkdf::HashFunction hash_function;
  Status status = CiphersuiteToHashFunction(ciphersuite, &hash_function);
  if (!status.ok()) return status;

  // The label buffer consists of 2 pieces: the first 2 bytes encode
  // |output_size|, and the following 10 or 11 bytes encode |suffix|. Note that
  // the suffix is 10 bytes when deriving the nonce, and 11 bytes when deriving
  // the key.
  std::vector<uint8_t> label(2 + suffix.size());
  label[0] = output.size() >> 8;
  label[1] = output.size();
  memcpy(label.data() + 2, suffix.data(), suffix.size());

  // Use the HKDF expansion function to write to |output|, using the
  // pseudo-random key equal to |secret| and info equal to |label|.
  return hkdf::HkdfDeriveSecret(hash_function, secret, label, output);
}

// Writes |out_size| bytes of derived key to |output|. The derived key is
// determined by |secret| and |ciphersuite|.
Status DeriveKey(Ciphersuite ciphersuite, const std::vector<uint8_t>& secret,
                 std::vector<uint8_t>& output) {
  // The suffix used for deriving keys is specified in the TLS 1.3 RFC: see
  // https://tools.ietf.org/html/rfc8446#section-7.3.
  const std::vector<uint8_t> key_suffix = {0x09, 't', 'l', 's', '1', '3',
                                           ' ',  'k', 'e', 'y', 0x00};
  return DeriveSecret(ciphersuite, key_suffix, secret, output);
}

// Writes |out_size| bytes of derived nonce to |output|. The derived nonce is
// determined by |secret| and |ciphersuite|.
Status DeriveNonce(Ciphersuite ciphersuite, const std::vector<uint8_t>& secret,
                   std::vector<uint8_t>& output) {
  // The suffix used for deriving nonces is specified in the TLS 1.3 RFC: see
  // https://tools.ietf.org/html/rfc8446#section-7.3.
  const std::vector<uint8_t> nonce_suffix = {0x08, 't', 'l', 's', '1',
                                             '3',  ' ', 'i', 'v', 0x00};
  return DeriveSecret(ciphersuite, nonce_suffix, secret, output);
}
}  // namespace

absl::variant<Status, std::unique_ptr<S2AHalfConnection>>
S2AHalfConnection::Create(Ciphersuite ciphersuite, uint64_t sequence,
                          const std::vector<uint8_t>& traffic_secret) {
  // Determine ciphersuite-specific constants.
  size_t key_size;
  size_t nonce_size;
  size_t expected_traffic_secret_size;
  switch (ciphersuite) {
    case Ciphersuite::AES_128_GCM_SHA256:
      key_size = aead_crypter::kAes128GcmSha256KeySize;
      nonce_size = aead_crypter::kAesGcmNonceSize;
      expected_traffic_secret_size = kSha256DigestLength;
      break;
    case Ciphersuite::AES_256_GCM_SHA384:
      key_size = aead_crypter::kAes256GcmSha384KeySize;
      nonce_size = aead_crypter::kAesGcmNonceSize;
      expected_traffic_secret_size = kSha384DigestLength;
      break;
    case Ciphersuite::CHACHA20_POLY1305_SHA256:
      key_size = aead_crypter::kChachaPolyKeySize;
      nonce_size = aead_crypter::kChachaPolyNonceSize;
      expected_traffic_secret_size = kSha256DigestLength;
      break;
    default:
      return Status(StatusCode::kInvalidArgument, "Unexpected ciphersuite.");
  }
  if (traffic_secret.size() != expected_traffic_secret_size) {
    return Status(StatusCode::kInvalidArgument,
                  "|traffic_secret| size is incorrect.");
  }

  // Derive the key from the traffic secret.
  std::vector<uint8_t> key(key_size);
  Status key_status = DeriveKey(ciphersuite, traffic_secret, key);
  if (!key_status.ok()) return key_status;

  // Derive the nonce from the traffic secret.
  std::vector<uint8_t> nonce(nonce_size);
  Status nonce_status = DeriveNonce(ciphersuite, traffic_secret, nonce);
  if (!nonce_status.ok()) return nonce_status;

  // Create the AEAD crypter.
  absl::variant<absl::Status, std::unique_ptr<S2AAeadCrypter>>
      aead_crypter_status;
  switch (ciphersuite) {
    case Ciphersuite::AES_128_GCM_SHA256:
    case Ciphersuite::AES_256_GCM_SHA384:
      aead_crypter_status = aead_crypter::CreateAesGcmAeadCrypter(key);
      break;
    case Ciphersuite::CHACHA20_POLY1305_SHA256:
      aead_crypter_status = aead_crypter::CreateChachaPolyAeadCrypter(key);
      break;
    default:
      return Status(StatusCode::kInvalidArgument, "Unexpected ciphersuite.");
  }
  switch (aead_crypter_status.index()) {
    case 0:
      return absl::get<0>(aead_crypter_status);
    case 1:
      break;
    default:
      ABSL_ASSERT(0);  // Unexpected variant case.
  }

  return absl::WrapUnique(new S2AHalfConnection(
      ciphersuite, key_size, sequence, nonce, traffic_secret,
      std::move(absl::get<1>(aead_crypter_status))));
}

CrypterStatus S2AHalfConnection::Encrypt(const std::vector<Iovec>& aad,
                                         const std::vector<Iovec>& plaintext,
                                         Iovec ciphertext_and_tag) {
  absl::MutexLock lock(&mu_);
  // Check if the half connection is in a usable state.
  if (aead_crypter_ == nullptr || always_fail_aead_operations_ ||
      has_sequence_overflowed_) {
    return CrypterStatus(Status(StatusCode::kInternal,
                                "|S2AHalfConnection| is in unusable state."),
                         /*bytes_written=*/0);
  }
  return aead_crypter_->Encrypt(NonceMask(), aad, plaintext,
                                ciphertext_and_tag);
}

CrypterStatus S2AHalfConnection::Decrypt(
    const std::vector<Iovec>& aad, const std::vector<Iovec>& ciphertext_and_tag,
    Iovec plaintext) {
  absl::MutexLock lock(&mu_);
  // Check if the half connection is in a usable state.
  if (aead_crypter_ == nullptr || always_fail_aead_operations_ ||
      has_sequence_overflowed_) {
    return CrypterStatus(Status(StatusCode::kInternal,
                                "|S2AHalfConnection| is in unusable state."),
                         /*bytes_written=*/0);
  }
  return aead_crypter_->Decrypt(NonceMask(), aad, ciphertext_and_tag,
                                plaintext);
}

Status S2AHalfConnection::UpdateKey() {
  absl::MutexLock lock(&mu_);

  // Advance the traffic secret and derive the updated key and nonce.
  Status status = AdvanceSecret(ciphersuite_, traffic_secret_);
  if (!status.ok()) {
    always_fail_aead_operations_ = true;
    return status;
  }

  std::vector<uint8_t> key(key_size_);
  status = DeriveKey(ciphersuite_, traffic_secret_, key);
  if (!status.ok()) {
    always_fail_aead_operations_ = true;
    return status;
  }

  status = DeriveNonce(ciphersuite_, traffic_secret_, nonce_);
  if (!status.ok()) {
    always_fail_aead_operations_ = true;
    return status;
  }

  // Populate |aead_crypter_| with the updated AEAD crypter.
  absl::variant<absl::Status, std::unique_ptr<S2AAeadCrypter>>
      aead_crypter_status;
  switch (ciphersuite_) {
    case Ciphersuite::AES_128_GCM_SHA256:
    case Ciphersuite::AES_256_GCM_SHA384:
      aead_crypter_status = aead_crypter::CreateAesGcmAeadCrypter(key);
      break;
    case Ciphersuite::CHACHA20_POLY1305_SHA256:
      aead_crypter_status = aead_crypter::CreateChachaPolyAeadCrypter(key);
      break;
    default:
      always_fail_aead_operations_ = true;
      return Status(StatusCode::kInvalidArgument, "Unexpected ciphersuite.");
  }
  switch (aead_crypter_status.index()) {
    case 0:
      always_fail_aead_operations_ = true;
      return absl::get<0>(aead_crypter_status);
    case 1:
      aead_crypter_ = std::move(absl::get<1>(aead_crypter_status));
      break;
    default:
      ABSL_ASSERT(0);  // Unexpected variant case.
  }

  // Reset the sequence number.
  sequence_ = 0;
  has_sequence_overflowed_ = false;
  return Status();
}

size_t S2AHalfConnection::TagLength() { return aead_crypter_->TagLength(); }

S2AHalfConnection::S2AHalfConnection(
    Ciphersuite ciphersuite, size_t key_size, uint64_t sequence,
    std::vector<uint8_t>& nonce, std::vector<uint8_t> traffic_secret,
    std::unique_ptr<S2AAeadCrypter> aead_crypter)
    : ciphersuite_(ciphersuite),
      key_size_(key_size),
      sequence_(sequence),
      nonce_(std::move(nonce)),
      traffic_secret_(traffic_secret),
      aead_crypter_(std::move(aead_crypter)) {}

std::vector<uint8_t> S2AHalfConnection::NonceMask() {
  // If the sequence number is valid, create the nonce mask.
  std::vector<uint8_t> masked_nonce = nonce_;
  for (size_t i = 0; i < 8; i++) {
    masked_nonce[nonce_.size() - 8 + i] ^= (sequence_ >> (56 - 8 * i));
  }
  // Increment the sequence number and check if it has overflowed.
  sequence_ += 1;
  if (sequence_ == 0) {
    has_sequence_overflowed_ = true;
  }
  return masked_nonce;
}

}  // namespace record_protocol
}  // namespace s2a
