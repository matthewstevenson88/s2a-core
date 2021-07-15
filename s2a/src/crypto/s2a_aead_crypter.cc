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

#include "s2a/src/crypto/s2a_aead_crypter.h"

namespace s2a {
namespace aead_crypter {

S2AAeadCrypter::CrypterStatus::CrypterStatus(absl::Status status,
                                             size_t bytes_written)
    : status_(status), bytes_written_(bytes_written) {}

S2AAeadCrypter::CrypterStatus& S2AAeadCrypter::CrypterStatus::operator=(
    const S2AAeadCrypter::CrypterStatus& other) {
  status_ = other.GetStatus();
  bytes_written_ = other.GetBytesWritten();
  return *this;
}

absl::Status S2AAeadCrypter::CrypterStatus::GetStatus() const {
  return status_;
}
size_t S2AAeadCrypter::CrypterStatus::GetBytesWritten() const {
  return bytes_written_;
}

S2AAeadCrypter::S2AAeadCrypter(size_t key_length, size_t nonce_length,
                               size_t tag_length)
    : key_length_(key_length),
      nonce_length_(nonce_length),
      tag_length_(tag_length) {}

size_t S2AAeadCrypter::MaxPlaintextLength(
    size_t ciphertext_and_tag_length) const {
  return ciphertext_and_tag_length - tag_length_;
}

size_t S2AAeadCrypter::MaxCiphertextAndTagLength(
    size_t plaintext_length) const {
  return plaintext_length + tag_length_;
}

size_t S2AAeadCrypter::KeyLength() const { return key_length_; }

size_t S2AAeadCrypter::NonceLength() const { return nonce_length_; }

size_t S2AAeadCrypter::TagLength() const { return tag_length_; }

}  // namespace aead_crypter
}  // namespace s2a
