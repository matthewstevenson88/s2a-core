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

#ifndef S2A_SRC_CRYPTO_S2A_AEAD_CRYPTER_H_
#define S2A_SRC_CRYPTO_S2A_AEAD_CRYPTER_H_

#include <vector>

// We need to include any header that is common to OpenSSL and BoringSSL (and
// which is also needed in this file). If BoringSSL is installed, then this
// header will link-in the BoringSSL-specific openssl/base.h header. The base.h
// header defines the OPENSSL_IS_BORINGSSL macro, which is needed below.
#include <openssl/bio.h>

#include "absl/status/status.h"
#include "absl/types/variant.h"
#include "s2a/include/s2a_constants.h"
#include "s2a/src/crypto/s2a_aead_constants.h"

namespace s2a {
namespace aead_crypter {

/** |S2AAeadCrypter| is an interface for AEAD encryption schemes. The
 *  |S2AAeadCrypter| and any implementation thereof should be thread compatible.
 **/
class S2AAeadCrypter {
 public:
  /** The |CrypterStatus| struct holds the return status for the encryption and
   *  decryption operations.
   *  - status: the status of the operation that was performed.
   *  - bytes_written: the number of bytes written to the output buffer of the
   *    operation that was performed. This value should be ignored when |status|
   *    is not OK. **/
  class CrypterStatus {
   public:
    CrypterStatus(absl::Status status, size_t bytes_written);

    CrypterStatus(const CrypterStatus& other) = default;
    CrypterStatus& operator=(const CrypterStatus& other);

    absl::Status GetStatus() const;
    size_t GetBytesWritten() const;

   private:
    absl::Status status_;
    size_t bytes_written_ = 0;
  };

  S2AAeadCrypter(size_t key_length, size_t nonce_length, size_t tag_length);

  virtual ~S2AAeadCrypter() = default;

  /** |Encrypt| performs an AEAD encrypt operation.
   *  - nonce: a vector containing a nonce whose length must be equal to
   *    |nonce_length_|.
   *  - aad: a vector of Iovec's that together contain the data that must be
   *    authenticated but not encrypted.
   *  - plaintext: a vector of Iovec's that together contain the data that must
   *    be encrypted.
   *  - ciphertext_and_tag: a buffer to which the ciphertext and authentication
   *    tag will be written. The caller must ensure that
   *    |ciphertext_and_tag.iov_len| is at least the total length of the
   *    plaintext plus |tag_length_|.
   *
   *  On success, the method returns an OK status along with the number of bytes
   *  written to the |ciphertext_and_tag| buffer. Otherwise, the method returns
   *  a status that contains error details. **/
  virtual CrypterStatus Encrypt(const std::vector<uint8_t>& nonce,
                                const std::vector<Iovec>& aad,
                                const std::vector<Iovec>& plaintext,
                                Iovec ciphertext_and_tag) = 0;

  /** |Decrypt| performs an AEAD decrypt operation.
   *  - nonce: a vector containing a nonce whose length must be equal to
   *    |nonce_length_|.
   *  - aad: a vector of Iovec's that together contain the data that must be
   *    authenticated but not encrypted.
   *  - ciphertext_and_tag: a vector of Iovec's that together contain the data
   *    that must be decrypted.
   *  - plaintext: a buffer to which the plaintext will be written. The caller
   *    must ensure that |plaintext.iov_len| is at least the total length of the
   *    ciphertext and tag minus |tag_length_|.
   *
   *  On success, the method returns an OK status along with the number of bytes
   *  written to the |plaintext| buffer. Otherwise, the method returns a status
   *  that contains error details. **/
  virtual CrypterStatus Decrypt(const std::vector<uint8_t>& nonce,
                                const std::vector<Iovec>& aad,
                                const std::vector<Iovec>& ciphertext_and_tag,
                                Iovec plaintext) = 0;

  /** Computes the max plaintext length that will result from decrypting
   * |ciphertext_and_tag_length| bytes of ciphertext and tag. **/
  size_t MaxPlaintextLength(size_t ciphertext_and_tag_length) const;
  /** Computes the max ciphertext and tag length that will result from
   *  encrypting |plaintext_length| bytes of plaintext. **/
  size_t MaxCiphertextAndTagLength(size_t plaintext_length) const;

  /** Getter methods. **/
  size_t KeyLength() const;
  size_t NonceLength() const;
  size_t TagLength() const;

 private:
  size_t key_length_;
  size_t nonce_length_;
  size_t tag_length_;
};

/** |CreateAesGcmAeadCrypter| creates an |S2AAeadCrypter| instance using the
 *  AES-GCM encryption scheme. It supports 16 and 32 byte-long keys, 12
 *  byte-long nonces, and 16 byte-long tags.
 *  - key: a vector containing the key used for encryption and decryption. The
 *    caller must ensure that |key.size()| is either 16 or 32.
 *
 *  On success, the method returns a unique pointer to the |S2AAeadCrypter|
 *  instance; otherwise, it returns an error status. **/
absl::variant<absl::Status, std::unique_ptr<S2AAeadCrypter>>
CreateAesGcmAeadCrypter(const std::vector<uint8_t>& key);

/** |CreateChachaPolyAeadCrypter| creates an |S2AAeadCrypter| instance using the
 *  CHACHA-POLY encryption scheme. It supports 32 byte-long keys, 12 byte-long
 *  nonces, and 16 byte-long tags.
 *  - key: a vector containing the key used for encryption and decryption. The
 *    caller must ensure that |key.size()| is 32.
 *
 *  On success, the method returns a unique pointer to the |S2AAeadCrypter|
 *  instance; otherwise, it returns an error status. **/
absl::variant<absl::Status, std::unique_ptr<S2AAeadCrypter>>
CreateChachaPolyAeadCrypter(const std::vector<uint8_t>& key);

}  // namespace aead_crypter
}  // namespace s2a

#endif  // S2A_SRC_CRYPTO_S2A_AEAD_CRYPTER_H_
