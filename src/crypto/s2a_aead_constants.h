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

#ifndef SRC_CRYPTO_S2A_AEAD_CONSTANTS_H_
#define SRC_CRYPTO_S2A_AEAD_CONSTANTS_H_

#include <cstddef>
#include <cstdint>

namespace s2a {
namespace aead_crypter {

// |Iovec| stores a buffer to be involved in encryption or decryption.
struct Iovec {
  void* iov_base;
  size_t iov_len;
};

// AES-GCM constants.
constexpr size_t kAes128GcmSha256KeySize = 16;
constexpr size_t kAes256GcmSha384KeySize = 32;
constexpr size_t kAesGcmNonceSize = 12;
constexpr size_t kAesGcmTagSize = 16;

// Chacha-Poly constants.
constexpr size_t kChachaPolyKeySize = 32;
constexpr size_t kChachaPolyNonceSize = 12;
constexpr size_t kChachaPolyTagSize = 16;

}  // namespace aead_crypter
}  // namespace s2a

#endif  // SRC_CRYPTO_S2A_AEAD_CONSTANTS_H_
