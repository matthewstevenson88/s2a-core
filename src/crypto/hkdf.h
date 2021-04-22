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

#ifndef SRC_CRYPTO_HKDF_H_
#define SRC_CRYPTO_HKDF_H_

#include <stdint.h>
#include <stdlib.h>

#include <vector>

#include "absl/status/status.h"

namespace s2a {
namespace hkdf {

enum class HashFunction {
  SHA256_hash_function,
  SHA384_hash_function,
};

// |HkdfDeriveSecret| derives an output key of length |out.size()| using the
// pseudorandom key |prk| and context |info|, and writes the output key to
// |out|. This uses the HKDF expansion algorithm; see
// https://tools.ietf.org/html/rfc5869 for details.
// - hash_function: the hash function used in the HKDF expansion algorithm.
// - prk: the pseudorandom key used to generate the output key; the length of
//   |prk| must be at least the digest size of |hash_function| (32 for SHA256,
//   48 for SHA384).
// - info: optional context used to generate the output key.
// - out: the buffer to which the output key will be written; the output key
//   will always fill the buffer.
//
// On success, returns |OK| status; otherwise, returns an error status.
absl::Status HkdfDeriveSecret(HashFunction hash_function,
                              const std::vector<uint8_t>& prk,
                              const std::vector<uint8_t>& info,
                              std::vector<uint8_t>& out);

}  // namespace hkdf
}  // namespace s2a

#endif  // SRC_CRYPTO_HKDF_H_
