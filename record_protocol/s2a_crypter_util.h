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

#ifndef RECORD_PROTOCOL_S2A_CRYPTER_UTIL_H_
#define RECORD_PROTOCOL_S2A_CRYPTER_UTIL_H_

#include "crypto/hkdf.h"
#include "options/s2a_options.h"
#include "absl/status/status.h"

namespace s2a {

// |CiphersuiteToHashFunction| populates |hash_function| with the hash function
// corresponding to the TLS ciphersuite represented by |ciphersuite|.
// - ciphersuite: a TLS ciphersuite.
// - hash_function: a pointer to a hash function; the caller must not pass in
//   nullptr for this argument.
//
// On success, returns |OK| status; otherwise, returns an error status.
absl::Status CiphersuiteToHashFunction(
    s2a_options::S2AOptions::Ciphersuite ciphersuite,
    hkdf::HashFunction* hash_function);

}  // namespace s2a

#endif  // RECORD_PROTOCOL_S2A_CRYPTER_UTIL_H_
