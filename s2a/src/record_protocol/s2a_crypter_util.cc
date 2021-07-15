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

#include "s2a/src/record_protocol/s2a_crypter_util.h"

namespace s2a {

using ::absl::Status;
using ::absl::StatusCode;
using Ciphersuite = ::s2a::s2a_options::S2AOptions::Ciphersuite;

Status CiphersuiteToHashFunction(Ciphersuite ciphersuite,
                                 hkdf::HashFunction* hash_function) {
  if (hash_function == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "|hash_function| must not be nullptr.");
  }
  switch (ciphersuite) {
    case Ciphersuite::AES_128_GCM_SHA256:
      *hash_function = hkdf::HashFunction::SHA256_hash_function;
      break;
    case Ciphersuite::AES_256_GCM_SHA384:
      *hash_function = hkdf::HashFunction::SHA384_hash_function;
      break;
    case Ciphersuite::CHACHA20_POLY1305_SHA256:
      *hash_function = hkdf::HashFunction::SHA256_hash_function;
      break;
    default:
      return Status(StatusCode::kInvalidArgument, "Unrecognized ciphersuite.");
  }
  return Status();
}

}  // namespace s2a
