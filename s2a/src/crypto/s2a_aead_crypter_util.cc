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

#include "s2a/src/crypto/s2a_aead_crypter_util.h"

#include <openssl/bio.h>
#include <openssl/err.h>

namespace s2a {
namespace aead_crypter {

std::string GetSSLErrors() {
  BIO* bio = BIO_new(BIO_s_mem());
  ERR_print_errors(bio);
  char* temp_buffer = nullptr;
  size_t temp_buffer_length = BIO_get_mem_data(bio, &temp_buffer);
  std::string error_message(temp_buffer, temp_buffer_length);
  BIO_free_all(bio);
  return error_message;
}

}  // namespace aead_crypter
}  // namespace s2a
