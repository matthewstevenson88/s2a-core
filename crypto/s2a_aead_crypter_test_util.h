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

#ifndef CRYPTO_S2A_AEAD_CRYPTER_TEST_UTIL_H_
#define CRYPTO_S2A_AEAD_CRYPTER_TEST_UTIL_H_

#include <vector>

#include "crypto/s2a_aead_crypter.h"

namespace s2a {
namespace aead_crypter {

// |S2AAeadSliceVector| slices the given |input_vec| into |num_slices|+1 |Iovec|
// entries and returns an |Iovec| vector.
//
// Callers of |S2AAeadSliceVector| must call |S2AAeadSliceVectorCleanup| to free
// up the memory allocated by |S2AAeadSliceVector| for each |Iovec| entry.
std::vector<Iovec> S2AAeadSliceVector(const std::vector<uint8_t>& input_vec,
                                      int32_t num_slices);

// |S2AAeadSliceVectorCleanup| frees up the memory allocated to each |Iovec|
// entry in the |input_vec|.
void S2AAeadSliceVectorCleanup(const std::vector<Iovec>& input_vec);

}  // namespace aead_crypter
}  // namespace s2a

#endif  // CRYPTO_S2A_AEAD_CRYPTER_TEST_UTIL_H_
