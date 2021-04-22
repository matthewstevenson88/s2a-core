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

#include "src/crypto/s2a_aead_crypter_test_util.h"

#include <algorithm>

#include "absl/base/macros.h"

namespace s2a {
namespace aead_crypter {

std::vector<Iovec> S2AAeadSliceVector(
    const std::vector<uint8_t>& input_vec, int32_t num_slices) {
  int32_t output_vec_length = num_slices + 1;
  ABSL_ASSERT(output_vec_length > 0);
  std::vector<Iovec> output_vec(output_vec_length);
  if (input_vec.empty()) {
    return output_vec;
  }
  size_t slice_length = input_vec.size() / output_vec_length;
  size_t remaining_input_length = input_vec.size();
  int32_t start_pos = 0;
  for (int i = 0; i < output_vec_length - 1; i++) {
    uint8_t* base = new uint8_t[sizeof(uint8_t) * slice_length];
    std::copy(&input_vec[start_pos], &input_vec[start_pos + slice_length],
              base);
    Iovec slice = {static_cast<void*>(base), slice_length};
    output_vec[i] = slice;
    start_pos += slice_length;
    remaining_input_length -= slice_length;
  }
  uint8_t* base = new uint8_t[sizeof(uint8_t) * remaining_input_length];
  std::copy(&input_vec[start_pos],
            &input_vec[start_pos + remaining_input_length], base);

  Iovec slice = {static_cast<uint8_t*>(base), remaining_input_length};
  output_vec[output_vec_length - 1] = slice;
  return output_vec;
}

void S2AAeadSliceVectorCleanup(const std::vector<Iovec>& input_vec) {
  ABSL_ASSERT(!input_vec.empty());
  for (auto vec : input_vec) {
    if (vec.iov_base != nullptr) {
      uint8_t* tmp = reinterpret_cast<uint8_t*>(vec.iov_base);
      delete[] tmp;
    }
  }
}

}  // namespace aead_crypter
}  // namespace s2a
