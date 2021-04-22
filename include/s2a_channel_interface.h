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

#ifndef INCLUDE_S2A_CHANNEL_INTERFACE_H_
#define INCLUDE_S2A_CHANNEL_INTERFACE_H_

#include "absl/status/status.h"

namespace s2a {
namespace s2a_channel {

// |S2AChannelInterface| is an interface for calling the S2A. It allows the
// caller to use whatever transport mechanism they choose, and decouples this
// choice from the logic of constructing messages to the S2A.
class S2AChannelInterface {
 public:
  struct ByteBuffer {
    char* buffer;
    size_t length;
  };

  virtual ~S2AChannelInterface() = default;

  // |SendRPCFromByteBuffer| sends 1 RPC to the S2A whose contents are specified
  // by |message|, and returns an OK status if the RPC was sent successfully.
  virtual absl::Status SendRPCFromByteBuffer(const ByteBuffer& message) = 0;

  // |Cancel| cancels any in progress calls on the channel.
  virtual void Cancel() = 0;
};

}  // namespace s2a_channel
}  // namespace s2a

#endif  // INCLUDE_S2A_CHANNEL_INTERFACE_H_
