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

#ifndef INCLUDE_S2A_CHANNEL_FACTORY_INTERFACE_H_
#define INCLUDE_S2A_CHANNEL_FACTORY_INTERFACE_H_

#include "absl/status/statusor.h"
#include "include/s2a_channel_interface.h"

namespace s2a {
namespace s2a_channel {

class S2AChannelFactoryInterface {
 public:
  // |S2AChannelOptionsInterface| is an interface for all options needed to
  // build a given |S2AChannelInterface| implementation.
  struct S2AChannelOptionsInterface {};

  virtual ~S2AChannelFactoryInterface() = default;

  // |WaitForChannelReady| waits until a channel is ready to be built. This can
  // be used to asynchronously perform any preperatory operations that must
  // occur before a channel can be created. Calling this more than once is a
  // no-op.
  virtual void WaitForChannelReady() = 0;

  // |Build| builds a channel to the S2A, or an error status, and does not take
  // ownership of |options|.
  virtual absl::StatusOr<std::unique_ptr<S2AChannelInterface>> Build(
      S2AChannelOptionsInterface* options) = 0;
};

}  // namespace s2a_channel
}  // namespace s2a

#endif  // INCLUDE_S2A_CHANNEL_FACTORY_INTERFACE_H_
