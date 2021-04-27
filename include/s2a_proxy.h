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

#ifndef INCLUDE_S2A_PROXY_H_
#define INCLUDE_S2A_PROXY_H_

#include <functional>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/synchronization/mutex.h"
#include "include//access_token_manager.h"
#include "include/s2a_channel_factory_interface.h"
#include "include/s2a_context.h"
#include "include/s2a_frame_protector.h"
#include "include/s2a_options.h"

namespace s2a {
namespace s2a_proxy {

// |S2AProxy| prepares messages to send to the S2A and parses messages received
// from the S2A.
class S2AProxy {
 public:
  using Buffer = std::vector<char>;
  using Logger = std::function<void(const std::string&)>;

  struct ProxyStatus {
    absl::Status status;
    size_t bytes_consumed;
    std::unique_ptr<Buffer> buffer;
  };

  struct S2AProxyOptions {
    Logger logger;
    bool is_client;
    std::string application_protocol;
    std::string target_hostname;  // Only used on the client-side.
    std::unique_ptr<s2a_options::S2AOptions> options;
    std::unique_ptr<s2a_channel::S2AChannelFactoryInterface> channel_factory;
    std::unique_ptr<
        s2a_channel::S2AChannelFactoryInterface::S2AChannelOptionsInterface>
        channel_options;
    std::unique_ptr<token_manager::AccessTokenManagerInterface> token_manager;
  };

  // |Create| returns an |S2AProxy| instance or nullptr if an error occurred.
  static std::unique_ptr<S2AProxy> Create(S2AProxyOptions& options);

  // |GetBytesForS2A| prepares a buffer to send to the S2A given the bytes
  // received from the peer in |buffer|, which may be empty if no bytes were
  // received (e.g. when called by a client at the start of the handshake).
  ProxyStatus GetBytesForS2A(std::unique_ptr<Buffer> bytes_from_peer);

  // |GetBytesForPeer| prepares a buffer to send to the peer given the bytes
  // received from the S2A in |bytes_from_s2a|, which may be empty if no bytes
  // were received (e.g. when called by a client at the start of the handshake).
  ProxyStatus GetBytesForPeer(std::unique_ptr<Buffer> bytes_from_s2a);

  // |IsHandshakeFinished| returns true if the handshake is finished.
  bool IsHandshakeFinished();

  // |CreateFrameProtector| returns a |S2AFrameProtector| initialized
  // using the session keys obtained during the TLS handshake, or an error
  // status if an error occurred. If the handshake is not complete,
  // |CreateFrameProtector| will always return an error status.
  absl::StatusOr<std::unique_ptr<frame_protector::S2AFrameProtector>>
  CreateFrameProtector();

  // |GetS2AContext| returns the |S2AContext| produced from the TLS handshake,
  // or an error status if the handshake is not yet complete.
  absl::variant<absl::Status, std::unique_ptr<s2a_context::S2AContext>>
  GetS2AContext();

 private:
  S2AProxy(
      Logger logger, bool is_client, const std::string& application_protocol,
      const std::string& target_hostname,
      std::unique_ptr<s2a_options::S2AOptions> options,
      std::unique_ptr<s2a_channel::S2AChannelFactoryInterface> channel_factory,
      std::unique_ptr<
          s2a_channel::S2AChannelFactoryInterface::S2AChannelOptionsInterface>
          channel_options,
      std::unique_ptr<token_manager::AccessTokenManagerInterface>
          token_manager);

  // |GetClientStart| prepares a serialized |ClientSessionStartReq| message.
  ProxyStatus GetClientStart();

  // |GetServerStart| prepares a serialized |ServerSessionStartReq| message.
  ProxyStatus GetServerStart(std::unique_ptr<Buffer> bytes_from_peer);

  // |GetNext| prepares a serialized |SessionNextReq| message.
  ProxyStatus GetNext(std::unique_ptr<Buffer> bytes_from_peer);

  // |PopulateTokenCache| populates the |token_cache_| based on the set of local
  // identities specified by |options_|.
  void PopulateTokenCache();

  const Logger logger_;
  const bool is_client_;
  const std::string application_protocol_;
  const std::string target_hostname_;
  const std::unique_ptr<s2a_options::S2AOptions> options_;
  std::unique_ptr<s2a_channel::S2AChannelFactoryInterface> channel_factory_;
  std::unique_ptr<
      s2a_channel::S2AChannelFactoryInterface::S2AChannelOptionsInterface>
      channel_options_;
  std::unique_ptr<token_manager::AccessTokenManagerInterface> token_manager_;
  absl::flat_hash_map<s2a_options::S2AOptions::Identity, std::string>
      token_cache_;
  // |selected_local_identity_| is the identity selected by the S2A and returned
  // to the |S2AProxy| as part of a |SessionResp| message.
  absl::StatusOr<s2a_options::S2AOptions::Identity> selected_local_identity_;

  struct S2AHandshakeResult {
    s2a_options::S2AOptions::TlsVersion tls_version;
    s2a_options::S2AOptions::Ciphersuite ciphersuite;
    std::vector<uint8_t> in_traffic_secret;
    std::vector<uint8_t> out_traffic_secret;
    uint64_t in_sequence;
    uint64_t out_sequence;
    uint64_t connection_id;
    s2a_options::S2AOptions::Identity local_identity =
        s2a_options::S2AOptions::Identity::GetEmptyIdentity();
  };

  absl::Mutex mu_;
  bool is_first_message_ = true;
  bool is_handshake_finished_ = false;
  std::unique_ptr<s2a_context::S2AContext> context_ = nullptr;
  std::unique_ptr<S2AHandshakeResult> result_ = nullptr;
};

}  // namespace s2a_proxy
}  // namespace s2a

#endif  // INCLUDE_S2A_PROXY_H_
