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

#ifndef RECORD_PROTOCOL_S2A_TICKET_SENDER_H_
#define RECORD_PROTOCOL_S2A_TICKET_SENDER_H_

#include "channel/s2a_channel_factory_interface.h"
#include "options/s2a_options.h"
#include "absl/strings/string_view.h"

namespace s2a {
namespace s2a_ticket_sender {

struct TicketSenderOptions {
  /* URL of S2A handshaker service. */
  const std::string handshaker_service_url;
  /* Connection ID generated by the S2A at the end of session setup. */
  const uint64_t connection_id;
  /* Local identity used during session setup. */
  const s2a_options::S2AOptions::Identity& local_identity;
  /* Resumption tickets to be forwarded to S2A. */
  std::unique_ptr<std::vector<std::unique_ptr<std::string>>> tickets;
  /* Factory and options for creating a channel to the S2A. */
  std::unique_ptr<s2a_channel::S2AChannelFactoryInterface> channel_factory;
  std::unique_ptr<
      s2a_channel::S2AChannelFactoryInterface::S2AChannelOptionsInterface>
      channel_options;
};

/* A pointer to a function that should be called to ensure the ticket sender is
 * done sending tickets. It returns a boolean that is set to true if the RPC
 * call completed with no errors. */
typedef bool (*WaitOnTicketSender)();

/* A pointer to a function that will be called to send tickets to the S2A
 * handshaker service. */
typedef WaitOnTicketSender (*TicketSender)(TicketSenderOptions& options);

/** This function starts an asynchronous RPC call to send resumption tickets to
 *  S2A. It returns a pointer to a function that should be called to ensure that
 *  the underlying client reactor has completed all operations related to the
 *  RPC call. */
WaitOnTicketSender SendTicketsToS2A(TicketSenderOptions& options);

/** |PrepareResumptionTicketReq| prepares a |ResumptionTicketReq| proto message
 *  and returns |true| on success. This is exposed for testing purposes only. */
bool PrepareResumptionTicketReq(
    uint64_t connection_id,
    const s2a_options::S2AOptions::Identity& local_identity,
    const std::unique_ptr<std::vector<std::unique_ptr<std::string>>>& tickets,
    void* arena, void* request);

}  //  namespace s2a_ticket_sender
}  //  namespace s2a

#endif  // RECORD_PROTOCOL_S2A_TICKET_SENDER_H_
