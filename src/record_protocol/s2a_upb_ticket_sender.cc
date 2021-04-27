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

#include "src/proto/upb-generated/proto/common.upb.h"
#include "src/proto/upb-generated/proto/s2a.upb.h"
#include "src/record_protocol/s2a_ticket_sender.h"
#include "upb/upb.hpp"

namespace s2a {
namespace s2a_ticket_sender {

WaitOnTicketSender SendTicketsToS2A(TicketSenderOptions& options) {
  // TODO(matthewstevenson88) Implement.
  return nullptr;
}

bool PrepareResumptionTicketReq(
    uint64_t connection_id,
    const s2a_options::S2AOptions::Identity& local_identity,
    const std::unique_ptr<std::vector<std::unique_ptr<std::string>>>& tickets,
    void* arena, void* request) {
  // Input checks.
  ABSL_ASSERT(arena != nullptr);
  ABSL_ASSERT(request != nullptr);
  if (tickets == nullptr) {
    return false;
  }

  // Cast |arena| and |request| to a UPB arena and |s2a_proto_SessionReq|.
  upb_arena* ar = reinterpret_cast<upb_arena*>(arena);
  s2a_proto_SessionReq* req = reinterpret_cast<s2a_proto_SessionReq*>(request);
  s2a_proto_ResumptionTicketReq* ticket_req =
      s2a_proto_SessionReq_mutable_resumption_ticket(req, ar);
  s2a_proto_ResumptionTicketReq_set_connection_id(ticket_req, connection_id);

  // Set the local identity. If the type is unrecognized, then fail because the
  // S2A will not know how to process the ticket, so there is no point in
  // sending a request that is doomed to fail.
  s2a_proto_Identity* identity =
      s2a_proto_ResumptionTicketReq_mutable_local_identity(ticket_req, ar);
  switch (local_identity.GetIdentityType()) {
    case s2a_options::S2AOptions::IdentityType::SPIFFE_ID:
      s2a_proto_Identity_set_spiffe_id(
          identity, upb_strview_makez(local_identity.GetIdentityCString()));
      break;
    case s2a_options::S2AOptions::IdentityType::HOSTNAME:
      s2a_proto_Identity_set_hostname(
          identity, upb_strview_makez(local_identity.GetIdentityCString()));
      break;
    case s2a_options::S2AOptions::IdentityType::UID:
      s2a_proto_Identity_set_uid(
          identity, upb_strview_makez(local_identity.GetIdentityCString()));
      break;
    default:
      return false;
  }

  // Add the tickets to the request.
  for (auto& ticket : *tickets) {
    ABSL_ASSERT(ticket != nullptr);
    upb_strview bytes = upb_strview_make(ticket->data(), ticket->size());
    s2a_proto_ResumptionTicketReq_add_in_bytes(ticket_req, bytes, ar);
  }
  return true;
}

}  // namespace s2a_ticket_sender
}  // namespace s2a
