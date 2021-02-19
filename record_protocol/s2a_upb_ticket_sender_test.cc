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

#include "proto/common.upb.h"
#include "proto/s2a.upb.h"
#include "record_protocol/s2a_ticket_sender.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "upb/upb.hpp"

namespace s2a {
namespace s2a_ticket_sender {
namespace {

using Identity = s2a_options::S2AOptions::Identity;
using IdentityType = s2a_options::S2AOptions::IdentityType;

constexpr char kTestLocalIdentity[] = "test_local_identity";
constexpr uint64_t kConnectionId = 1234;
constexpr uint8_t kResumptionTicketOne[] = {0x04, 0x00, 0x00, 0x01, 0x00};
constexpr uint8_t kResumptionTicketTwo[] = {0x04, 0x00, 0x00, 0x01, 0x01};

void CompareWithByteVector(const upb_strview& message_one,
                           const uint8_t* message_two,
                           size_t message_two_size) {
  EXPECT_EQ(message_one.size, message_two_size);
  for (size_t i = 0; i < message_two_size; i++) {
    EXPECT_EQ(message_one.data[i], message_two[i]);
  }
}

TEST(S2AUpbTicketSenderTest, PrepareTicketSessionReqFailure) {
  const struct {
    std::string desc;
    Identity identity;
    bool nullptr_tickets;
  } tests[] = {
      {"Fail because of empty identity.", Identity::GetEmptyIdentity(),
       /*nullptr_tickets=*/false},
      {"Fail because tickets options is nullptr.",
       Identity::FromHostname(kTestLocalIdentity),
       /*nullptr_tickets=*/true},
  };

  for (int i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
    upb::Arena arena;
    s2a_proto_SessionReq* request = s2a_proto_SessionReq_new(arena.ptr());

    auto tickets =
        absl::make_unique<std::vector<std::unique_ptr<std::string>>>();
    auto ticket = absl::make_unique<std::string>(
        reinterpret_cast<const char*>(kResumptionTicketOne),
        sizeof(kResumptionTicketOne));
    tickets->push_back(std::move(ticket));
    if (tests[i].nullptr_tickets) {
      tickets = nullptr;
    }
    EXPECT_FALSE(PrepareResumptionTicketReq(kConnectionId, tests[i].identity,
                                            tickets, arena.ptr(), request));
  }
}

TEST(S2AUpbTicketSenderTest,
     PrepareTicketSessionReqSuccessWithOneTicketAndHostname) {
  auto tickets = absl::make_unique<std::vector<std::unique_ptr<std::string>>>();
  std::string ticket(reinterpret_cast<const char*>(kResumptionTicketOne),
                     sizeof(kResumptionTicketOne));
  tickets->push_back(absl::make_unique<std::string>(ticket));

  // Prepare |ResumptionTicketReq| message with a single ticket.
  upb::Arena arena;
  s2a_proto_SessionReq* request = s2a_proto_SessionReq_new(arena.ptr());
  Identity test_local_identity = Identity::FromHostname(kTestLocalIdentity);
  ASSERT_TRUE(PrepareResumptionTicketReq(kConnectionId, test_local_identity,
                                         tickets, arena.ptr(), request));

  // Check the contents of the |SessionReq| message.
  ASSERT_TRUE(s2a_proto_SessionReq_has_resumption_ticket(request));
  const s2a_proto_ResumptionTicketReq* ticket_req =
      s2a_proto_SessionReq_resumption_ticket(request);
  EXPECT_EQ(s2a_proto_ResumptionTicketReq_connection_id(ticket_req),
            kConnectionId);
  const s2a_proto_Identity* local_identity =
      s2a_proto_ResumptionTicketReq_local_identity(ticket_req);
  EXPECT_TRUE(s2a_proto_Identity_has_hostname(local_identity));
  EXPECT_TRUE(upb_strview_eql(s2a_proto_Identity_hostname(local_identity),
                              upb_strview_makez(kTestLocalIdentity)));

  size_t ticket_list_size = 0;
  const upb_strview* ticket_list =
      s2a_proto_ResumptionTicketReq_in_bytes(ticket_req, &ticket_list_size);
  ASSERT_NE(ticket_list, nullptr);
  EXPECT_EQ(ticket_list_size, 1);
  CompareWithByteVector(ticket_list[0], kResumptionTicketOne,
                        sizeof(kResumptionTicketOne));
}

TEST(S2AUpbTicketSenderTest,
     PrepareTicketSessionReqSuccessWithTwoTicketsAndSpiffeId) {
  auto tickets = absl::make_unique<std::vector<std::unique_ptr<std::string>>>();
  std::string ticket_one(reinterpret_cast<const char*>(kResumptionTicketOne),
                         sizeof(kResumptionTicketOne));
  std::string ticket_two(reinterpret_cast<const char*>(kResumptionTicketTwo),
                         sizeof(kResumptionTicketTwo));
  tickets->push_back(absl::make_unique<std::string>(ticket_one));
  tickets->push_back(absl::make_unique<std::string>(ticket_two));

  // Prepare |ResumptionTicketReq| message with a single ticket.
  upb::Arena arena;
  s2a_proto_SessionReq* request = s2a_proto_SessionReq_new(arena.ptr());
  Identity test_local_identity = Identity::FromSpiffeId(kTestLocalIdentity);
  ASSERT_TRUE(PrepareResumptionTicketReq(kConnectionId, test_local_identity,
                                         tickets, arena.ptr(), request));

  // Check the contents of the |SessionReq| message.
  ASSERT_TRUE(s2a_proto_SessionReq_has_resumption_ticket(request));
  const s2a_proto_ResumptionTicketReq* ticket_req =
      s2a_proto_SessionReq_resumption_ticket(request);
  EXPECT_EQ(s2a_proto_ResumptionTicketReq_connection_id(ticket_req),
            kConnectionId);
  const s2a_proto_Identity* local_identity =
      s2a_proto_ResumptionTicketReq_local_identity(ticket_req);
  EXPECT_TRUE(s2a_proto_Identity_has_spiffe_id(local_identity));
  EXPECT_TRUE(upb_strview_eql(s2a_proto_Identity_spiffe_id(local_identity),
                              upb_strview_makez(kTestLocalIdentity)));

  size_t ticket_list_size = 0;
  const upb_strview* ticket_list =
      s2a_proto_ResumptionTicketReq_in_bytes(ticket_req, &ticket_list_size);
  ASSERT_NE(ticket_list, nullptr);
  EXPECT_EQ(ticket_list_size, 2);
  CompareWithByteVector(ticket_list[0], kResumptionTicketOne,
                        sizeof(kResumptionTicketOne));
  CompareWithByteVector(ticket_list[1], kResumptionTicketTwo,
                        sizeof(kResumptionTicketTwo));
}

TEST(S2AProtoTicketSenderTest, SendTicketsToS2AUnimplemented) {
  TicketSenderOptions options = {/*handshaker_service_url=*/"",
                                 /*connection_id=*/0,
                                 Identity::FromSpiffeId(kTestLocalIdentity),
                                 /*tickets=*/nullptr};
  EXPECT_EQ(SendTicketsToS2A(options), nullptr);
}

}  // namespace
}  // namespace s2a_ticket_sender
}  // namespace s2a
