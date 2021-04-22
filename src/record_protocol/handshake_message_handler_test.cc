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

#include "src/record_protocol/handshake_message_handler.h"

#include <cstdint>
#include <memory>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "src/test_util/s2a_test_util.h"

namespace s2a {
namespace handshake_message_handler {
namespace {

using MessageFragment = std::vector<uint8_t>;
using Message = std::vector<std::unique_ptr<MessageFragment>>;
using Result = HandshakeMessageHandler::Result;

using ::s2a::handshake_message_handler::kKeyUpdateMessageType;
using ::s2a::handshake_message_handler::kSessionTicketMessageType;
using ::s2a::handshake_message_handler::kTlsHandshakeHeaderLength;
using ::s2a::test_util::StatusIs;

constexpr uint32_t kTestTicketDataNumBytes = 10;
constexpr uint32_t kTestKeyUpdateDataNumBytes = 1;
constexpr uint32_t kTestKeyUpdateType = 0x01;
constexpr size_t kInvalidKeyUpdateType = 0xFF;

/* Utility method for setting the header of a handshake message. */
void SetMessageHeader(uint8_t* buffer, uint8_t message_type,
                      uint32_t message_len) {
  ASSERT_TRUE(buffer != nullptr);
  buffer[0] = message_type;
  buffer[1] = message_len >> 16;
  buffer[2] = message_len >> 8;
  buffer[3] = message_len & 0xff;
}

std::vector<uint8_t> CreateOneTicket() {
  /* Create a ticket and set its header. The rest of the ticket is filled with
   * zeroes. */
  size_t message_size = kTlsHandshakeHeaderLength + kTestTicketDataNumBytes;
  std::vector<uint8_t> ticket_message(message_size, 0);
  SetMessageHeader(ticket_message.data(), kSessionTicketMessageType,
                   kTestTicketDataNumBytes);
  return ticket_message;
}

std::vector<std::vector<uint8_t>> CreateOneTicketDataFragmented() {
  /* Create two fragments for a ticket. The first fragment contains the header
   * and a portion of the ticket data. The second fragment contains the
   * remaining ticket data. */
  size_t message_size = kTlsHandshakeHeaderLength + kTestTicketDataNumBytes;
  size_t second_frag_len = 5;
  /* Set the header in the first fragment. */
  size_t first_message_size = message_size - second_frag_len;
  std::vector<uint8_t> first_ticket_fragment(first_message_size, 0);
  SetMessageHeader(first_ticket_fragment.data(), kSessionTicketMessageType,
                   kTestTicketDataNumBytes);
  /* Fill second fragment with zeroes. */
  size_t second_message_size = second_frag_len;
  std::vector<uint8_t> second_ticket_fragment(second_message_size, 0);

  std::vector<std::vector<uint8_t>> frags;
  frags.push_back(first_ticket_fragment);
  frags.push_back(second_ticket_fragment);
  return frags;
}

std::vector<std::vector<uint8_t>> CreateOneTicketHeaderFragmented() {
  /* Create two fragments for a ticket. The first fragment contains a portion
   * of the header. The second fragment contains the remaining portion of the
   * header and the ticket data filled with zeros. */
  size_t message_size = kTlsHandshakeHeaderLength + kTestTicketDataNumBytes;
  size_t first_frag_len = 2;
  /* Set half of the header in the first fragment. */
  std::vector<uint8_t> first_ticket_fragment(first_frag_len, 0);
  first_ticket_fragment[0] = 0x04;
  first_ticket_fragment[1] = kTestTicketDataNumBytes >> 16;

  /* Second half of header followed by ticket data filled with zeroes. */
  size_t second_message_size = message_size - first_frag_len;
  std::vector<uint8_t> second_ticket_fragment(second_message_size, 0);
  second_ticket_fragment[0] = kTestTicketDataNumBytes >> 8;
  second_ticket_fragment[1] = kTestTicketDataNumBytes & 0xff;

  std::vector<std::vector<uint8_t>> frags;
  frags.push_back(first_ticket_fragment);
  frags.push_back(second_ticket_fragment);
  return frags;
}

std::vector<uint8_t> CreateTwoTicketsOneRecord() {
  /* Create buffer big enough for two tickets. */
  size_t message_size = kTlsHandshakeHeaderLength + kTestTicketDataNumBytes;
  std::vector<uint8_t> ticket_message(message_size * 2, 0);
  size_t at_byte = 0;
  /* Set header of first ticket. */
  SetMessageHeader(ticket_message.data(), kSessionTicketMessageType,
                   kTestTicketDataNumBytes);
  at_byte += message_size;
  /* Set header of second ticket. */
  SetMessageHeader(ticket_message.data() + at_byte, kSessionTicketMessageType,
                   kTestTicketDataNumBytes);
  return ticket_message;
}

std::vector<uint8_t> CreateTwoTicketsAndKeyUpdateOneRecord() {
  size_t ticket_message_size =
      kTlsHandshakeHeaderLength + kTestTicketDataNumBytes;
  size_t key_update_message_size =
      kTlsHandshakeHeaderLength + kTestKeyUpdateDataNumBytes;
  std::vector<uint8_t> record_payload(
      ticket_message_size * 2 + key_update_message_size, 0);
  size_t at_byte = 0;
  /* Set header of first ticket. */
  SetMessageHeader(record_payload.data(), kSessionTicketMessageType,
                   kTestTicketDataNumBytes);
  at_byte += ticket_message_size;
  /* Set header of second ticket. */
  SetMessageHeader(record_payload.data() + at_byte, kSessionTicketMessageType,
                   kTestTicketDataNumBytes);
  at_byte += ticket_message_size;
  /* Set header of key update. */
  SetMessageHeader(record_payload.data() + at_byte, kKeyUpdateMessageType,
                   kTestKeyUpdateDataNumBytes);
  /* Set key update type. */
  record_payload[at_byte + 4] = kTestKeyUpdateType;
  return record_payload;
}

std::vector<uint8_t> CreateKeyUpdateRecord() {
  size_t message_size = kTlsHandshakeHeaderLength + kTestKeyUpdateDataNumBytes;
  std::vector<uint8_t> record_payload(message_size, 0);
  /* Set header and data of key update. */
  SetMessageHeader(record_payload.data(), kKeyUpdateMessageType,
                   kTestKeyUpdateDataNumBytes);
  /* Set key update type. */
  record_payload[4] = kTestKeyUpdateType;
  return record_payload;
}

std::vector<uint8_t> CreateTwoKeyUpdatesOneRecord() {
  size_t message_size = kTlsHandshakeHeaderLength + kTestKeyUpdateDataNumBytes;
  std::vector<uint8_t> record_payload(message_size * 2, 0);
  size_t at_byte = 0;
  /* Set header and data of first key update. */
  SetMessageHeader(record_payload.data() + at_byte, kKeyUpdateMessageType,
                   kTestKeyUpdateDataNumBytes);
  record_payload[at_byte + 4] = kTestKeyUpdateType;
  at_byte += message_size;
  /* Set header and data of second key update. */
  SetMessageHeader(record_payload.data() + at_byte, kKeyUpdateMessageType,
                   kTestKeyUpdateDataNumBytes);
  record_payload[at_byte + 4] = kTestKeyUpdateType;
  return record_payload;
}

void CheckProcessMessageSuccess(absl::variant<absl::Status, Result> result,
                                bool expecting_to_read_more_bytes,
                                bool contains_key_update,
                                uint8_t key_update_type, bool contains_ticket,
                                size_t num_full_tickets_stored) {
  /* Expect the variant to contain a valid result. */
  switch (result.index()) {
    case 0:
      EXPECT_TRUE(false) << absl::get<0>(result).message();
      return;
    case 1:
      EXPECT_EQ(absl::get<1>(result).expecting_to_read_more_bytes,
                expecting_to_read_more_bytes);
      EXPECT_EQ(absl::get<1>(result).contains_key_update, contains_key_update);
      EXPECT_EQ(absl::get<1>(result).key_update_type, key_update_type);
      EXPECT_EQ(absl::get<1>(result).contains_ticket, contains_ticket);
      EXPECT_EQ(absl::get<1>(result).num_full_tickets_stored,
                num_full_tickets_stored);
      return;
    default:
      EXPECT_TRUE(false);
      return;
  }
}

void CheckProcessMessageFailure(absl::variant<absl::Status, Result> result,
                                absl::StatusCode status_code,
                                absl::string_view status_message) {
  /* Expect the variant to contain a status. */
  switch (result.index()) {
    case 0:
      EXPECT_THAT(absl::get<0>(result), StatusIs(status_code, status_message))
          << absl::get<0>(result).message();
      return;
    case 1:
      EXPECT_TRUE(false);
      return;
    default:
      EXPECT_TRUE(false);
      return;
  }
}

void CheckGetTicketsSuccess(
    absl::variant<absl::Status,
                  std::unique_ptr<std::vector<std::unique_ptr<Message>>>>
        tickets,
    size_t num_tickets_stored, std::vector<uint8_t> plaintext) {
  /* Expect the variant to contain tickets. */
  switch (tickets.index()) {
    case 0:
      EXPECT_TRUE(false) << absl::get<0>(tickets).message();
      return;
    case 1:
      /* Verify number of tickets. */
      EXPECT_EQ(absl::get<1>(tickets)->size(), num_tickets_stored);

      for (auto& ticket : *(absl::get<1>(tickets))) {
        /* Verify size of ticket. */
        size_t ticket_total_size = 0;
        for (auto& fragment : *ticket) {
          ticket_total_size += fragment->size();
        }
        EXPECT_EQ(ticket_total_size,
                  kTlsHandshakeHeaderLength + kTestTicketDataNumBytes);

        /* Merge ticket fragments and verify content of ticket. */
        std::vector<uint8_t> ticket_joined(ticket_total_size, 0);
        size_t at_byte = 0;
        for (auto& fragment : *ticket) {
          memcpy(&ticket_joined[0] + at_byte, fragment->data(),
                 fragment->size());
          at_byte += fragment->size();
        }
        EXPECT_EQ(plaintext, ticket_joined);
      }
      return;
    default:
      EXPECT_TRUE(false);
      return;
  }
}

void CheckGetTicketsFailure(
    absl::variant<absl::Status,
                  std::unique_ptr<std::vector<std::unique_ptr<Message>>>>
        tickets,
    absl::StatusCode status_code, absl::string_view status_message) {
  /* Expect the variant to contain a status. */
  switch (tickets.index()) {
    case 0:
      EXPECT_THAT(absl::get<0>(tickets), StatusIs(status_code, status_message))
          << absl::get<0>(tickets).message();
      return;
    case 1:
      EXPECT_TRUE(false);
      return;
    default:
      EXPECT_TRUE(false);
      return;
  }
}

TEST(HandshakeMessageHandler, ProcessHandshakeMessageFailure) {
  HandshakeMessageHandler handler;
  absl::variant<absl::Status, Result> result_or_status =
      handler.ProcessHandshakeMessage(nullptr, /*plaintext_len=*/0);
  CheckProcessMessageFailure(
      result_or_status, absl::StatusCode::kInvalidArgument,
      "Plaintext passed to |ProcessTicketBytes| must not be nullptr.");
}

TEST(HandshakeMessageHandler, OneTicketInOneRecord) {
  HandshakeMessageHandler handler;

  std::vector<uint8_t> plaintext = CreateOneTicket();
  absl::variant<absl::Status, Result> result_or_status =
      handler.ProcessHandshakeMessage(plaintext.data(), plaintext.size());
  CheckProcessMessageSuccess(result_or_status,
                             /*expecting_to_read_more_bytes=*/false,
                             /*contains_key_update=*/false,
                             kInvalidKeyUpdateType,
                             /*contains_ticket=*/true,
                             /*num_full_tickets_stored=*/1);
}

TEST(HandshakeMessageHandler, TwoTicketsInOneRecord) {
  HandshakeMessageHandler handler;

  std::vector<uint8_t> plaintext = CreateTwoTicketsOneRecord();
  absl::variant<absl::Status, Result> result_or_status =
      handler.ProcessHandshakeMessage(plaintext.data(), plaintext.size());
  CheckProcessMessageSuccess(result_or_status,
                             /*expecting_to_read_more_bytes=*/false,
                             /*contains_key_update=*/false,
                             kInvalidKeyUpdateType,
                             /*contains_ticket=*/true,
                             /*num_full_tickets_stored=*/2);
}

TEST(HandshakeMessageHandler, TwoTicketsInTwoConsecutiveRecords) {
  HandshakeMessageHandler handler;

  std::vector<uint8_t> plaintext1 = CreateOneTicket();
  absl::variant<absl::Status, Result> result1_or_status =
      handler.ProcessHandshakeMessage(plaintext1.data(), plaintext1.size());
  CheckProcessMessageSuccess(result1_or_status,
                             /*expecting_to_read_more_bytes=*/false,
                             /*contains_key_update=*/false,
                             kInvalidKeyUpdateType,
                             /*contains_ticket=*/true,
                             /*num_full_tickets_stored=*/1);

  std::vector<uint8_t> plaintext2 = CreateOneTicket();
  absl::variant<absl::Status, Result> result2_or_status =
      handler.ProcessHandshakeMessage(plaintext2.data(), plaintext2.size());
  CheckProcessMessageSuccess(result2_or_status,
                             /*expecting_to_read_more_bytes=*/false,
                             /*contains_key_update=*/false,
                             kInvalidKeyUpdateType,
                             /*contains_ticket=*/true,
                             /*num_full_tickets_stored=*/2);
}

TEST(HandshakeMessageHandler, OneTicketInTwoRecordsDataFragmented) {
  HandshakeMessageHandler handler;

  std::vector<std::vector<uint8_t>> fragments = CreateOneTicketDataFragmented();
  absl::variant<absl::Status, Result> result_or_status;
  for (auto& plaintext : fragments) {
    result_or_status =
        handler.ProcessHandshakeMessage(plaintext.data(), plaintext.size());
    bool expecting_to_read_more_bytes;
    size_t num_full_tickets_stored;
    if (&plaintext != &fragments.back()) {
      /* If not the last fragment. */
      expecting_to_read_more_bytes = true;
      num_full_tickets_stored = 0;
    } else {
      expecting_to_read_more_bytes = false;
      num_full_tickets_stored = 1;
    }
    CheckProcessMessageSuccess(
        result_or_status, expecting_to_read_more_bytes,
        /*contains_key_update=*/false, kInvalidKeyUpdateType,
        /*contains_ticket=*/true, num_full_tickets_stored);
  }
}

TEST(HandshakeMessageHandler, OneTicketInTwoRecordsHeaderFragmented) {
  HandshakeMessageHandler handler;

  std::vector<std::vector<uint8_t>> fragments =
      CreateOneTicketHeaderFragmented();
  absl::variant<absl::Status, Result> result_or_status;
  for (auto& plaintext : fragments) {
    result_or_status =
        handler.ProcessHandshakeMessage(plaintext.data(), plaintext.size());
    bool expecting_to_read_more_bytes;
    size_t num_full_tickets_stored;
    if (&plaintext != &fragments.back()) {
      /* If not the last fragment. */
      expecting_to_read_more_bytes = true;
      num_full_tickets_stored = 0;
    } else {
      expecting_to_read_more_bytes = false;
      num_full_tickets_stored = 1;
    }
    CheckProcessMessageSuccess(
        result_or_status, expecting_to_read_more_bytes,
        /*contains_key_update=*/false, kInvalidKeyUpdateType,
        /*contains_ticket=*/true, num_full_tickets_stored);
  }
}

TEST(HandshakeMessageHandler, ProcessHandshakeMessageReachedTicketLimit) {
  HandshakeMessageHandler handler;

  /* Process |kMaxNumTicketsToProcess| many tickets in consecutive records. */
  absl::variant<absl::Status, Result> result1_or_status;
  for (int i = 1; i <= kMaxNumTicketsToProcess; i++) {
    std::vector<uint8_t> plaintext = CreateOneTicket();
    result1_or_status =
        handler.ProcessHandshakeMessage(plaintext.data(), plaintext.size());
    CheckProcessMessageSuccess(result1_or_status,
                               /*expecting_to_read_more_bytes=*/false,
                               /*contains_key_update=*/false,
                               kInvalidKeyUpdateType,
                               /*contains_ticket=*/true,
                               /*num_full_tickets_stored=*/i);
  }

  /* Future tickets should be ignored (number of stored tickets stays the same.
   */
  std::vector<uint8_t> plaintext = CreateOneTicket();
  absl::variant<absl::Status, Result> result2_or_status =
      handler.ProcessHandshakeMessage(plaintext.data(), plaintext.size());
  CheckProcessMessageSuccess(result2_or_status,
                             /*expecting_to_read_more_bytes=*/false,
                             /*contains_key_update=*/false,
                             kInvalidKeyUpdateType,
                             /*contains_ticket=*/true, kMaxNumTicketsToProcess);
}

TEST(HandshakeMessageHandler, OneKeyUpdateInOneRecord) {
  HandshakeMessageHandler handler;

  std::vector<uint8_t> plaintext = CreateKeyUpdateRecord();
  absl::variant<absl::Status, Result> result_or_status =
      handler.ProcessHandshakeMessage(plaintext.data(), plaintext.size());
  CheckProcessMessageSuccess(result_or_status,
                             /*expecting_to_read_more_bytes=*/false,
                             /*contains_key_update=*/true, kTestKeyUpdateType,
                             /*contains_ticket=*/false,
                             /*num_full_tickets_stored=*/0);
}

TEST(HandshakeMessageHandler, TwoTicketsAndKeyUpdateInOneRecord) {
  HandshakeMessageHandler handler;

  std::vector<uint8_t> plaintext = CreateTwoTicketsAndKeyUpdateOneRecord();
  absl::variant<absl::Status, Result> result_or_status =
      handler.ProcessHandshakeMessage(plaintext.data(), plaintext.size());
  CheckProcessMessageSuccess(result_or_status,
                             /*expecting_to_read_more_bytes=*/false,
                             /*contains_key_update=*/true, kTestKeyUpdateType,
                             /*contains_ticket=*/true,
                             /*num_full_tickets_stored=*/2);
}

TEST(HandshakeMessageHandler, KeyUpdateNotTheLastByteFailure) {
  HandshakeMessageHandler handler;

  /* Processing two key updates in the same record should fail cause a key
   * update message needs to be the last byte in a record. */
  std::vector<uint8_t> plaintext = CreateTwoKeyUpdatesOneRecord();
  absl::variant<absl::Status, Result> result_or_status =
      handler.ProcessHandshakeMessage(plaintext.data(), plaintext.size());
  CheckProcessMessageFailure(
      result_or_status, absl::StatusCode::kInternal,
      "Key update should be the last message in a plaintext.");
}

TEST(HandshakeMessageHandler, GetStoredTicketsSuccess) {
  HandshakeMessageHandler handler;

  /* Process |kMaxNumTicketsToProcess - 2| tickets in consecutive records. */
  absl::variant<absl::Status, Result> result1_or_status;
  std::vector<uint8_t> plaintext = CreateOneTicket();
  for (int i = 0; i < kMaxNumTicketsToProcess - 2; i++) {
    result1_or_status =
        handler.ProcessHandshakeMessage(plaintext.data(), plaintext.size());
  }
  /* Process a ticket with data fragmented into two records. */
  std::vector<std::vector<uint8_t>> fragments1 =
      CreateOneTicketDataFragmented();
  for (auto& fragment : fragments1) {
    result1_or_status =
        handler.ProcessHandshakeMessage(fragment.data(), fragment.size());
  }
  /* Process a ticket with header fragmented into two records. */
  std::vector<std::vector<uint8_t>> fragments2 =
      CreateOneTicketHeaderFragmented();
  for (auto& fragment : fragments2) {
    result1_or_status =
        handler.ProcessHandshakeMessage(fragment.data(), fragment.size());
  }
  CheckProcessMessageSuccess(result1_or_status,
                             /*expecting_to_read_more_bytes=*/false,
                             /*contains_key_update=*/false,
                             kInvalidKeyUpdateType,
                             /*contains_ticket=*/true, kMaxNumTicketsToProcess);

  /* At this point we have processed |kMaxNumTicketsToProcess| and should be
   * ready to send to S2A. We verify the content of all tickets (all tickets
   * contain the same content). */
  auto tickets_or_status = handler.GetStoredTickets();
  CheckGetTicketsSuccess(std::move(tickets_or_status),
                         /*num_tickets_stored=*/kMaxNumTicketsToProcess,
                         plaintext);
}

TEST(HandshakeMessageHandler, GetStoredTicketsAlreadyRetrievedFailure) {
  HandshakeMessageHandler handler;

  /* Process one ticket and retrieve the stored ticket. */
  std::vector<uint8_t> plaintext = CreateOneTicket();
  absl::variant<absl::Status, Result> result_or_status =
      handler.ProcessHandshakeMessage(plaintext.data(), plaintext.size());
  CheckProcessMessageSuccess(
      result_or_status,
      /*expecting_to_read_more_bytes=*/false,
      /*contains_key_update=*/false, kInvalidKeyUpdateType,
      /*contains_ticket=*/true, /*num_full_tickets_stored=*/1);
  auto tickets_or_status = handler.GetStoredTickets();
  CheckGetTicketsSuccess(std::move(tickets_or_status), /*num_tickets_stored=*/1,
                         plaintext);

  /* Future calls after retrieving tickets should return an error. */
  tickets_or_status = handler.GetStoredTickets();
  CheckGetTicketsFailure(std::move(tickets_or_status),
                         absl::StatusCode::kInternal,
                         "|GetStoredTickets| should not be called after "
                         "tickets have been retrieved.");
}

}  //  namespace
}  //  namespace handshake_message_handler
}  //  namespace s2a
