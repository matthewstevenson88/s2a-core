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

#include "s2a/src/record_protocol/handshake_message_handler.h"

#include <cstdint>
#include <memory>
#include <utility>

#include "absl/base/macros.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"

namespace s2a {
namespace handshake_message_handler {

using MessageFragment = HandshakeMessageHandler::MessageFragment;
using Message = HandshakeMessageHandler::Message;
using Result = HandshakeMessageHandler::Result;

namespace {

/* An invalid key update type included in a result when there is no key update
 * message in the record. */
constexpr uint8_t kInvalidKeyUpdateType = 0xFF;

}  // namespace

HandshakeMessageHandler::HandshakeMessageHandler()
    : message_fragments_(absl::make_unique<Message>()),
      full_tickets_(
          absl::make_unique<std::vector<std::unique_ptr<Message>>>()) {}

absl::variant<absl::Status, Result>
HandshakeMessageHandler::ProcessHandshakeMessage(const uint8_t* plaintext,
                                                 size_t plaintext_len) {
  if (plaintext == nullptr) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Plaintext passed to |ProcessTicketBytes| must not be nullptr.");
  }

  bool contains_key_update = false;
  bool contains_ticket = false;
  size_t at_byte = 0;
  /* This loop parses a handshake message(s) in |plaintext|. It stores fragments
   * in a buffer until a full handshake message is read, and processes the full
   * message. If the parses finds a ticket message but |IgnoreFutureTickets()|
   * is true, |StoreMessageFragment()| doesn't actually copy the ticket to the
   * internal buffer to reduce uneccessary copying. |at_byte| and the other
   * states will still be updated
   * since there may be more handshake messages to parse after the ticket. */
  while (at_byte < plaintext_len) {
    /* Step 1. Read the next fragment (or full message) from plaintext. */
    size_t bytes_left_to_read = plaintext_len - at_byte;
    bool full_hs_message_read = false;
    switch (state_) {
      case State::READ_HEADER:
        if (num_header_bytes_expecting_to_read_ <= bytes_left_to_read) {
          /* Header is not fragmented, or this fragment completes header. */
          StoreMessageFragment(plaintext, at_byte,
                               num_header_bytes_expecting_to_read_);
          at_byte += num_header_bytes_expecting_to_read_;
          /* Update state. */
          num_header_bytes_expecting_to_read_ = kTlsHandshakeHeaderLength;
          num_data_bytes_expecting_to_read_ = GetMessageDataSizeFromHeader();
          if (num_data_bytes_expecting_to_read_ > 0) {
            state_ = State::READ_DATA;
          }
        } else {
          /* Read incomplete message header. Read all remaining bytes. */
          StoreMessageFragment(plaintext, at_byte, bytes_left_to_read);
          at_byte += bytes_left_to_read;
          /* Update state. */
          num_header_bytes_expecting_to_read_ -= bytes_left_to_read;
        }
        break;
      case State::READ_DATA:
        if (num_data_bytes_expecting_to_read_ <= bytes_left_to_read) {
          /* Data is not fragmented, or this fragment completes data. */
          StoreMessageFragment(plaintext, at_byte,
                               num_data_bytes_expecting_to_read_);
          at_byte += num_data_bytes_expecting_to_read_;
          full_hs_message_read = true;
          /* Update state. */
          num_data_bytes_expecting_to_read_ = 0;
          state_ = State::READ_HEADER;
        } else {
          /* Read incomplete message data. Read all remaining bytes. */
          StoreMessageFragment(plaintext, at_byte, bytes_left_to_read);
          at_byte += bytes_left_to_read;
          /* Update state. */
          num_data_bytes_expecting_to_read_ -= bytes_left_to_read;
        }
        break;
      default:
        return absl::Status(absl::StatusCode::kInternal,
                            "Handshake message parser in unexpected state.");
    }

    /* Step 2: Check if a complete handshake message is read. */
    uint8_t message_type = GetMessageType();
    switch (message_type) {
      case kKeyUpdateMessageType:
        contains_key_update = true;
        if (full_hs_message_read) {
          /* The last fragment read completes a key update message. We ensure
           * nothing follows the key update message and include the key update
           * type in the returned result. */
          if (at_byte < plaintext_len) {
            return absl::Status(
                absl::StatusCode::kInternal,
                "Key update should be the last message in a plaintext.");
          }
          uint8_t key_update_type = GetKeyUpdateType();
          message_fragments_->clear();
          Result result = {ExpectingToReadMoreBytes(), contains_key_update,
                           key_update_type, contains_ticket,
                           num_full_tickets_in_store_};
          return result;
        }
        break;
      case kSessionTicketMessageType:
        contains_ticket = true;
        if (full_hs_message_read) {
          /* The last fragment read completes a session ticket message. We
           * store the ticket if tickets have not be retrieved already and the
           * limit on number of tickets has not been reached. */
          if (!IgnoreFutureTickets()) {
            AddTicketToStore();
          }
          message_fragments_->clear();
        }
        break;
      default:
        return absl::Status(absl::StatusCode::kInternal,
                            "Unexpected handshake message type.");
    }
  }
  Result result = {ExpectingToReadMoreBytes(), contains_key_update,
                   kInvalidKeyUpdateType, contains_ticket,
                   num_full_tickets_in_store_};
  return result;
}

absl::variant<absl::Status,
              std::unique_ptr<std::vector<std::unique_ptr<Message>>>>
HandshakeMessageHandler::GetStoredTickets() {
  if (tickets_retrieved_) {
    return absl::Status(absl::StatusCode::kInternal,
                        "|GetStoredTickets| should not be called after "
                        "tickets have been retrieved.");
  }
  if (ExpectingToReadMoreBytes() && GetMessageType() == 0x04) {
    return absl::Status(absl::StatusCode::kInternal,
                        "|GetStoredTickets| should not be called while "
                        "waiting to read more ticket bytes.");
  }
  ABSL_ASSERT(full_tickets_ != nullptr);
  tickets_retrieved_ = true;
  num_full_tickets_in_store_ = 0;
  auto tickets = std::move(full_tickets_);
  full_tickets_ = nullptr;
  return std::move(tickets);
}

void HandshakeMessageHandler::StoreMessageFragment(const uint8_t* plaintext,
                                                   size_t at_byte,
                                                   size_t bytes_to_read) {
  ABSL_ASSERT(plaintext != nullptr);
  /* If the handshake message handler is ignoring future tickets, we do not need
   * to copy ticket data fragments into the internal buffer and can just ignore
   * them. We still copy the header bytes because we need to know how long the
   * ticket is. */
  if (IgnoreFutureTickets()) {
    if (state_ == State::READ_DATA &&
        GetMessageType() == kSessionTicketMessageType) {
      return;
    }
  }
  auto fragment = absl::make_unique<MessageFragment>(bytes_to_read);
  memcpy(fragment->data(), plaintext + at_byte, bytes_to_read);
  message_fragments_->push_back(std::move(fragment));
}

void HandshakeMessageHandler::AddTicketToStore() {
  ABSL_ASSERT(full_tickets_ != nullptr);
  full_tickets_->push_back(std::move(message_fragments_));
  num_full_tickets_in_store_++;
  message_fragments_ = absl::make_unique<Message>();
}

uint32_t HandshakeMessageHandler::GetMessageDataSizeFromHeader() {
  /* The message size is in the 2nd, 3rd and 4th bytes of the header.
   * For example, if a header contains the following 4 bytes: 04 00 00 B2,
   * then the size of the message data is 0x0000B2 (178 bytes.)
   *
   * The complexity of the code below is because headers might be framented. */
  uint32_t message_data_size = 0;
  std::size_t at_byte = 1;
  int shift_by = 16;
  for (const auto& fragment : *message_fragments_) {
    for (const auto& byte : *fragment) {
      /* Skip first byte which is the message type. */
      if (at_byte == 1) {
        at_byte++;
        continue;
      }
      message_data_size |= (static_cast<uint32_t>(byte) << shift_by);
      at_byte++;
      shift_by -= 8;
      if (at_byte > kTlsHandshakeHeaderLength) {
        break;
      }
    }
  }
  return message_data_size;
}

uint8_t HandshakeMessageHandler::GetMessageType() {
  /* The message type is the first byte of the first fragment. */
  Message* message = message_fragments_.get();
  ABSL_ASSERT(message != nullptr);
  MessageFragment* first_fragment = (*message)[0].get();
  ABSL_ASSERT(first_fragment != nullptr);
  return (*first_fragment)[0];
}

uint8_t HandshakeMessageHandler::GetKeyUpdateType() {
  int at_byte = 1;
  for (const auto& fragment : *message_fragments_) {
    for (const auto& byte : *fragment) {
      /* The 5th bytes contains the key update type. */
      if (at_byte == 5) {
        return byte;
      }
      at_byte++;
    }
  }
  return kInvalidKeyUpdateType;
}

bool HandshakeMessageHandler::ExpectingToReadMoreBytes() {
  return !message_fragments_->empty();
}

bool HandshakeMessageHandler::IgnoreFutureTickets() {
  return tickets_retrieved_ ||
         num_full_tickets_in_store_ >= kMaxNumTicketsToProcess;
}

}  //  namespace handshake_message_handler
}  //  namespace s2a
