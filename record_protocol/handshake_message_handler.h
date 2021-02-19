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

#ifndef RECORD_PROTOCOL_HANDSHAKE_MESSAGE_HANDLER_H_
#define RECORD_PROTOCOL_HANDSHAKE_MESSAGE_HANDLER_H_

#include <memory>
#include <vector>

#include "absl/status/status.h"
#include "absl/types/variant.h"

namespace s2a {
namespace handshake_message_handler {

/* Number of bytes in header of a handshake message. */
constexpr size_t kTlsHandshakeHeaderLength = 4;

/* Handshake message types. */
constexpr uint8_t kSessionTicketMessageType = 0x04;
constexpr uint8_t kKeyUpdateMessageType = 0x18;

/* Maximum number of tickets that will be processed. Tickets that arrive after
 * reaching the limit will be ignored. */
// TODO(matthewstevenson88): Make the limit on number of tickets configurable.
constexpr size_t kMaxNumTicketsToProcess = 5;

/** This class parses handshake messages received by the record protocol (which
 *  can be either key updates or session tickets). It locally buffers the
 *  session tickets received until the record protocol is ready to retrieve them
 *  and send them to the S2A handshaker service for processing.
 *
 *  This class is not thread-safe. **/
class HandshakeMessageHandler {
 public:
  using MessageFragment = std::vector<uint8_t>;
  using Message = std::vector<std::unique_ptr<MessageFragment>>;

  /* This struct is used to return the state of the handshake message handler
   * after |ProcessHandshakeMessage| executes. Both |contains_key_update| and
   * |contains_ticket| can be true since a single TLS record can contain both
   * key updates and session tickets. */
  struct Result {
    /* Set to true if waiting to read more bytes of a fragmented message.
     * If this field is true and the record protocol receives a non-handshake
     * type record, then the record protocol should return a protocol error. */
    bool expecting_to_read_more_bytes;

    /* Set to true if the handshake message that was just processed contained a
     * key update message (or fragments of it). */
    bool contains_key_update;
    /* Set to a valid value only if |contains_key_update| is true. Otherwise,
     * its value MUST be ignored. */
    uint8_t key_update_type;

    /* Set to true if the handshake message that was just processed contained a
     * session ticket (or fragments of it). */
    bool contains_ticket;
    /* Number of full tickets currently being stored internally by this
     * |HandshakeMessageHandler| instance. */
    size_t num_full_tickets_stored;
  };

  HandshakeMessageHandler();

  // Copy and copy-assigment of |HandshakeMessageHandler| are disallowed.
  HandshakeMessageHandler(const HandshakeMessageHandler&) = delete;
  HandshakeMessageHandler& operator=(const HandshakeMessageHandler&) = delete;

  ~HandshakeMessageHandler() = default;

  /** This method will be called when the record protocol receives a handshake
   *  message. The arguments are:
   *  - plaintext: a buffer containing the plaintext decrypted by the record
   *    protocol. The API does not take ownership of the buffer. |plaintext|
   *    must not be nullptr even if |plaintext_len| is zero.
   *  - plaintext_len: number of bytes to read from |plaintext|
   *
   * It returns a |Result| struct that contains the state of the handler
   * after processing the bytes in |plaintext|. It returns an error with the
   * appropriate status code if the processing failed. **/
  absl::variant<absl::Status, Result> ProcessHandshakeMessage(
      const uint8_t* plaintext, size_t plaintext_len);

  /** This method returns all stored complete tickets that are ready to be
   *  sent to the handshaker service.
   *
   *  It returns the tickets as a vector of tickets, where each ticket is a
   *  vector of ticket fragments. Before sending the tickets to the handshaker
   *  service, the caller needs to merge the ticket fragments.
   *
   *  It returns an error if called while the ticket handler is waiting to read
   *  more ticket bytes. Once this API returns successfully (the tickets are
   *  retrieved), a future call to the API will return an error. **/
  absl::variant<absl::Status,
                std::unique_ptr<std::vector<std::unique_ptr<Message>>>>
  GetStoredTickets();

 private:
  /** Reads |bytes_to_read| bytes from |plaintext| starting  the |at_byte|'th
   *  byte and stores a handshake message fragment. **/
  void StoreMessageFragment(const uint8_t* plaintext, size_t at_byte,
                            size_t bytes_to_read);

  /** Results true if waiting to read more bytes of a fragmented handhsake
   *  message. **/
  bool ExpectingToReadMoreBytes();

  /** This method is called after a full header is read to extract the
   *  handshake message data size from the header bytes. **/
  uint32_t GetMessageDataSizeFromHeader();

  /** Get the message type of the current handshake message being processed.
   * **/
  uint8_t GetMessageType();

  /** Get the key update type for a key update message. This method is only
   *  called once a full key update message has been read. **/
  uint8_t GetKeyUpdateType();

  /** This method is called after all fragments of a ticket are read. It
   *  will store the fragments in the ticket store. **/
  void AddTicketToStore();

  /** Returns true if tickets stored have already being retrieved or if the
   *  limit on the number of tickets this class will store is reached. **/
  bool IgnoreFutureTickets();

  /* Fragments of a handshake message (key update or ticket) currently being
   * processed. */
  std::unique_ptr<Message> message_fragments_;

  /* A vector of complete tickets. |full_tickets_| is |nullptr| iff
   * |tickets_retrieved_| is true. */
  std::unique_ptr<std::vector<std::unique_ptr<Message>>> full_tickets_;
  size_t num_full_tickets_in_store_ = 0;

  /* This flag is set to true once |GetStoredTickets| successfully returns. */
  bool tickets_retrieved_ = false;

  /* If |num_data_bytes_expecting_to_read_ > 0|, the handler is waiting to
   * read more data bytes of a fragmented message. */
  size_t num_data_bytes_expecting_to_read_ = 0;

  /* If |num_header_bytes_expecting_to_read_ < kTlsHandshakeHeaderLength|, the
   * handler is waiting to read more header bytes of a fragmented message. */
  size_t num_header_bytes_expecting_to_read_ = kTlsHandshakeHeaderLength;

  /* State that indicates whether the handler is going to read message header or
   * data next. It is initially set to read header bytes. */
  enum class State { READ_HEADER, READ_DATA };
  State state_ = State::READ_HEADER;
};

}  //  namespace handshake_message_handler
}  //  namespace s2a

#endif  // RECORD_PROTOCOL_HANDSHAKE_MESSAGE_HANDLER_H_
