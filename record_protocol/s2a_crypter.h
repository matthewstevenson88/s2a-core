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

#ifndef RECORD_PROTOCOL_S2A_CRYPTER_H_
#define RECORD_PROTOCOL_S2A_CRYPTER_H_

#include <cstdint>
#include <string>

#include "channel/s2a_channel_factory_interface.h"
#include "crypto/s2a_aead_constants.h"
#include "options/s2a_options.h"
#include "record_protocol/handshake_message_handler.h"
#include "record_protocol/s2a_half_connection.h"
#include "record_protocol/s2a_ticket_sender.h"
#include "s2a_constants.h"
#include "absl/synchronization/mutex.h"
#include "absl/types/variant.h"

namespace s2a {
namespace record_protocol {

// |S2ACrypter| implements the TLS 1.3 record protocol that is used by the S2A's
// client libraries. It supports the AES-128-GCM-SHA256, AES-256-GCM-SHA384, and
// CHACHA20-POLY1305-SHA256 ciphersuites.
class S2ACrypter {
 public:
  enum class RecordType {
    APPLICATION_DATA,
    ALERT,
    HANDSHAKE,
  };

  enum class S2ACrypterStatusCode {
    OK,
    INCOMPLETE_RECORD,      // No complete record found.
    INVALID_ARGUMENT,       // The argument to some API is invalid.
    INVALID_RECORD,         // The record does not meet the TLS 1.3 format.
    RENEGOTIATION_ATTEMPT,  // The peer attempted to renegotiate the handshake.
    ALERT_CLOSE_NOTIFY,     // The record was a close-notify alert record.
    ALERT_RECORD_OVERFLOW,  // The record size is too large.
    ALERT_OTHER,     // The record was an alert record other than close-notify.
    INTERNAL_ERROR,  // An unexpected error occurred during decryption.
    FAILED_PRECONDITION,  // A requirement for calling a method was not met.
    END_OF_DATA,          // A close notify altert has already been received.
    UNIMPLEMENTED,        // An unimplemented operation was called.
    UNKNOWN,              // An unknown error occurred.
  };

  class S2ACrypterStatus {
   public:
    S2ACrypterStatus(S2ACrypterStatusCode code,
                     const std::string& error_message, size_t bytes_written);

    S2ACrypterStatusCode GetCode() const;
    std::string GetErrorMessage() const;
    size_t GetBytesWritten() const;

   private:
    S2ACrypterStatusCode code_;
    std::string error_message_;
    size_t bytes_written_ = 0;
  };

  static absl::variant<absl::Status, std::unique_ptr<S2ACrypter>> Create(
      s2a_options::S2AOptions::TlsVersion tls_version,
      s2a_options::S2AOptions::Ciphersuite ciphersuite, uint64_t connection_id,
      const std::string& handshaker_service_url,
      const s2a_options::S2AOptions::Identity local_identity,
      const std::vector<uint8_t>& in_traffic_secret,
      const std::vector<uint8_t>& out_traffic_secret, uint64_t in_sequence,
      uint64_t out_sequence,
      s2a_ticket_sender::TicketSender ticket_sender_function,
      std::unique_ptr<s2a_channel::S2AChannelFactoryInterface> channel_factory,
      std::unique_ptr<
          s2a_channel::S2AChannelFactoryInterface::S2AChannelOptionsInterface>
          channel_options,
      std::function<void(const std::string&)> logger);

  ~S2ACrypter();

  // |Protect| writes a TLS 1.3 record (of type |record_type|) to |record| whose
  // payload consists of the ciphertext obtained by encrypting |plaintext|.
  //
  // The total length of |plaintext| must be <= 2^14 bytes. The length of
  // |record| must be at least the total length of |plaintext| plus
  // |RecordOverhead()|.
  S2ACrypterStatus Protect(RecordType record_type,
                           const std::vector<aead_crypter::Iovec>& plaintext,
                           const aead_crypter::Iovec& record);

  // |Unprotect| parses a TLS 1.3 record that is broken up into |header| and
  // |payload|, decrypts the ciphertext, and writes any application data that
  // results to |plaintext|.
  S2ACrypterStatus Unprotect(const aead_crypter::Iovec& header,
                             const std::vector<aead_crypter::Iovec>& payload,
                             const aead_crypter::Iovec& plaintext);

  // |RecordOverhead| returns the number of overhead bytes of a TLS 1.3 record,
  // i.e. bytes other than ciphertext.
  size_t RecordOverhead() const;

  // |UpdateOutboundKey| updates the session key in the outbound direction. This
  // should be called only when sending a key update message to the peer.
  absl::Status UpdateOutboundKey();

 private:
  S2ACrypter(
      const uint64_t connection_id, const std::string& handshaker_service_url,
      const s2a_options::S2AOptions::Identity local_identity,
      std::unique_ptr<record_protocol::S2AHalfConnection> in_connection,
      std::unique_ptr<record_protocol::S2AHalfConnection> out_connection,
      s2a_ticket_sender::TicketSender ticket_sender_function,
      std::unique_ptr<s2a_channel::S2AChannelFactoryInterface> channel_factory,
      std::unique_ptr<
          s2a_channel::S2AChannelFactoryInterface::S2AChannelOptionsInterface>
          channel_options,
      std::function<void(const std::string&)> logger);

  // |HandleProcessHandshakeMessageResult| modifies the state of this
  // |S2ACrypter| based on the most recent complete handshake message received
  // from the peer.
  absl::Status HandleProcessHandshakeMessageResult(
      absl::variant<absl::Status,
                    handshake_message_handler::HandshakeMessageHandler::Result>
          result_or_status);

  // |RetrieveStoredTicketsAndSendToS2A| retrieves any session tickets stored in
  // the |handshake_message_handler_| and sends them to the S2A.
  void RetrieveStoredTicketsAndSendToS2A();

  const uint64_t connection_id_;
  const std::string handshaker_service_url_;
  const s2a_options::S2AOptions::Identity local_identity_;
  const std::function<void(const std::string&)> logger_;

  std::unique_ptr<record_protocol::S2AHalfConnection> in_connection_;
  std::unique_ptr<record_protocol::S2AHalfConnection> out_connection_;

  // If a close notify alert is received, then |close_notify_received_| is set
  // to true and the |S2ACrypter| will no longer unprotect any TLS records.
  bool close_notify_received_ = false;

  enum class TicketHandlingPhase { NOT_RECEIVED, RECEIVING, DONE };
  struct HandshakeMessageHandlingState {
    TicketHandlingPhase phase = TicketHandlingPhase::NOT_RECEIVED;
    bool expecting_to_read_more_bytes = false;
  };

  // Handles handshake messages (i.e. session tickets and key updates) received
  // by the record protocol.
  std::unique_ptr<handshake_message_handler::HandshakeMessageHandler>
      handshake_message_handler_;
  // Indicates whether the record protocol has not received, is in the process
  // of receiving, or is done receiving session tickets from the peer.
  std::unique_ptr<HandshakeMessageHandlingState> hs_message_handling_state_;

  // Factory for creating a channel to S2A that can be used to send session
  // tickets.
  std::unique_ptr<s2a_channel::S2AChannelFactoryInterface> channel_factory_;
  std::unique_ptr<
      s2a_channel::S2AChannelFactoryInterface::S2AChannelOptionsInterface>
      channel_options_;

  // Sends any stored session tickets to the S2A.
  s2a_ticket_sender::TicketSender ticket_sender_function_ = nullptr;
  // Must be called to ensure a pending RPC call to S2A completes before this
  // |S2ACrypter| is destroyed.
  s2a_ticket_sender::WaitOnTicketSender wait_on_ticket_sender_function_ =
      nullptr;
};

}  // namespace record_protocol
}  // namespace s2a

#endif  //  RECORD_PROTOCOL_S2A_CRYPTER_H_
