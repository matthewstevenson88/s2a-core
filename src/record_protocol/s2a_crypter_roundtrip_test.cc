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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "include/s2a_constants.h"
#include "include/s2a_options.h"
#include "src/record_protocol/s2a_crypter.h"
#include "src/test_util/s2a_test_data.h"

namespace s2a {
namespace record_protocol {
namespace {

using ::absl::Status;
using Ciphersuite = s2a_options::S2AOptions::Ciphersuite;
using TlsVersion = s2a_options::S2AOptions::TlsVersion;
using RecordType = ::s2a::record_protocol::S2ACrypter::RecordType;
using S2ACrypterStatus = ::s2a::record_protocol::S2ACrypter::S2ACrypterStatus;
using S2ACrypterStatusCode =
    ::s2a::record_protocol::S2ACrypter::S2ACrypterStatusCode;

void NoOpLogger(const std::string& log_message) {}

struct KeyPair {
  Ciphersuite ciphersuite;
  const uint8_t* in_traffic_secret;
  const uint8_t* out_traffic_secret;
  size_t key_size;
};

// TODO(matthewstevenson88): generate test vectors for AES-256-GCM and
// CHACHA-POLY.

constexpr KeyPair aes_128_gcm_key_pair_1 = {
    Ciphersuite::AES_128_GCM_SHA256, s2a_test_data::aes_128_gcm_in_key_1,
    s2a_test_data::aes_128_gcm_out_key_1, kSha256DigestLength};
constexpr KeyPair aes_128_gcm_key_pair_2 = {
    Ciphersuite::AES_128_GCM_SHA256, s2a_test_data::aes_128_gcm_in_key_2,
    s2a_test_data::aes_128_gcm_out_key_2, kSha256DigestLength};
constexpr KeyPair aes_128_gcm_key_pair_3 = {
    Ciphersuite::AES_128_GCM_SHA256, s2a_test_data::aes_128_gcm_in_key_3,
    s2a_test_data::aes_128_gcm_out_key_3, kSha256DigestLength};
constexpr KeyPair aes_128_gcm_key_pair_4 = {
    Ciphersuite::AES_128_GCM_SHA256, s2a_test_data::aes_128_gcm_in_key_4,
    s2a_test_data::aes_128_gcm_out_key_4, kSha256DigestLength};

constexpr uint64_t kConnectionId = 1234;
constexpr char kHandshakerServiceUrl[] = "handshaker_service_url";
constexpr uint8_t kKeyUpdateMessage[] = {0x18, 0x00, 0x00, 0x01, 0x00};
constexpr size_t kKeyUpdateMessageLength = 5;
constexpr char kLocalIdentity[] = "local_identity";
constexpr size_t kTls13HeaderLength = 5;
constexpr size_t kTls13MaxPlaintextBytesPerRecord = 16384;

// A fake ticket sender and waiter functions.
bool FakeWaitOnTicketSender() { return true; }
typedef bool (*WaitOnTicketSender)();
WaitOnTicketSender FakeSendTicketsToS2A(
    s2a_ticket_sender::TicketSenderOptions& options) {
  return FakeWaitOnTicketSender;
}

class S2ACrypterRoundtripTest : public ::testing::TestWithParam<KeyPair> {
 protected:
  S2ACrypterRoundtripTest() {}

  void SetUp() override {
    // Convert the in and out traffic secrets to vectors.
    std::vector<uint8_t> in_traffic_secret(GetParam().key_size);
    std::vector<uint8_t> out_traffic_secret(GetParam().key_size);
    memcpy(in_traffic_secret.data(), GetParam().in_traffic_secret,
           in_traffic_secret.size());
    memcpy(out_traffic_secret.data(), GetParam().out_traffic_secret,
           out_traffic_secret.size());

    // Create the 2 |S2ACrypter|'s.
    absl::variant<Status, std::unique_ptr<S2ACrypter>> in_crypter_status =
        S2ACrypter::Create(
            TlsVersion::TLS1_3, GetParam().ciphersuite, kConnectionId,
            kHandshakerServiceUrl,
            s2a_options::S2AOptions::Identity::FromHostname(kLocalIdentity),
            in_traffic_secret, out_traffic_secret, /*in_sequence=*/0,
            /*out_sequence=*/0, FakeSendTicketsToS2A,
            /*channel_factory=*/nullptr,
            /*channel_options=*/nullptr, NoOpLogger);
    ASSERT_EQ(in_crypter_status.index(), 1);
    in_crypter_ = std::move(absl::get<1>(in_crypter_status));

    absl::variant<Status, std::unique_ptr<S2ACrypter>> out_crypter_status =
        S2ACrypter::Create(
            TlsVersion::TLS1_3, GetParam().ciphersuite, kConnectionId,
            kHandshakerServiceUrl,
            s2a_options::S2AOptions::Identity::FromHostname(kLocalIdentity),
            out_traffic_secret, in_traffic_secret, /*in_sequence=*/0,
            /*out_sequence=*/0, FakeSendTicketsToS2A,
            /*channel_factory=*/nullptr,
            /*channel_options=*/nullptr, NoOpLogger);
    ASSERT_EQ(out_crypter_status.index(), 1);
    out_crypter_ = std::move(absl::get<1>(out_crypter_status));
  }

  s2a_options::S2AOptions::Identity local_identity_ =
      s2a_options::S2AOptions::Identity::FromHostname(kLocalIdentity);
  std::unique_ptr<S2ACrypter> in_crypter_ = nullptr;
  std::unique_ptr<S2ACrypter> out_crypter_ = nullptr;
};

INSTANTIATE_TEST_CASE_P(S2ACrypterRoundtripTest, S2ACrypterRoundtripTest,
                        ::testing::Values(aes_128_gcm_key_pair_1,
                                          aes_128_gcm_key_pair_2,
                                          aes_128_gcm_key_pair_3,
                                          aes_128_gcm_key_pair_4));

void SendKeyUpdate(S2ACrypter& out_crypter, S2ACrypter& in_crypter) {
  // Write a key update message into a TLS record in |record|.
  std::vector<uint8_t> record(kKeyUpdateMessageLength +
                              out_crypter.RecordOverhead());
  S2ACrypterStatus status = out_crypter.Protect(
      RecordType::HANDSHAKE,
      {{const_cast<uint8_t*>(kKeyUpdateMessage), kKeyUpdateMessageLength}},
      {record.data(), record.size()});
  EXPECT_EQ(status.GetCode(), S2ACrypterStatusCode::OK)
      << "Error message: " << status.GetErrorMessage();
  EXPECT_EQ(status.GetBytesWritten(), record.size());

  // Update |out_crypter|'s outbound session keys.
  EXPECT_TRUE(out_crypter.UpdateOutboundKey().ok());

  // Decrypt the TLS record in |record|.
  std::vector<uint8_t> plaintext(record.size());
  status = in_crypter.Unprotect(
      {const_cast<uint8_t*>(record.data()), kTls13HeaderLength},
      {{const_cast<uint8_t*>(record.data()) + kTls13HeaderLength,
        record.size() - kTls13HeaderLength}},
      {plaintext.data(), plaintext.size()});
  EXPECT_EQ(status.GetCode(), S2ACrypterStatusCode::OK);
  EXPECT_EQ(status.GetErrorMessage(), "");
  EXPECT_EQ(status.GetBytesWritten(), 0);
}

void SendMessage(const uint8_t* message, size_t message_size,
                 S2ACrypter& out_crypter, S2ACrypter& in_crypter) {
  // Write |message| into a TLS record in |record|.
  std::vector<uint8_t> record(message_size + out_crypter.RecordOverhead());
  S2ACrypterStatus status =
      out_crypter.Protect(RecordType::APPLICATION_DATA,
                          {{const_cast<uint8_t*>(message), message_size}},
                          {record.data(), record.size()});
  EXPECT_EQ(status.GetCode(), S2ACrypterStatusCode::OK)
      << "Error message: " << status.GetErrorMessage();
  EXPECT_EQ(status.GetBytesWritten(), record.size());

  // Decrypt the TLS record in |record|.
  std::vector<uint8_t> plaintext(record.size());
  status = in_crypter.Unprotect({record.data(), kTls13HeaderLength},
                                {{record.data() + kTls13HeaderLength,
                                  record.size() - kTls13HeaderLength}},
                                {plaintext.data(), plaintext.size()});
  EXPECT_EQ(status.GetCode(), S2ACrypterStatusCode::OK);
  EXPECT_EQ(status.GetErrorMessage(), "");
  EXPECT_EQ(status.GetBytesWritten(), message_size);
  plaintext.resize(message_size);

  // Check the output.
  if (message_size > 0) {
    std::vector<uint8_t> correct_message(message_size);
    memcpy(correct_message.data(), message, message_size);
    EXPECT_EQ(correct_message, plaintext);
  } else {
    EXPECT_TRUE(plaintext.empty());
  }
}

TEST_P(S2ACrypterRoundtripTest, Conversation) {
  SendMessage(s2a_test_data::test_message_1, s2a_test_data::test_message_1_size,
              *in_crypter_, *out_crypter_);
  SendMessage(s2a_test_data::test_message_2, s2a_test_data::test_message_2_size,
              *out_crypter_, *in_crypter_);
  SendMessage(s2a_test_data::test_message_3, s2a_test_data::test_message_3_size,
              *in_crypter_, *out_crypter_);
  std::vector<uint8_t> test_message_4(1500, 'm');
  SendMessage(test_message_4.data(), test_message_4.size(), *out_crypter_,
              *in_crypter_);
  std::vector<uint8_t> test_message_5(kTls13MaxPlaintextBytesPerRecord, 's');
  SendMessage(test_message_5.data(), test_message_5.size(), *in_crypter_,
              *out_crypter_);
}

TEST_P(S2ACrypterRoundtripTest, ConversationWithKeyUpdate) {
  // Exchange messages.
  SendMessage(s2a_test_data::test_message_1, s2a_test_data::test_message_1_size,
              *in_crypter_, *out_crypter_);
  SendMessage(s2a_test_data::test_message_2, s2a_test_data::test_message_2_size,
              *out_crypter_, *in_crypter_);

  // Send a key update message from |out_crypter_| to |in_crypter_|.
  SendKeyUpdate(*out_crypter_, *in_crypter_);

  // Do another exchange of messages using the new keys.
  SendMessage(s2a_test_data::test_message_3, s2a_test_data::test_message_3_size,
              *out_crypter_, *in_crypter_);
  std::vector<uint8_t> test_message_4(1500, 'm');
  SendMessage(test_message_4.data(), test_message_4.size(), *out_crypter_,
              *in_crypter_);
  std::vector<uint8_t> test_message_5(kTls13MaxPlaintextBytesPerRecord, 's');
  SendMessage(test_message_5.data(), test_message_5.size(), *in_crypter_,
              *out_crypter_);

  // Send a key update message from |in_crypter_| to |out_crypter_|.
  SendKeyUpdate(*in_crypter_, *out_crypter_);

  // Do another exchange of messages using the new keys.
  SendMessage(s2a_test_data::test_message_3, s2a_test_data::test_message_3_size,
              *in_crypter_, *out_crypter_);
  SendMessage(test_message_4.data(), test_message_4.size(), *in_crypter_,
              *out_crypter_);
  SendMessage(test_message_5.data(), test_message_5.size(), *out_crypter_,
              *in_crypter_);
}

}  // namespace
}  // namespace record_protocol
}  // namespace s2a
