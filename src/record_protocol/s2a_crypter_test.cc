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

#include "src/record_protocol/s2a_crypter.h"

#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "include/s2a_constants.h"
#include "include/s2a_options.h"
#include "src/record_protocol/handshake_message_handler.h"
#include "src/record_protocol/s2a_crypter_util.h"
#include "src/record_protocol/s2a_ticket_sender.h"
#include "src/test_util/s2a_test_data.h"
#include "src/test_util/s2a_test_util.h"

namespace s2a {
namespace record_protocol {
namespace {

using ::absl::Status;
using ::absl::StatusCode;
using ::s2a::record_protocol::S2ACrypter;
using ::s2a::test_util::StatusIs;
using Ciphersuite = s2a_options::S2AOptions::Ciphersuite;
using Identity = s2a_options::S2AOptions::Identity;
using IdentityType = s2a_options::S2AOptions::IdentityType;
using TlsVersion = s2a_options::S2AOptions::TlsVersion;
using RecordType = ::s2a::record_protocol::S2ACrypter::RecordType;
using S2ACrypterStatus = ::s2a::record_protocol::S2ACrypter::S2ACrypterStatus;
using S2ACrypterStatusCode =
    ::s2a::record_protocol::S2ACrypter::S2ACrypterStatusCode;

constexpr size_t kConnectionId = 1234;
constexpr char kS2AHandshakerServiceUrl[] = "s2a_handshaker_service_url";
constexpr size_t kTagLength = 16;
constexpr size_t kTls13HeaderLength = 5;
constexpr size_t kTls13MaxPlaintextBytesPerRecord = 16384;

constexpr char kTestLocalIdentity[] = "test_local_identity";
constexpr uint64_t kTestConnectionId = 1234;
constexpr uint8_t kTestResumptionTicket[] = {0x04, 0x00, 0x00, 0x01, 0x00};

void NoOpLogger(const std::string& log_message) {}

// A fake function the crypter will call to check if the ticket sender is done.
bool send_ticket_done = false;
bool FakeWaitOnTicketSender() {
  send_ticket_done = true;
  return true;
}

typedef bool (*WaitOnTicketSender)();

// A fake ticket sender function that just verifies the arguments passed.
size_t num_tickets_to_send = 0;
bool send_ticket_started = false;
WaitOnTicketSender FakeSendTicketsToS2A(
    s2a_ticket_sender::TicketSenderOptions& options) {
  send_ticket_started = true;

  EXPECT_EQ(options.handshaker_service_url, kS2AHandshakerServiceUrl);
  EXPECT_TRUE(options.connection_id == kTestConnectionId);
  s2a_options::S2AOptions::Identity test_identity =
      s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity);
  EXPECT_EQ(options.local_identity, test_identity);
  EXPECT_EQ(options.tickets->size(), num_tickets_to_send);
  for (auto& ticket : *options.tickets) {
    EXPECT_STREQ((*ticket).c_str(),
                 reinterpret_cast<const char*>(kTestResumptionTicket));
  }
  return FakeWaitOnTicketSender;
}

size_t CiphersuiteToHashLength(Ciphersuite ciphersuite) {
  switch (ciphersuite) {
    case Ciphersuite::AES_128_GCM_SHA256:
    case Ciphersuite::CHACHA20_POLY1305_SHA256:
      return kSha256DigestLength;
    case Ciphersuite::AES_256_GCM_SHA384:
      return kSha384DigestLength;
    default:  // Ciphersuite is unsupported.
      return 0;
  }
}

struct TestTlsRecord {
  const uint8_t* record;
  size_t record_size;
};

TestTlsRecord GetTestTlsRecord(Ciphersuite ciphersuite, uint16_t sequence) {
  switch (ciphersuite) {
    case Ciphersuite::AES_128_GCM_SHA256:
      switch (sequence) {
        case 0:
          return {s2a_test_data::aes_128_gcm_record_one_bytes,
                  s2a_test_data::aes_128_gcm_record_one_bytes_size};
        case 1:
          return {s2a_test_data::aes_128_gcm_record_two_bytes,
                  s2a_test_data::aes_128_gcm_record_two_bytes_size};
        case 2:
          return {s2a_test_data::aes_128_gcm_record_three_bytes,
                  s2a_test_data::aes_128_gcm_record_three_bytes_size};
        default:
          return {nullptr, 0};
      }
    case Ciphersuite::AES_256_GCM_SHA384:
      switch (sequence) {
        case 0:
          return {s2a_test_data::aes_256_gcm_record_one_bytes,
                  s2a_test_data::aes_256_gcm_record_one_bytes_size};
        case 1:
          return {s2a_test_data::aes_256_gcm_record_two_bytes,
                  s2a_test_data::aes_256_gcm_record_two_bytes_size};
        case 2:
          return {s2a_test_data::aes_256_gcm_record_three_bytes,
                  s2a_test_data::aes_256_gcm_record_three_bytes_size};
        default:
          return {nullptr, 0};
      }
    case Ciphersuite::CHACHA20_POLY1305_SHA256:
      switch (sequence) {
        case 0:
          return {s2a_test_data::chacha_poly_record_one_bytes,
                  s2a_test_data::chacha_poly_record_one_bytes_size};
        case 1:
          return {s2a_test_data::chacha_poly_record_two_bytes,
                  s2a_test_data::chacha_poly_record_two_bytes_size};
        case 2:
          return {s2a_test_data::chacha_poly_record_three_bytes,
                  s2a_test_data::chacha_poly_record_three_bytes_size};
        default:
          return {nullptr, 0};
      }
    default:
      return {nullptr, 0};
  }
}

TestTlsRecord GetTestTlsRecordWithPadding(Ciphersuite ciphersuite) {
  switch (ciphersuite) {
    case Ciphersuite::AES_128_GCM_SHA256:
      return {s2a_test_data::aes_128_gcm_padded_zeros_record,
              s2a_test_data::aes_128_gcm_padded_zeros_record_size};
    case Ciphersuite::AES_256_GCM_SHA384:
      return {s2a_test_data::aes_256_gcm_padded_zeros_record,
              s2a_test_data::aes_256_gcm_padded_zeros_record_size};
    case Ciphersuite::CHACHA20_POLY1305_SHA256:
      return {s2a_test_data::chacha_poly_padded_zeros_record,
              s2a_test_data::chacha_poly_padded_zeros_record_size};
    default:
      return {nullptr, 0};
  }
}

TestTlsRecord GetTestTlsAlertRecord(Ciphersuite ciphersuite, bool close_notify,
                                    bool close_notify_with_padding,
                                    bool other_alert, bool small_alert) {
  if (close_notify) {
    switch (ciphersuite) {
      case Ciphersuite::AES_128_GCM_SHA256:
        return {s2a_test_data::aes_128_gcm_decrypt_close_notify,
                s2a_test_data::aes_128_gcm_decrypt_close_notify_size};
      case Ciphersuite::AES_256_GCM_SHA384:
        return {s2a_test_data::aes_256_gcm_decrypt_close_notify,
                s2a_test_data::aes_256_gcm_decrypt_close_notify_size};
      case Ciphersuite::CHACHA20_POLY1305_SHA256:
        return {s2a_test_data::chacha_poly_decrypt_close_notify,
                s2a_test_data::chacha_poly_decrypt_close_notify_size};
      default:
        break;
    }
  }
  if (close_notify_with_padding) {
    switch (ciphersuite) {
      case Ciphersuite::AES_128_GCM_SHA256:
        return {s2a_test_data::aes_128_gcm_alert_with_padding,
                s2a_test_data::aes_128_gcm_alert_with_padding_size};
      case Ciphersuite::AES_256_GCM_SHA384:
        return {s2a_test_data::aes_256_gcm_alert_with_padding,
                s2a_test_data::aes_256_gcm_alert_with_padding_size};
      case Ciphersuite::CHACHA20_POLY1305_SHA256:
        return {s2a_test_data::chacha_poly_alert_with_padding,
                s2a_test_data::chacha_poly_alert_with_padding_size};
      default:
        break;
    }
  }
  if (other_alert) {
    switch (ciphersuite) {
      case Ciphersuite::AES_128_GCM_SHA256:
        return {s2a_test_data::aes_128_gcm_decrypt_alert_other,
                s2a_test_data::aes_128_gcm_decrypt_alert_other_size};
      case Ciphersuite::AES_256_GCM_SHA384:
        return {s2a_test_data::aes_256_gcm_decrypt_alert_other,
                s2a_test_data::aes_256_gcm_decrypt_alert_other_size};
      case Ciphersuite::CHACHA20_POLY1305_SHA256:
        return {s2a_test_data::chacha_poly_decrypt_alert_other,
                s2a_test_data::chacha_poly_decrypt_alert_other_size};
      default:
        break;
    }
  }
  if (small_alert) {
    switch (ciphersuite) {
      case Ciphersuite::AES_128_GCM_SHA256:
        return {s2a_test_data::aes_128_gcm_decrypt_alert_small,
                s2a_test_data::aes_128_gcm_decrypt_alert_small_size};
      case Ciphersuite::AES_256_GCM_SHA384:
        return {s2a_test_data::aes_256_gcm_decrypt_alert_small,
                s2a_test_data::aes_256_gcm_decrypt_alert_small_size};
      case Ciphersuite::CHACHA20_POLY1305_SHA256:
        return {s2a_test_data::chacha_poly_decrypt_alert_small,
                s2a_test_data::chacha_poly_decrypt_alert_small_size};
      default:
        break;
    }
  }
  return {nullptr, 0};
}

TestTlsRecord GetTestTlsAdvancedRecord(Ciphersuite ciphersuite) {
  switch (ciphersuite) {
    case Ciphersuite::AES_128_GCM_SHA256:
      return {s2a_test_data::aes_128_gcm_advanced_record,
              s2a_test_data::aes_128_gcm_advanced_record_size};
    case Ciphersuite::AES_256_GCM_SHA384:
      return {s2a_test_data::aes_256_gcm_advanced_record,
              s2a_test_data::aes_256_gcm_advanced_record_size};
    case Ciphersuite::CHACHA20_POLY1305_SHA256:
      return {s2a_test_data::chacha_poly_advanced_record,
              s2a_test_data::chacha_poly_advanced_record_size};
    default:
      return {nullptr, 0};
  }
}

TestTlsRecord GetTestTlsKeyUpdateWithPaddingRecord(Ciphersuite ciphersuite) {
  switch (ciphersuite) {
    case Ciphersuite::AES_128_GCM_SHA256:
      return {s2a_test_data::aes_128_gcm_key_update_with_padding,
              s2a_test_data::aes_128_gcm_key_update_with_padding_size};
    case Ciphersuite::AES_256_GCM_SHA384:
      return {s2a_test_data::aes_256_gcm_key_update_with_padding,
              s2a_test_data::aes_256_gcm_key_update_with_padding_size};
    case Ciphersuite::CHACHA20_POLY1305_SHA256:
      return {s2a_test_data::chacha_poly_key_update_with_padding,
              s2a_test_data::chacha_poly_key_update_with_padding_size};
    default:
      return {nullptr, 0};
  }
}

class S2ACrypterTest : public ::testing::TestWithParam<Ciphersuite> {
 protected:
  S2ACrypterTest() {}

  void SetUp() override {
    std::vector<uint8_t> traffic_secret(CiphersuiteToHashLength(GetParam()),
                                        0x6b);
    traffic_secret_ = traffic_secret;
  }

  // Tests that decrypting a record that contains a single ticket succeeds. If
  // |partial| is true, the record will contain an incomplete fragment of a
  // ticket and nothing else in the record. */
  void TestDecryptSingleSessionTicketSuccess(S2ACrypter& crypter,
                                             bool partial) {
    size_t ticket_len = partial ? sizeof(kTestResumptionTicket) - 1
                                : sizeof(kTestResumptionTicket);

    // Write a session ticket into a TLS record.
    std::vector<uint8_t> plaintext_session_ticket(
        kTestResumptionTicket, kTestResumptionTicket + ticket_len);
    std::vector<uint8_t> tls_record(plaintext_session_ticket.size() +
                                        kTls13HeaderLength + /*record type=*/1 +
                                        kTagLength,
                                    0);
    S2ACrypterStatus status = crypter.Protect(
        RecordType::HANDSHAKE,
        {{plaintext_session_ticket.data(), plaintext_session_ticket.size()}},
        {tls_record.data(), tls_record.size()});
    EXPECT_EQ(status.GetCode(), S2ACrypterStatusCode::OK);
    EXPECT_EQ(status.GetErrorMessage(), "");
    EXPECT_EQ(status.GetBytesWritten(), tls_record.size());

    // Decrypt a session ticket from a TLS record.
    std::vector<uint8_t> decrypted_session_ticket(1000, 0);
    status = crypter.Unprotect(
        {tls_record.data(), kTls13HeaderLength},
        {{tls_record.data() + kTls13HeaderLength,
          tls_record.size() - kTls13HeaderLength}},
        {decrypted_session_ticket.data(), decrypted_session_ticket.size()});
    EXPECT_EQ(status.GetCode(), S2ACrypterStatusCode::OK);
    EXPECT_EQ(status.GetErrorMessage(), "");
    EXPECT_EQ(status.GetBytesWritten(), 0);
  }

  // Decrypts a single record with application data and checks the status.
  void TestDecryptApplicationData(S2ACrypter& crypter,
                                  S2ACrypterStatusCode code) {
    // Write application data into a TLS record.
    std::vector<uint8_t> application_data = {0x00, 0x00, 0x00, 0x00};
    std::vector<uint8_t> tls_record(application_data.size() +
                                        kTls13HeaderLength + /*record type=*/1 +
                                        kTagLength,
                                    0);
    S2ACrypterStatus status =
        crypter.Protect(RecordType::APPLICATION_DATA,
                        {{application_data.data(), application_data.size()}},
                        {tls_record.data(), tls_record.size()});
    EXPECT_EQ(status.GetCode(), S2ACrypterStatusCode::OK);
    EXPECT_EQ(status.GetErrorMessage(), "");
    EXPECT_EQ(status.GetBytesWritten(), tls_record.size());

    std::vector<uint8_t> decrypted_application_data(1000, 0);
    status = crypter.Unprotect(
        {tls_record.data(), kTls13HeaderLength},
        {{tls_record.data() + kTls13HeaderLength,
          tls_record.size() - kTls13HeaderLength}},
        {decrypted_application_data.data(), decrypted_application_data.size()});
    EXPECT_EQ(status.GetCode(), code);
    EXPECT_EQ(status.GetBytesWritten(),
              code == S2ACrypterStatusCode::OK ? application_data.size() : 0);
  }

  std::string handshaker_service_url_ = kS2AHandshakerServiceUrl;
  std::vector<uint8_t> traffic_secret_;
};

INSTANTIATE_TEST_CASE_P(
    S2ACrypterTest, S2ACrypterTest,
    ::testing::Values(Ciphersuite::AES_128_GCM_SHA256,
                      Ciphersuite::AES_256_GCM_SHA384,
                      Ciphersuite::CHACHA20_POLY1305_SHA256));

TEST_P(S2ACrypterTest, CreateFailsBecauseEmptyHandshakerServiceUrl) {
  absl::variant<Status, std::unique_ptr<S2ACrypter>> crypter_status =
      S2ACrypter::Create(
          TlsVersion::TLS1_3, GetParam(), kConnectionId,
          /*handshaker_service_url=*/"",
          s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity),
          traffic_secret_, traffic_secret_, /*in_sequence=*/0,
          /*out_sequence=*/0, FakeSendTicketsToS2A,
          /*channel_factory=*/nullptr,
          /*channel_options=*/nullptr, NoOpLogger);
  ASSERT_EQ(crypter_status.index(), 0);
  EXPECT_THAT(absl::get<0>(crypter_status),
              StatusIs(StatusCode::kInvalidArgument,
                       "|handshaker_service_url| is empty."));
}

TEST_P(S2ACrypterTest, CreateFailsBecauseNullptrTicketSenderFunction) {
  absl::variant<Status, std::unique_ptr<S2ACrypter>> crypter_status =
      S2ACrypter::Create(
          TlsVersion::TLS1_3, GetParam(), kConnectionId,
          handshaker_service_url_,
          s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity),
          traffic_secret_, traffic_secret_, /*in_sequence=*/0,
          /*out_sequence=*/0, /*ticket_sender_function=*/nullptr,
          /*channel_factory=*/nullptr, /*channel_options=*/nullptr, NoOpLogger);
  ASSERT_EQ(crypter_status.index(), 0);
  EXPECT_THAT(absl::get<0>(crypter_status),
              StatusIs(StatusCode::kInvalidArgument,
                       "|ticket_sender_function| must not be nullptr."));
}

TEST_P(S2ACrypterTest, CreateFailsBecauseTLS12) {
  absl::variant<Status, std::unique_ptr<S2ACrypter>> crypter_status =
      S2ACrypter::Create(
          TlsVersion::TLS1_2, GetParam(), kConnectionId,
          handshaker_service_url_,
          s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity),
          traffic_secret_, traffic_secret_, /*in_sequence=*/0,
          /*out_sequence=*/0, FakeSendTicketsToS2A, /*channel_factory=*/nullptr,
          /*channel_options=*/nullptr, NoOpLogger);
  ASSERT_EQ(crypter_status.index(), 0);
  EXPECT_THAT(absl::get<0>(crypter_status),
              StatusIs(StatusCode::kInvalidArgument,
                       "TLS 1.3 is the only supported TLS version."));
}

TEST_P(S2ACrypterTest, CreateSuccess) {
  absl::variant<Status, std::unique_ptr<S2ACrypter>> crypter_status =
      S2ACrypter::Create(
          TlsVersion::TLS1_3, GetParam(), kConnectionId,
          handshaker_service_url_,
          s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity),
          traffic_secret_, traffic_secret_, /*in_sequence=*/0,
          /*out_sequence=*/0, FakeSendTicketsToS2A, /*channel_factory=*/nullptr,
          /*channel_options=*/nullptr, NoOpLogger);
  ASSERT_EQ(crypter_status.index(), 1);
  EXPECT_NE(absl::get<1>(crypter_status), nullptr);
}

TEST_P(S2ACrypterTest, ProtectFailsBecausePlaintextIsTooLarge) {
  // Create the |S2ACrypter|.
  absl::variant<Status, std::unique_ptr<S2ACrypter>> crypter_status =
      S2ACrypter::Create(
          TlsVersion::TLS1_3, GetParam(), kConnectionId,
          handshaker_service_url_,
          s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity),
          traffic_secret_, traffic_secret_, /*in_sequence=*/0,
          /*out_sequence=*/0, FakeSendTicketsToS2A, /*channel_factory=*/nullptr,
          /*channel_options=*/nullptr, NoOpLogger);
  ASSERT_EQ(crypter_status.index(), 1);
  std::unique_ptr<S2ACrypter> crypter = std::move(absl::get<1>(crypter_status));

  // Try to write more than 2^14 bytes of plaintext. Note that 2^14 = 16384.
  std::vector<uint8_t> plaintext(16385);
  std::vector<uint8_t> record(plaintext.size() + crypter->RecordOverhead());
  S2ACrypterStatus status = crypter->Protect(
      RecordType::APPLICATION_DATA, {{plaintext.data(), plaintext.size()}},
      {record.data(), record.size()});
  EXPECT_EQ(status.GetCode(), S2ACrypterStatusCode::FAILED_PRECONDITION);
  EXPECT_EQ(status.GetErrorMessage(),
            "|plaintext| contains more bytes than are allowed in a single TLS "
            "1.3 record.");
  EXPECT_EQ(status.GetBytesWritten(), 0);
}

TEST_P(S2ACrypterTest, ProtectFailsBecauseRecordIsTooSmall) {
  // Create the |S2ACrypter|.
  absl::variant<Status, std::unique_ptr<S2ACrypter>> crypter_status =
      S2ACrypter::Create(
          TlsVersion::TLS1_3, GetParam(), kConnectionId,
          handshaker_service_url_,
          s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity),
          traffic_secret_, traffic_secret_, /*in_sequence=*/0,
          /*out_sequence=*/0, FakeSendTicketsToS2A, /*channel_factory=*/nullptr,
          /*channel_options=*/nullptr, NoOpLogger);
  ASSERT_EQ(crypter_status.index(), 1);
  std::unique_ptr<S2ACrypter> crypter = std::move(absl::get<1>(crypter_status));

  // Try to write a TLS record to |record|, but it is too small relative to
  // the size of |plaintext|.
  std::vector<uint8_t> plaintext(10);
  std::vector<uint8_t> record(plaintext.size() + crypter->RecordOverhead() - 1);
  S2ACrypterStatus status = crypter->Protect(
      RecordType::APPLICATION_DATA, {{plaintext.data(), plaintext.size()}},
      {record.data(), record.size()});
  EXPECT_EQ(status.GetCode(), S2ACrypterStatusCode::FAILED_PRECONDITION);
  EXPECT_EQ(status.GetErrorMessage(),
            "|record| is not large enough to hold the TLS 1.3 record built "
            "from |plaintext|.");
  EXPECT_EQ(status.GetBytesWritten(), 0);
}

TEST_P(S2ACrypterTest, ProtectFailsBecauseUnrecognizedRecordType) {
  // Create the |S2ACrypter|.
  absl::variant<Status, std::unique_ptr<S2ACrypter>> crypter_status =
      S2ACrypter::Create(
          TlsVersion::TLS1_3, GetParam(), kConnectionId,
          handshaker_service_url_,
          s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity),
          traffic_secret_, traffic_secret_, /*in_sequence=*/0,
          /*out_sequence=*/0, FakeSendTicketsToS2A, /*channel_factory=*/nullptr,
          /*channel_options=*/nullptr, NoOpLogger);
  ASSERT_EQ(crypter_status.index(), 1);
  std::unique_ptr<S2ACrypter> crypter = std::move(absl::get<1>(crypter_status));

  // Try to write the TLS record to |record|, but it fails because record type
  // is unrecognized.
  std::vector<uint8_t> plaintext;
  std::vector<uint8_t> record(crypter->RecordOverhead());
  S2ACrypterStatus status = crypter->Protect(
      static_cast<RecordType>(4), {{plaintext.data(), plaintext.size()}},
      {record.data(), record.size()});
  EXPECT_EQ(status.GetCode(), S2ACrypterStatusCode::FAILED_PRECONDITION);
  EXPECT_EQ(status.GetErrorMessage(), "Unrecognized record type.");
  EXPECT_EQ(status.GetBytesWritten(), 0);
}

TEST_P(S2ACrypterTest, Protect) {
  const struct {
    std::vector<uint8_t> plaintext;
    uint64_t out_sequence;
  } tests[] = {
      {{'1', '2', '3', '4', '5', '6'}, /*out_sequence=*/0},
      {{'7', '8', '9', '1', '2', '3', '4', '5', '6'}, /*out_sequence=*/1},
      {{'7', '8', '9', '1'}, /*out_sequence=*/2}};
  for (size_t i = 0; i < sizeof(tests) / sizeof(*tests); i++) {
    // Create the |S2ACrypter|.
    absl::variant<Status, std::unique_ptr<S2ACrypter>> crypter_status =
        S2ACrypter::Create(
            TlsVersion::TLS1_3, GetParam(), kConnectionId,
            handshaker_service_url_,
            s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity),
            traffic_secret_, traffic_secret_, /*in_sequence=*/0,
            tests[i].out_sequence, FakeSendTicketsToS2A,
            /*channel_factory=*/nullptr,
            /*channel_options=*/nullptr, NoOpLogger);
    ASSERT_EQ(crypter_status.index(), 1);
    std::unique_ptr<S2ACrypter> crypter =
        std::move(absl::get<1>(crypter_status));

    // Write the TLS record to |record|.
    std::vector<uint8_t> record(tests[i].plaintext.size() +
                                crypter->RecordOverhead());
    S2ACrypterStatus status =
        crypter->Protect(RecordType::APPLICATION_DATA,
                         {{const_cast<uint8_t*>(tests[i].plaintext.data()),
                           tests[i].plaintext.size()}},
                         {record.data(), record.size()});
    EXPECT_EQ(status.GetCode(), S2ACrypterStatusCode::OK);
    EXPECT_EQ(status.GetErrorMessage(), "");
    EXPECT_EQ(status.GetBytesWritten(),
              tests[i].plaintext.size() + crypter->RecordOverhead());

    // Check if the correct TLS record was written to |record|.
    TestTlsRecord correct_record =
        GetTestTlsRecord(GetParam(), tests[i].out_sequence);
    EXPECT_EQ(record.size(), correct_record.record_size);
    for (size_t i = 0; i < correct_record.record_size; i++) {
      EXPECT_EQ(record[i], correct_record.record[i]);
    }
  }
}

TEST_P(S2ACrypterTest, ProtectEmptyPlaintext) {
  // Create the |S2ACrypter|.
  absl::variant<Status, std::unique_ptr<S2ACrypter>> crypter_status =
      S2ACrypter::Create(
          TlsVersion::TLS1_3, GetParam(), kConnectionId,
          handshaker_service_url_,
          s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity),
          traffic_secret_, traffic_secret_, /*in_sequence=*/0,
          /*out_sequence=*/0, FakeSendTicketsToS2A, /*channel_factory=*/nullptr,
          /*channel_options=*/nullptr, NoOpLogger);
  ASSERT_EQ(crypter_status.index(), 1);
  std::unique_ptr<S2ACrypter> crypter = std::move(absl::get<1>(crypter_status));

  // Write the TLS record to |record|.
  std::vector<uint8_t> record(crypter->RecordOverhead());
  S2ACrypterStatus status = crypter->Protect(RecordType::APPLICATION_DATA, {},
                                             {record.data(), record.size()});
  EXPECT_EQ(status.GetCode(), S2ACrypterStatusCode::OK);
  EXPECT_EQ(status.GetErrorMessage(), "");
  EXPECT_EQ(status.GetBytesWritten(), crypter->RecordOverhead());

  // Check if the correct TLS record was written to |record|.
  TestTlsRecord correct_record;
  switch (GetParam()) {
    case Ciphersuite::AES_128_GCM_SHA256:
      correct_record = {s2a_test_data::aes_128_gcm_empty_record_bytes,
                        s2a_test_data::aes_128_gcm_empty_record_bytes_size};
      break;
    case Ciphersuite::AES_256_GCM_SHA384:
      correct_record = {s2a_test_data::aes_256_gcm_empty_record_bytes,
                        s2a_test_data::aes_256_gcm_empty_record_bytes_size};
      break;
    case Ciphersuite::CHACHA20_POLY1305_SHA256:
      correct_record = {s2a_test_data::chacha_poly_empty_record_bytes,
                        s2a_test_data::chacha_poly_empty_record_bytes_size};
      break;
    default:
      FAIL() << "Unrecognized ciphersuite.";
  }
  EXPECT_EQ(record.size(), correct_record.record_size);
  for (size_t i = 0; i < correct_record.record_size; i++) {
    EXPECT_EQ(record[i], correct_record.record[i]);
  }
}

TEST_P(S2ACrypterTest, UnprotectFailures) {
  const struct {
    std::string description;
    std::vector<uint8_t> header;
    std::vector<uint8_t> payload;
    S2ACrypterStatusCode code;
  } tests[] = {
      {"TLS 1.3 record body is too small to contain a real record.",
       {},
       {},
       S2ACrypterStatusCode::FAILED_PRECONDITION},
      {"TLS 1.3 record body is too large.",
       {0x17, 0x03, 0x03, 0x01, 0x11},
       std::vector<uint8_t>(kTls13MaxPlaintextBytesPerRecord + 2 + kTagLength),
       S2ACrypterStatusCode::ALERT_RECORD_OVERFLOW},
      {"TLS 1.3 record header is invalid because of wrong first byte.",
       {0x16, 0x03, 0x03, 0x00, 0x00},
       std::vector<uint8_t>(1 + kTagLength),
       S2ACrypterStatusCode::FAILED_PRECONDITION},
      {"TLS 1.3 record header is invalid because lists wrong record size.",
       {0x17, 0x03, 0x03, 0x01, 0x11},
       std::vector<uint8_t>(1 + kTagLength),
       S2ACrypterStatusCode::FAILED_PRECONDITION},
      {"Decryption failed.",
       {0x17, 0x03, 0x03, 0x00, 0x11},
       std::vector<uint8_t>(1 + kTagLength),
       S2ACrypterStatusCode::INTERNAL_ERROR},
  };
  for (size_t i = 0; i < sizeof(tests) / sizeof(*tests); i++) {
    // Create the |S2ACrypter|.
    absl::variant<Status, std::unique_ptr<S2ACrypter>> crypter_status =
        S2ACrypter::Create(
            TlsVersion::TLS1_3, GetParam(), kConnectionId,
            handshaker_service_url_,
            s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity),
            traffic_secret_, traffic_secret_, /*in_sequence=*/0,
            /*out_sequence=*/0, FakeSendTicketsToS2A,
            /*channel_factory=*/nullptr,
            /*channel_options=*/nullptr, NoOpLogger);
    ASSERT_EQ(crypter_status.index(), 1);
    std::unique_ptr<S2ACrypter> crypter =
        std::move(absl::get<1>(crypter_status));

    S2ACrypterStatus status = crypter->Unprotect(
        {const_cast<uint8_t*>(tests[i].header.data()), tests[i].header.size()},
        {{const_cast<uint8_t*>(tests[i].payload.data()),
          tests[i].payload.size()}},
        /*plaintext=*/{nullptr, 0});
    EXPECT_EQ(status.GetCode(), tests[i].code) << tests[i].description;
    EXPECT_EQ(status.GetBytesWritten(), 0) << tests[i].description;
  }
}

TEST_P(S2ACrypterTest, UnprotectApplicationData) {
  const struct {
    std::vector<uint8_t> plaintext;
    uint64_t in_sequence;
    bool use_padded_record;
  } tests[] = {
      {{'1', '2', '3', '4', '5', '6'},
       /*in_sequence=*/0,
       /*use_padded_record=*/false},
      {{'7', '8', '9', '1', '2', '3', '4', '5', '6'},
       /*in_sequence=*/1,
       /*use_padded_record=*/false},
      {{'7', '8', '9', '1'}, /*in_sequence=*/2, /*use_padded_record=*/false},
      {{'1', '2', '3', '4', '5', '6'},
       /*in_sequence=*/0,
       /*use_padded_record=*/true},
  };
  for (size_t i = 0; i < sizeof(tests) / sizeof(*tests); i++) {
    // Create the |S2ACrypter|.
    absl::variant<Status, std::unique_ptr<S2ACrypter>> crypter_status =
        S2ACrypter::Create(
            TlsVersion::TLS1_3, GetParam(), kConnectionId,
            handshaker_service_url_,
            s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity),
            traffic_secret_, traffic_secret_, tests[i].in_sequence,
            /*out_sequence=*/0, FakeSendTicketsToS2A,
            /*channel_factory=*/nullptr, /*channel_options=*/nullptr,
            NoOpLogger);
    ASSERT_EQ(crypter_status.index(), 1);
    std::unique_ptr<S2ACrypter> crypter =
        std::move(absl::get<1>(crypter_status));

    // Decrypt the application data stored in |record|.
    TestTlsRecord record =
        tests[i].use_padded_record
            ? GetTestTlsRecordWithPadding(GetParam())
            : GetTestTlsRecord(GetParam(), tests[i].in_sequence);
    std::vector<uint8_t> plaintext(tests[i].plaintext.size() +
                                   crypter->RecordOverhead());
    S2ACrypterStatus status = crypter->Unprotect(
        {const_cast<uint8_t*>(record.record), kTls13HeaderLength},
        {{const_cast<uint8_t*>(record.record) + kTls13HeaderLength,
          record.record_size - kTls13HeaderLength}},
        {plaintext.data(), plaintext.size()});
    EXPECT_EQ(status.GetCode(), S2ACrypterStatusCode::OK);
    EXPECT_EQ(status.GetBytesWritten(), tests[i].plaintext.size());
    plaintext.resize(tests[i].plaintext.size());
    EXPECT_EQ(plaintext, tests[i].plaintext);
  }
}

TEST_P(S2ACrypterTest, UnprotectEmptyApplicationData) {
  // Create the |S2ACrypter|.
  absl::variant<Status, std::unique_ptr<S2ACrypter>> crypter_status =
      S2ACrypter::Create(
          TlsVersion::TLS1_3, GetParam(), kConnectionId,
          handshaker_service_url_,
          s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity),
          traffic_secret_, traffic_secret_, /*in_sequence=*/0,
          /*out_sequence=*/0, FakeSendTicketsToS2A, /*channel_factory=*/nullptr,
          /*channel_options=*/nullptr, NoOpLogger);
  ASSERT_EQ(crypter_status.index(), 1);
  std::unique_ptr<S2ACrypter> crypter = std::move(absl::get<1>(crypter_status));

  // Check if the correct TLS record was written to |record|.
  TestTlsRecord record;
  switch (GetParam()) {
    case Ciphersuite::AES_128_GCM_SHA256:
      record = {s2a_test_data::aes_128_gcm_empty_record_bytes,
                s2a_test_data::aes_128_gcm_empty_record_bytes_size};
      break;
    case Ciphersuite::AES_256_GCM_SHA384:
      record = {s2a_test_data::aes_256_gcm_empty_record_bytes,
                s2a_test_data::aes_256_gcm_empty_record_bytes_size};
      break;
    case Ciphersuite::CHACHA20_POLY1305_SHA256:
      record = {s2a_test_data::chacha_poly_empty_record_bytes,
                s2a_test_data::chacha_poly_empty_record_bytes_size};
      break;
    default:
      FAIL() << "Unrecognized ciphersuite.";
  }

  std::vector<uint8_t> plaintext(record.record_size +
                                 crypter->RecordOverhead());
  S2ACrypterStatus status = crypter->Unprotect(
      {const_cast<uint8_t*>(record.record), kTls13HeaderLength},
      {{const_cast<uint8_t*>(record.record) + kTls13HeaderLength,
        record.record_size - kTls13HeaderLength}},
      {plaintext.data(), plaintext.size()});
  EXPECT_EQ(status.GetCode(), S2ACrypterStatusCode::OK);
  EXPECT_EQ(status.GetBytesWritten(), 0);
}

TEST_P(S2ACrypterTest, UnprotectAlert) {
  const struct {
    bool close_notify;
    bool close_notify_with_padding;
    bool other_alert;
    bool small_alert;
    S2ACrypterStatusCode code;
  } tests[] = {
      {/*close_notify=*/true, /*close_notify_with_padding=*/false,
       /*other_alert=*/false, /*small_alert=*/false,
       S2ACrypterStatusCode::ALERT_CLOSE_NOTIFY},
      {/*close_notify=*/false, /*close_notify_with_padding=*/true,
       /*other_alert=*/false, /*small_alert=*/false,
       S2ACrypterStatusCode::ALERT_CLOSE_NOTIFY},
      {/*close_notify=*/false, /*close_notify_with_padding=*/false,
       /*other_alert=*/true, /*small_alert=*/false,
       S2ACrypterStatusCode::ALERT_OTHER},
      {/*close_notify=*/false, /*close_notify_with_padding=*/false,
       /*other_alert=*/false, /*small_alert=*/true,
       S2ACrypterStatusCode::INVALID_RECORD},
  };
  for (size_t i = 0; i < sizeof(tests) / sizeof(*tests); i++) {
    // Create the |S2ACrypter|.
    absl::variant<Status, std::unique_ptr<S2ACrypter>> crypter_status =
        S2ACrypter::Create(
            TlsVersion::TLS1_3, GetParam(), kConnectionId,
            handshaker_service_url_,
            s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity),
            traffic_secret_, traffic_secret_, /*in_sequence=*/0,
            /*out_sequence=*/0, FakeSendTicketsToS2A,
            /*channel_factory=*/nullptr,
            /*channel_options=*/nullptr, NoOpLogger);
    ASSERT_EQ(crypter_status.index(), 1);
    std::unique_ptr<S2ACrypter> crypter =
        std::move(absl::get<1>(crypter_status));

    // Decrypt the alert stored in |record|.
    TestTlsRecord record = GetTestTlsAlertRecord(
        GetParam(), tests[i].close_notify, tests[i].close_notify_with_padding,
        tests[i].other_alert, tests[i].small_alert);
    std::vector<uint8_t> plaintext(record.record_size);
    S2ACrypterStatus status = crypter->Unprotect(
        {const_cast<uint8_t*>(record.record), kTls13HeaderLength},
        {{const_cast<uint8_t*>(record.record) + kTls13HeaderLength,
          record.record_size - kTls13HeaderLength}},
        {plaintext.data(), plaintext.size()});
    EXPECT_EQ(status.GetCode(), tests[i].code);
    EXPECT_EQ(status.GetBytesWritten(), 0);

    if (tests[i].close_notify || tests[i].close_notify_with_padding) {
      status = crypter->Unprotect({nullptr, 0}, {}, {nullptr, 0});
      EXPECT_EQ(status.GetCode(), S2ACrypterStatusCode::ALERT_CLOSE_NOTIFY);
      EXPECT_EQ(status.GetBytesWritten(), 0);
    }
  }
}

TEST_P(S2ACrypterTest, DecryptSessionTicket) {
  // Create the |S2ACrypter|.
  absl::variant<Status, std::unique_ptr<S2ACrypter>> crypter_status =
      S2ACrypter::Create(
          TlsVersion::TLS1_3, GetParam(), kConnectionId,
          handshaker_service_url_,
          s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity),
          traffic_secret_, traffic_secret_, /*in_sequence=*/0,
          /*out_sequence=*/0, FakeSendTicketsToS2A, /*channel_factory=*/nullptr,
          /*channel_options=*/nullptr, NoOpLogger);
  ASSERT_EQ(crypter_status.index(), 1);
  std::unique_ptr<S2ACrypter> crypter = std::move(absl::get<1>(crypter_status));

  TestDecryptSingleSessionTicketSuccess(*crypter, /*partial=*/false);
}

TEST_P(S2ACrypterTest, DecryptApplicantDataFollowingPartialTicket) {
  // Create the |S2ACrypter|.
  absl::variant<Status, std::unique_ptr<S2ACrypter>> crypter_status =
      S2ACrypter::Create(
          TlsVersion::TLS1_3, GetParam(), kConnectionId,
          handshaker_service_url_,
          s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity),
          traffic_secret_, traffic_secret_, /*in_sequence=*/0,
          /*out_sequence=*/0, FakeSendTicketsToS2A, /*channel_factory=*/nullptr,
          /*channel_options=*/nullptr, NoOpLogger);
  ASSERT_EQ(crypter_status.index(), 1);
  std::unique_ptr<S2ACrypter> crypter = std::move(absl::get<1>(crypter_status));

  // Encrypt and decrypt a partial ticket message.
  TestDecryptSingleSessionTicketSuccess(*crypter, /*partial=*/true);

  // Trying to decrypt application data after reading partial ticket should fail
  // with |kS2AExpectingHandshakeMessage| error message. */
  TestDecryptApplicationData(*crypter, S2ACrypterStatusCode::INVALID_RECORD);
}

TEST_P(S2ACrypterTest, SendTicketsToS2ALimitReached) {
  send_ticket_done = false;
  send_ticket_started = false;
  num_tickets_to_send = handshake_message_handler::kMaxNumTicketsToProcess;

  {
    // Create the |S2ACrypter|.
    absl::variant<Status, std::unique_ptr<S2ACrypter>> crypter_status =
        S2ACrypter::Create(
            TlsVersion::TLS1_3, GetParam(), kConnectionId,
            handshaker_service_url_,
            s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity),
            traffic_secret_, traffic_secret_, /*in_sequence=*/0,
            /*out_sequence=*/0, FakeSendTicketsToS2A,
            /*channel_factory=*/nullptr,
            /*channel_options=*/nullptr, NoOpLogger);
    ASSERT_EQ(crypter_status.index(), 1);
    std::unique_ptr<S2ACrypter> crypter =
        std::move(absl::get<1>(crypter_status));

    // Decrypt |kMaxNumTicketsToProcess| tickets.
    for (std::size_t i = 0;
         i < handshake_message_handler::kMaxNumTicketsToProcess; i++) {
      TestDecryptSingleSessionTicketSuccess(*crypter, /*partial=*/false);
      // Tickets should not have been sent to the S2A up until the last ticket
      // is decrypted.
      if (i < handshake_message_handler::kMaxNumTicketsToProcess - 1) {
        ASSERT_FALSE(send_ticket_started);
      }
    }

    // At this point, |crypter| should have initiated a call to send the
    // tickets.
    ASSERT_TRUE(send_ticket_started);
  }

  // Once |crypter| has been destroyed, we must ensure that
  // |FakeWaitOnTicketSender| is called.
  ASSERT_TRUE(send_ticket_done);
}

TEST_P(S2ACrypterTest, SendTicketsToS2ANonTicketRecordFound) {
  send_ticket_done = false;
  send_ticket_started = false;
  num_tickets_to_send = 1;

  {
    // Create the |S2ACrypter|.
    absl::variant<Status, std::unique_ptr<S2ACrypter>> crypter_status =
        S2ACrypter::Create(
            TlsVersion::TLS1_3, GetParam(), kConnectionId,
            handshaker_service_url_,
            s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity),
            traffic_secret_, traffic_secret_, /*in_sequence=*/0,
            /*out_sequence=*/0, FakeSendTicketsToS2A,
            /*channel_factory=*/nullptr,
            /*channel_options=*/nullptr, NoOpLogger);
    ASSERT_EQ(crypter_status.index(), 1);
    std::unique_ptr<S2ACrypter> crypter =
        std::move(absl::get<1>(crypter_status));

    // Decrypt a TLS record with a ticket. At this point, ticket should not be
    // sent to S2A.
    TestDecryptSingleSessionTicketSuccess(*crypter, /*partial=*/false);
    ASSERT_FALSE(send_ticket_started);

    // Decrypt a TLS record with application data. This will trigger the crypter
    // to send the tickets.
    TestDecryptApplicationData(*crypter, S2ACrypterStatusCode::OK);
    ASSERT_TRUE(send_ticket_started);
  }

  // Once |crypter| has been destroyed, we must ensure that
  // |FakeWaitOnTicketSender| is called.
  ASSERT_TRUE(send_ticket_done);
}

TEST_P(S2ACrypterTest, KeyUpdate) {
  // Create the |S2ACrypter|.
  absl::variant<Status, std::unique_ptr<S2ACrypter>> crypter_status =
      S2ACrypter::Create(
          TlsVersion::TLS1_3, GetParam(), kConnectionId,
          handshaker_service_url_,
          s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity),
          traffic_secret_, traffic_secret_, /*in_sequence=*/0,
          /*out_sequence=*/0, FakeSendTicketsToS2A, /*channel_factory=*/nullptr,
          /*channel_options=*/nullptr, NoOpLogger);
  ASSERT_EQ(crypter_status.index(), 1);
  std::unique_ptr<S2ACrypter> crypter = std::move(absl::get<1>(crypter_status));

  // Write the key update message into a TLS record.
  std::vector<uint8_t> record(s2a_test_data::key_update_message_size +
                              crypter->RecordOverhead());
  S2ACrypterStatus status = crypter->Protect(
      RecordType::HANDSHAKE,
      {{const_cast<uint8_t*>(s2a_test_data::key_update_message),
        s2a_test_data::key_update_message_size}},
      {record.data(), record.size()});
  EXPECT_EQ(status.GetCode(), S2ACrypterStatusCode::OK);
  EXPECT_EQ(status.GetBytesWritten(), record.size());

  // Decrypt the key update message. A key update should occur and no bytes of
  // application data should be written to |plaintext|.
  std::vector<uint8_t> plaintext(1000);
  status = crypter->Unprotect({record.data(), kTls13HeaderLength},
                              {{record.data() + kTls13HeaderLength,
                                record.size() - kTls13HeaderLength}},
                              {plaintext.data(), plaintext.size()});
  EXPECT_EQ(status.GetCode(), S2ACrypterStatusCode::OK);
  EXPECT_EQ(status.GetBytesWritten(), 0);

  // Decrypt a TLS record that was encrypted using the new key.
  std::vector<uint8_t> advanced_record_plaintext = {'1', '2', '3',
                                                    '4', '5', '6'};
  TestTlsRecord advanced_record = GetTestTlsAdvancedRecord(GetParam());
  status = crypter->Unprotect(
      {const_cast<uint8_t*>(advanced_record.record), kTls13HeaderLength},
      {{const_cast<uint8_t*>(advanced_record.record) + kTls13HeaderLength,
        advanced_record.record_size - kTls13HeaderLength}},
      {plaintext.data(), plaintext.size()});
  EXPECT_EQ(status.GetCode(), S2ACrypterStatusCode::OK);
  EXPECT_EQ(status.GetBytesWritten(), advanced_record_plaintext.size());
  plaintext.resize(advanced_record_plaintext.size());
  EXPECT_EQ(plaintext, advanced_record_plaintext);
}

TEST_P(S2ACrypterTest, KeyUpdateWithPadding) {
  // Create the |S2ACrypter|.
  absl::variant<Status, std::unique_ptr<S2ACrypter>> crypter_status =
      S2ACrypter::Create(
          TlsVersion::TLS1_3, GetParam(), kConnectionId,
          handshaker_service_url_,
          s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity),
          traffic_secret_, traffic_secret_, /*in_sequence=*/0,
          /*out_sequence=*/0, FakeSendTicketsToS2A, /*channel_factory=*/nullptr,
          /*channel_options=*/nullptr, NoOpLogger);
  ASSERT_EQ(crypter_status.index(), 1);
  std::unique_ptr<S2ACrypter> crypter = std::move(absl::get<1>(crypter_status));

  // Decrypt a key update message with padding. A key update should occur and no
  // bytes of application data should be written to |plaintext|.
  TestTlsRecord record = GetTestTlsKeyUpdateWithPaddingRecord(GetParam());
  std::vector<uint8_t> plaintext(1000);
  S2ACrypterStatus status = crypter->Unprotect(
      {const_cast<uint8_t*>(record.record), kTls13HeaderLength},
      {{const_cast<uint8_t*>(record.record) + kTls13HeaderLength,
        record.record_size - kTls13HeaderLength}},
      {plaintext.data(), plaintext.size()});
  EXPECT_EQ(status.GetCode(), S2ACrypterStatusCode::OK);
  EXPECT_EQ(status.GetBytesWritten(), 0);

  // Decrypt a TLS record that was encrypted using the new key.
  std::vector<uint8_t> advanced_record_plaintext = {'1', '2', '3',
                                                    '4', '5', '6'};
  TestTlsRecord advanced_record = GetTestTlsAdvancedRecord(GetParam());
  status = crypter->Unprotect(
      {const_cast<uint8_t*>(advanced_record.record), kTls13HeaderLength},
      {{const_cast<uint8_t*>(advanced_record.record) + kTls13HeaderLength,
        advanced_record.record_size - kTls13HeaderLength}},
      {plaintext.data(), plaintext.size()});
  EXPECT_EQ(status.GetCode(), S2ACrypterStatusCode::OK);
  EXPECT_EQ(status.GetBytesWritten(), advanced_record_plaintext.size());
  plaintext.resize(advanced_record_plaintext.size());
  EXPECT_EQ(plaintext, advanced_record_plaintext);
}

}  // namespace
}  // namespace record_protocol
}  // namespace s2a
