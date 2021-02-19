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

#include "record_protocol/s2a_half_connection.h"

#include "options/s2a_options.h"
#include "s2a_constants.h"
#include "test_util/s2a_test_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace s2a {
namespace record_protocol {
namespace {

using ::absl::Status;
using ::absl::StatusCode;
using ::s2a::test_util::StatusIs;
using Ciphersuite = ::s2a::s2a_options::S2AOptions::Ciphersuite;
using CrypterStatus = ::s2a::aead_crypter::S2AAeadCrypter::CrypterStatus;

TEST(S2AHalfConnectionTest, Create) {
  const struct {
    std::string description;
    Ciphersuite ciphersuite;
    std::vector<uint8_t> traffic_secret;
    StatusCode status_code;
    std::string error_message;
  } tests[] = {
      {"Fails because of incorrect traffic secret size: ",
       Ciphersuite::AES_128_GCM_SHA256,
       std::vector<uint8_t>(kSha384DigestLength), StatusCode::kInvalidArgument,
       "|traffic_secret| size is incorrect."},
      {"Success: ", Ciphersuite::CHACHA20_POLY1305_SHA256,
       std::vector<uint8_t>(kSha256DigestLength), StatusCode::kOk, ""},
  };
  for (size_t i = 0; i < sizeof(tests) / sizeof(*tests); i++) {
    absl::variant<Status, std::unique_ptr<S2AHalfConnection>> output =
        S2AHalfConnection::Create(tests[i].ciphersuite, /*sequence=*/0,
                                  tests[i].traffic_secret);
    if (tests[i].status_code != StatusCode::kOk) {
      ASSERT_EQ(output.index(), 0) << tests[i].description;
      EXPECT_THAT(absl::get<0>(output),
                  StatusIs(tests[i].status_code, tests[i].error_message))
          << tests[i].description;
    } else {
      EXPECT_NE(absl::get<1>(output), nullptr) << tests[i].description;
    }
  }
}

TEST(S2AHalfConnectionTest, SequenceOverflow) {
  absl::variant<Status, std::unique_ptr<S2AHalfConnection>> output =
      S2AHalfConnection::Create(Ciphersuite::AES_256_GCM_SHA384,
                                /*sequence=*/-1,
                                std::vector<uint8_t>(kSha384DigestLength));
  ASSERT_EQ(output.index(), 1);
  std::unique_ptr<S2AHalfConnection> half_connection =
      std::move(absl::get<1>(output));

  // The first call to |Encrypt| should cause the sequence number to overflow.
  std::vector<uint8_t> tag(half_connection->TagLength());
  EXPECT_THAT(
      half_connection
          ->Encrypt(/*aad=*/{}, /*plaintext=*/{}, {tag.data(), tag.size()})
          .GetStatus(),
      StatusIs(StatusCode::kOk));

  // The second call to |Encrypt| should produce an error.
  EXPECT_THAT(
      half_connection
          ->Encrypt(/*aad=*/{}, /*plaintext=*/{}, {tag.data(), tag.size()})
          .GetStatus(),
      StatusIs(StatusCode::kInternal));
}

TEST(S2AHalfConnectionTest, Encrypt) {
  // The |ciphertext_and_tag| vectors below were generated using BoringSSL.
  const struct {
    Ciphersuite ciphersuite;
    std::vector<uint8_t> traffic_secret;
    std::vector<uint8_t> ciphertext_and_tag;
  } tests[] = {
      {Ciphersuite::AES_128_GCM_SHA256,
       std::vector<uint8_t>(kSha256DigestLength, 0x6b),
       {0xf2, 0xe4, 0xe4, 0x11, 0xac, 0x67, 0x4e, 0x01, 0x38, 0x5e, 0x7a,
        0xe9, 0xdb, 0x54, 0xc9, 0x7a, 0x9a, 0xe3, 0xd1, 0x84, 0x2e, 0x51}},
      {Ciphersuite::AES_256_GCM_SHA384,
       std::vector<uint8_t>(kSha384DigestLength, 0x6b),
       {0x24, 0xef, 0xee, 0x5a, 0xf1, 0xa6, 0x65, 0xe6, 0xbb, 0x18, 0x8e,
        0x79, 0x54, 0x4a, 0x7e, 0x97, 0x4c, 0x70, 0x7d, 0x69, 0x0c, 0x5f}},
      {Ciphersuite::CHACHA20_POLY1305_SHA256,
       std::vector<uint8_t>(kSha256DigestLength, 0x6b),
       {0xc9, 0x47, 0xff, 0xa4, 0x70, 0x30, 0x8b, 0x19, 0xd9, 0xa0, 0x86,
        0xb0, 0x5c, 0xcb, 0x75, 0xd8, 0xc9, 0x4a, 0xbb, 0x70, 0x4a, 0xae}},
  };
  for (size_t i = 0; i < sizeof(tests) / sizeof(*tests); i++) {
    absl::variant<Status, std::unique_ptr<S2AHalfConnection>> output =
        S2AHalfConnection::Create(tests[i].ciphersuite, /*sequence=*/0,
                                  tests[i].traffic_secret);
    ASSERT_EQ(output.index(), 1);
    std::unique_ptr<S2AHalfConnection> half_connection =
        std::move(absl::get<1>(output));

    // Encrypt the plaintext.
    std::vector<uint8_t> plaintext = {'1', '2', '3', '4', '5', '6'};
    size_t bytes_to_write = plaintext.size() + half_connection->TagLength();
    std::vector<uint8_t> buffer(bytes_to_write);
    CrypterStatus status = half_connection->Encrypt(
        /*aad=*/{}, {{plaintext.data(), plaintext.size()}},
        {buffer.data(), buffer.size()});
    EXPECT_TRUE(status.GetStatus().ok());
    EXPECT_EQ(status.GetBytesWritten(), bytes_to_write);
    EXPECT_EQ(buffer, tests[i].ciphertext_and_tag);
  }
}

TEST(S2AHalfConnectionTest, UpdateKeyAndEncrypt) {
  // The |ciphertext_and_tag| vectors below were generated using BoringSSL.
  const struct {
    Ciphersuite ciphersuite;
    std::vector<uint8_t> traffic_secret;
    std::vector<uint8_t> ciphertext_and_tag;
  } tests[] = {
      {Ciphersuite::AES_128_GCM_SHA256,
       std::vector<uint8_t>(kSha256DigestLength, 0x6b),
       {0xdd, 0x99, 0xeb, 0xef, 0x48, 0x29, 0x48, 0x72, 0xe5, 0xfb, 0x83,
        0xa6, 0xb9, 0x65, 0xd4, 0x9c, 0x67, 0xdb, 0xa4, 0x1d, 0xcb, 0xdc}},
      {Ciphersuite::AES_256_GCM_SHA384,
       std::vector<uint8_t>(kSha384DigestLength, 0x6b),
       {0x9c, 0xd5, 0x97, 0x2e, 0x76, 0xba, 0x86, 0x26, 0xa6, 0x9d, 0x68,
        0x0c, 0xf5, 0x84, 0x00, 0x30, 0x45, 0x12, 0x6c, 0x61, 0x8c, 0xf8}},
      {Ciphersuite::CHACHA20_POLY1305_SHA256,
       std::vector<uint8_t>(kSha256DigestLength, 0x6b),
       {0xc4, 0xe4, 0x8c, 0xca, 0xf0, 0x36, 0xb0, 0x60, 0x34, 0xb8, 0x1f,
        0xbf, 0x44, 0x34, 0xc7, 0x82, 0x7c, 0x2b, 0x4d, 0xc2, 0x79, 0x63}},
  };
  for (size_t i = 0; i < sizeof(tests) / sizeof(*tests); i++) {
    absl::variant<Status, std::unique_ptr<S2AHalfConnection>> output =
        S2AHalfConnection::Create(tests[i].ciphersuite, /*sequence=*/0,
                                  tests[i].traffic_secret);
    ASSERT_EQ(output.index(), 1);
    std::unique_ptr<S2AHalfConnection> half_connection =
        std::move(absl::get<1>(output));

    // Update the key.
    EXPECT_TRUE(half_connection->UpdateKey().ok());

    // Encrypt the plaintext using the next key.
    std::vector<uint8_t> plaintext = {'1', '2', '3', '4', '5', '6'};
    size_t bytes_to_write = plaintext.size() + half_connection->TagLength();
    std::vector<uint8_t> buffer(bytes_to_write);
    CrypterStatus status = half_connection->Encrypt(
        /*aad=*/{}, {{plaintext.data(), plaintext.size()}},
        {buffer.data(), buffer.size()});
    EXPECT_TRUE(status.GetStatus().ok());
    EXPECT_EQ(status.GetBytesWritten(), bytes_to_write);
    EXPECT_EQ(buffer, tests[i].ciphertext_and_tag);
  }
}

}  // namespace
}  // namespace record_protocol
}  // namespace s2a
