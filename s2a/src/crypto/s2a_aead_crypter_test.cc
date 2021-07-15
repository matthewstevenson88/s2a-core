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

#include "s2a/src/crypto/s2a_aead_crypter.h"

#include "absl/status/status.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace s2a {
namespace aead_crypter {
namespace {

constexpr size_t kKeyLength = 32;
constexpr size_t kNonceLength = 12;
constexpr size_t kTagLength = 16;
constexpr size_t kTestPlaintextSize = 10;
constexpr size_t kTestCiphertextAndTagSize = 26;

class FakeS2AAeadCrypter : public S2AAeadCrypter {
 public:
  FakeS2AAeadCrypter(size_t key_length, size_t nonce_length, size_t tag_length)
      : S2AAeadCrypter(key_length, nonce_length, tag_length) {}

  ~FakeS2AAeadCrypter() override {}

  CrypterStatus Encrypt(const std::vector<uint8_t>& nonce,
                        const std::vector<Iovec>& aad,
                        const std::vector<Iovec>& plaintext,
                        Iovec ciphertext_and_tag) override {
    // This method should not be called.
    return CrypterStatus(absl::Status(), 0);
  }

  CrypterStatus Decrypt(const std::vector<uint8_t>& nonce,
                        const std::vector<Iovec>& aad,
                        const std::vector<Iovec>& ciphertext_and_tag,
                        Iovec plaintext) override {
    // This method should not be called.
    return CrypterStatus(absl::Status(), 0);
  }
};

class S2AAeadCrypterTest : public ::testing::Test {
 protected:
  S2AAeadCrypterTest() : crypter_(kKeyLength, kNonceLength, kTagLength) {}

  FakeS2AAeadCrypter crypter_;
};

TEST_F(S2AAeadCrypterTest, KeyLength) {
  EXPECT_EQ(crypter_.KeyLength(), kKeyLength);
}

TEST_F(S2AAeadCrypterTest, NonceLength) {
  EXPECT_EQ(crypter_.NonceLength(), kNonceLength);
}

TEST_F(S2AAeadCrypterTest, TagLength) {
  EXPECT_EQ(crypter_.TagLength(), kTagLength);
}

TEST_F(S2AAeadCrypterTest, MaxPlaintextLength) {
  EXPECT_EQ(crypter_.MaxPlaintextLength(kTestCiphertextAndTagSize),
            kTestPlaintextSize);
}

TEST_F(S2AAeadCrypterTest, MaxCiphertextAndTagLength) {
  EXPECT_EQ(crypter_.MaxCiphertextAndTagLength(kTestPlaintextSize),
            kTestCiphertextAndTagSize);
}

TEST(CrypterStatusTest, ConstructAndGet) {
  size_t bytes_written = 1;
  S2AAeadCrypter::CrypterStatus status(absl::OkStatus(), bytes_written);
  EXPECT_TRUE(status.GetStatus().ok());
  EXPECT_EQ(status.GetBytesWritten(), bytes_written);
}

}  // namespace
}  // namespace aead_crypter
}  // namespace s2a
