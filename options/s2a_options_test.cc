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

#include "options/s2a_options.h"

#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace s2a {
namespace s2a_options {
namespace {

using Ciphersuite = S2AOptions::Ciphersuite;
using Identity = S2AOptions::Identity;
using IdentityType = S2AOptions::IdentityType;
using TlsVersion = S2AOptions::TlsVersion;

constexpr char kHandshakerServiceUrl[] = "handshaker_service_url";
constexpr char kLocalSpiffeId[] = "local spiffe id";
constexpr char kLocalHostname[] = "local hostname";
constexpr char kTargetSpiffeId[] = "target spiffe id";
constexpr char kTargetHostname[] = "target hostname";

static std::vector<Ciphersuite> GetCiphersuites() {
  return {Ciphersuite::AES_128_GCM_SHA256, Ciphersuite::AES_256_GCM_SHA384,
          Ciphersuite::CHACHA20_POLY1305_SHA256};
}

static absl::flat_hash_set<Identity> GetLocalIdentities() {
  absl::flat_hash_set<Identity> local_identities;
  local_identities.insert(Identity::FromSpiffeId(kLocalSpiffeId));
  local_identities.insert(Identity::FromHostname(kLocalHostname));
  return local_identities;
}

static absl::flat_hash_set<Identity> GetTargetIdentities() {
  absl::flat_hash_set<Identity> target_identities;
  target_identities.insert(Identity::FromSpiffeId(kTargetSpiffeId));
  target_identities.insert(Identity::FromHostname(kTargetHostname));
  return target_identities;
}

TEST(S2AOptionsIdentityTest, GetEmptyIdentity) {
  Identity empty_identity = Identity::GetEmptyIdentity();
  EXPECT_TRUE(empty_identity.GetIdentityString().empty());
  EXPECT_EQ(empty_identity.GetIdentityType(), IdentityType::NONE);
}

TEST(S2AOptionsIdentityTest, FromHostname) {
  Identity hostname = Identity::FromHostname(kLocalHostname);
  EXPECT_EQ(hostname.GetIdentityString(), kLocalHostname);
  EXPECT_STREQ(hostname.GetIdentityCString(), kLocalHostname);
  EXPECT_EQ(hostname.GetIdentityType(), IdentityType::HOSTNAME);
}

TEST(S2AOptionsIdentityTest, FromSpiffeId) {
  Identity spiffe_id = Identity::FromSpiffeId(kLocalSpiffeId);
  EXPECT_EQ(spiffe_id.GetIdentityString(), kLocalSpiffeId);
  EXPECT_STREQ(spiffe_id.GetIdentityCString(), kLocalSpiffeId);
  EXPECT_EQ(spiffe_id.GetIdentityType(), IdentityType::SPIFFE_ID);
}

TEST(S2AOptionsIdentityTest, CopyConstructor) {
  Identity spiffe_id = Identity::FromSpiffeId(kLocalSpiffeId);
  EXPECT_EQ(spiffe_id.GetIdentityString(), kLocalSpiffeId);
  EXPECT_EQ(spiffe_id.GetIdentityType(), IdentityType::SPIFFE_ID);
}

TEST(S2ACredentialsOptionsTest, Create) {
  auto options = absl::make_unique<S2AOptions>();
  options->set_min_tls_version(TlsVersion::TLS1_2);
  options->set_max_tls_version(TlsVersion::TLS1_3);
  options->set_handshaker_service_url(kHandshakerServiceUrl);
  for (auto ciphersuite : GetCiphersuites()) {
    options->add_supported_ciphersuite(ciphersuite);
  }
  options->add_local_spiffe_id(kLocalSpiffeId);
  options->add_local_hostname(kLocalHostname);
  options->add_target_spiffe_id(kTargetSpiffeId);
  options->add_target_hostname(kTargetHostname);

  EXPECT_EQ(options->min_tls_version(), TlsVersion::TLS1_2);
  EXPECT_EQ(options->max_tls_version(), TlsVersion::TLS1_3);
  EXPECT_EQ(options->handshaker_service_url(), kHandshakerServiceUrl);
  EXPECT_EQ(options->supported_ciphersuites(), GetCiphersuites());
  EXPECT_EQ(options->local_identities(), GetLocalIdentities());
  EXPECT_EQ(options->target_identities(), GetTargetIdentities());
}

TEST(S2ACredentialsOptionsTest, CreateAndCopy) {
  auto options = absl::make_unique<S2AOptions>();
  options->set_min_tls_version(TlsVersion::TLS1_2);
  options->set_max_tls_version(TlsVersion::TLS1_3);
  options->set_handshaker_service_url(kHandshakerServiceUrl);
  for (auto ciphersuite : GetCiphersuites()) {
    options->add_supported_ciphersuite(ciphersuite);
  }
  options->add_local_spiffe_id(kLocalSpiffeId);
  options->add_local_hostname(kLocalHostname);
  options->add_target_spiffe_id(kTargetSpiffeId);
  options->add_target_hostname(kTargetHostname);

  auto copy_options = options->Copy();

  EXPECT_EQ(copy_options->min_tls_version(), TlsVersion::TLS1_2);
  EXPECT_EQ(copy_options->max_tls_version(), TlsVersion::TLS1_3);
  EXPECT_EQ(copy_options->handshaker_service_url(), kHandshakerServiceUrl);
  EXPECT_EQ(copy_options->supported_ciphersuites(), GetCiphersuites());
  EXPECT_EQ(copy_options->local_identities(), GetLocalIdentities());
  EXPECT_EQ(copy_options->target_identities(), GetTargetIdentities());
}

}  // namespace
}  // namespace s2a_options
}  // namespace s2a
