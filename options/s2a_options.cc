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

namespace s2a {
namespace s2a_options {

namespace {

using Identity = S2AOptions::Identity;
using IdentityType = S2AOptions::IdentityType;
using TlsVersion = S2AOptions::TlsVersion;
using Ciphersuite = S2AOptions::Ciphersuite;

}  // namespace

Identity Identity::GetEmptyIdentity() {
  return Identity("", IdentityType::NONE);
}

Identity Identity::FromHostname(const std::string& hostname) {
  return Identity(hostname, IdentityType::HOSTNAME);
}

Identity Identity::FromSpiffeId(const std::string& spiffe_id) {
  return Identity(spiffe_id, IdentityType::SPIFFE_ID);
}

Identity Identity::FromUid(const std::string& uid) {
  return Identity(uid, IdentityType::UID);
}

Identity::Identity(const Identity& other)
    : identity_(other.GetIdentityString()), type_(other.GetIdentityType()) {}

Identity::Identity(const std::string& identity, IdentityType type)
    : identity_(identity), type_(type) {}

bool Identity::operator==(const Identity& other) const {
  return type_ == other.GetIdentityType() &&
         identity_ == other.GetIdentityString();
}

std::string Identity::GetIdentityString() const { return identity_; }

const char* Identity::GetIdentityCString() const { return identity_.c_str(); }

IdentityType Identity::GetIdentityType() const { return type_; }

S2AOptions::~S2AOptions() {}

TlsVersion S2AOptions::min_tls_version() const { return min_tls_version_; }

TlsVersion S2AOptions::max_tls_version() const { return max_tls_version_; }

const std::string S2AOptions::handshaker_service_url() const {
  return handshaker_service_url_;
}

const std::vector<Ciphersuite>& S2AOptions::supported_ciphersuites() const {
  return supported_ciphersuites_;
}

const absl::flat_hash_set<Identity>& S2AOptions::local_identities() const {
  return local_identities_;
}

const absl::flat_hash_set<Identity>& S2AOptions::target_identities() const {
  return target_identities_;
}

void S2AOptions::set_min_tls_version(TlsVersion min_tls_version) {
  min_tls_version_ = min_tls_version;
}

void S2AOptions::set_max_tls_version(TlsVersion max_tls_version) {
  max_tls_version_ = max_tls_version;
}

void S2AOptions::add_supported_ciphersuite(Ciphersuite ciphersuite) {
  supported_ciphersuites_.push_back(ciphersuite);
}

void S2AOptions::set_handshaker_service_url(const std::string& url) {
  handshaker_service_url_ = url;
}

void S2AOptions::add_local_spiffe_id(const std::string& local_spiffe_id) {
  local_identities_.insert(Identity::FromSpiffeId(local_spiffe_id));
}

void S2AOptions::add_local_hostname(const std::string& local_hostname) {
  local_identities_.insert(Identity::FromHostname(local_hostname));
}

void S2AOptions::add_local_uid(const std::string& local_uid) {
  local_identities_.insert(Identity::FromUid(local_uid));
}

void S2AOptions::add_target_spiffe_id(const std::string& target_spiffe_id) {
  target_identities_.insert(Identity::FromSpiffeId(target_spiffe_id));
}

void S2AOptions::add_target_hostname(const std::string& target_hostname) {
  target_identities_.insert(Identity::FromHostname(target_hostname));
}

void S2AOptions::add_target_uid(const std::string& target_uid) {
  target_identities_.insert(Identity::FromUid(target_uid));
}

std::unique_ptr<S2AOptions> S2AOptions::Copy() const {
  auto new_options = absl::make_unique<S2AOptions>();
  new_options->set_min_tls_version(min_tls_version_);
  new_options->set_max_tls_version(max_tls_version_);
  new_options->set_handshaker_service_url(handshaker_service_url_);
  new_options->local_identities_ = local_identities_;
  new_options->target_identities_ = target_identities_;
  for (auto ciphersuite : supported_ciphersuites_) {
    new_options->add_supported_ciphersuite(ciphersuite);
  }
  return new_options;
}

}  // namespace s2a_options
}  // namespace s2a
