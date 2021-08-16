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

#ifndef S2A_SRC_HANDSHAKER_S2A_UTIL_H_
#define S2A_SRC_HANDSHAKER_S2A_UTIL_H_

#include "absl/status/status.h"
#include "absl/types/variant.h"
#include "s2a/include/s2a_options.h"
#include "s2a/src/proto/upb-generated/s2a/src/proto/common.upb.h"
#include "upb/upb.hpp"

namespace s2a {
namespace s2a_util {

// |ConvertTlsVersionToProto| returns the UPB-compiled proto message
// corresponding to |tls_version|, or an error status if none exists.
absl::variant<absl::Status, s2a_proto_TLSVersion> ConvertTlsVersionToProto(
    s2a_options::S2AOptions::TlsVersion tls_version);

// |ConvertCiphersuiteToProto| returns the UPB-compiled proto message
// corresponding to |ciphersuite|, or an error status if none exists.
absl::variant<absl::Status, s2a_proto_Ciphersuite> ConvertCiphersuiteToProto(
    s2a_options::S2AOptions::Ciphersuite ciphersuite);

// |ConvertIdentityToProto| returns the UPB-compiled proto message corresponding
// to |identity|, or an error status if none exists.
absl::variant<absl::Status, s2a_proto_Identity*> ConvertIdentityToProto(
    upb_arena* arena, const s2a_options::S2AOptions::Identity& identity);

// |ConvertFromProtoToTlsVersion| returns the |TlsVersion| corresponding to the
// UPB-compiled proto messaage |tls_version|, or an error status if none exists.
absl::variant<absl::Status, s2a_options::S2AOptions::TlsVersion>
ConvertFromProtoToTlsVersion(s2a_proto_TLSVersion tls_version);

// |ConvertFromProtoToCiphersuite| returns the |Ciphersuite| corresponding to
// the UPB-compiled proto message |ciphersuite|, or an error status if none
// exists.
absl::variant<absl::Status, s2a_options::S2AOptions::Ciphersuite>
ConvertFromProtoToCiphersuite(s2a_proto_Ciphersuite ciphersuite);

// |ConvertFromProtoToIdentity| returns the |Identity| corresponding to the
// UPB-compiled proto message |identity|.
s2a_options::S2AOptions::Identity ConvertFromProtoToIdentity(
    const s2a_proto_Identity* identity);

// |ParseUpbStrview| converts |message| to a |std::string|.
std::string ParseUpbStrview(const upb_strview& message);

}  // namespace s2a_util
}  // namespace s2a

#endif  // S2A_SRC_HANDSHAKER_S2A_UTIL_H_
