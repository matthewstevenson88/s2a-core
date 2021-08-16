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

#ifndef S2A_INCLUDE_S2A_CONSTANTS_H_
#define S2A_INCLUDE_S2A_CONSTANTS_H_

#include <cstddef>
#include <cstdint>

#include "s2a/src/proto/upb-generated/s2a/src/proto/common.upb.h"

/** The supported TLS 1.3 ciphersuites, with values from the TLS 1.3 RFC:
 *  https://tools.ietf.org/html/rfc8446#appendix-B.4. **/
constexpr int kTlsAes128GcmSha256 = 0x1301;
constexpr int kTlsAes256GcmSha384 = 0x1302;
constexpr int kTlsChacha20Poly1305Sha256 = 0x1303;

/** The TLS versions listed in the S2A proto. These constants should be used by
 *  the top-level API's (e.g. the credentials and credentials options). **/
constexpr int kTls12 = s2a_proto_TLS1_2;
constexpr int kTls13 = s2a_proto_TLS1_3;

/** The following constants are ciphersuite-specific data. **/
constexpr std::size_t kEvpAeadAesGcmTagLength = 16;
constexpr std::size_t kEvpAeadMaxKeyLength = 80;
constexpr std::size_t kEvpAeadMaxNonceLength = 24;
constexpr std::size_t kPoly1305TagLength = 16;
constexpr std::size_t kSha256DigestLength = 32;
constexpr std::size_t kSha384DigestLength = 48;

/** The following constants represent the key and nonce sizes of the supported
 *  ciphersuites. **/
constexpr std::size_t kTlsAes128GcmSha256KeySize = 16;
constexpr std::size_t kTlsAes256GcmSha384KeySize = 32;
constexpr std::size_t kTlsChacha20Poly1305Sha256KeySize = 32;

constexpr std::size_t kTlsAes128GcmSha256NonceSize = 12;
constexpr std::size_t kTlsAes256GcmSha384NonceSize = 12;
constexpr std::size_t kTlsChacha20Poly1305Sha256NonceSize = 12;

/** The size (in bytes) of the sequence buffer used for parsing TLS 1.3 records.
 * **/
constexpr std::size_t kTlsSequenceSize = 8;

/** The maximum size of a frame expected by the S2A frame protector. **/
constexpr std::size_t kS2AMaxFrameSize =
    /*record_header=*/5 + /*max_plaintext_size=*/16 * 1024 + /*tag=*/16;

/** The initial size (in bytes) of the buffer owned by an S2A handshaker client.
 * **/
constexpr std::size_t kS2AInitialBufferSize = 256;

/** The extension for the interaction with the S2A service. **/
constexpr char kS2AServiceMethod[] = "/s2a.proto.S2AService/SetUpSession";

/** The application protocol used by S2A. **/
constexpr char kS2AApplicationProtocol[] = "grpc";

#endif  // S2A_INCLUDE_S2A_CONSTANTS_H_
