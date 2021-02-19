/*
 *
 * Copyright 2021 Google LLC
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

#ifndef TEST_UTIL_S2A_TEST_DATA_H_
#define TEST_UTIL_S2A_TEST_DATA_H_

#include <cstddef>
#include <cstdint>

namespace s2a_test_data {

/** The following vectors are the traffic secret "kkkk...k", with the length
 *  determined by the ciphersuite. **/
constexpr std::size_t aes_128_gcm_traffic_secret_size = 32;
constexpr uint8_t aes_128_gcm_traffic_secret[] = {
    0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
    0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
    0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b};
constexpr std::size_t aes_256_gcm_traffic_secret_size = 48;
constexpr uint8_t aes_256_gcm_traffic_secret[] = {
    0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
    0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
    0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
    0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b};
constexpr std::size_t chacha_poly_traffic_secret_size = 32;
constexpr uint8_t chacha_poly_traffic_secret[] = {
    0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
    0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b,
    0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b, 0x6b};

/** The following vectors are the new traffic secret obtaing from "kkkk...k"
 *  after advancing once. **/
constexpr std::size_t aes_128_gcm_advanced_traffic_secret_size = 32;
constexpr uint8_t aes_128_gcm_advanced_traffic_secret[] = {
    243, 139, 148, 85,  234, 88, 113, 35, 90,  105, 252, 55, 97,  12, 108, 161,
    33,  87,  121, 230, 107, 69, 160, 71, 215, 57,  1,   17, 224, 0,  129, 196};
constexpr std::size_t aes_256_gcm_advanced_traffic_secret_size = 48;
constexpr uint8_t aes_256_gcm_advanced_traffic_secret[] = {
    1,   108, 131, 93,  182, 100, 190, 181, 82,  106, 155, 179,
    217, 164, 251, 166, 62,  103, 37,  93,  207, 164, 96,  161,
    20,  217, 241, 239, 154, 154, 31,  104, 90,  81,  135, 57,
    245, 87,  208, 230, 111, 219, 137, 189, 175, 162, 98,  87};
constexpr std::size_t chacha_poly_advanced_traffic_secret_size = 32;
constexpr uint8_t chacha_poly_advanced_traffic_secret[] = {
    243, 139, 148, 85,  234, 88, 113, 35, 90,  105, 252, 55, 97,  12, 108, 161,
    33,  87,  121, 230, 107, 69, 160, 71, 215, 57,  1,   17, 224, 0,  129, 196};

/** The following vectors were generated using a different TLS 1.3
 *  implementation. The keys and nonces are derived from the traffic secret
 *  "kkkk...k", with the length determined by the ciphersuite. **/
constexpr std::size_t aes_128_gcm_key_bytes_size = 16;
constexpr uint8_t aes_128_gcm_key_bytes[] = {0xc3, 0xae, 0x75, 0x09, 0xcf, 0xce,
                                             0xd2, 0xb8, 0x03, 0xa6, 0x18, 0x69,
                                             0x56, 0xcd, 0xa7, 0x9f};
constexpr std::size_t aes_256_gcm_key_bytes_size = 32;
constexpr uint8_t aes_256_gcm_key_bytes[] = {
    0xda, 0xc7, 0x31, 0xae, 0x48, 0x66, 0x67, 0x7e, 0xd2, 0xf6, 0x5c,
    0x49, 0x0e, 0x18, 0x81, 0x7b, 0xe5, 0xcb, 0xbb, 0xd0, 0x3f, 0x59,
    0x7a, 0xd5, 0x90, 0x41, 0xc1, 0x17, 0xb7, 0x31, 0x10, 0x9a};
constexpr std::size_t chacha_poly_key_bytes_size = 32;
constexpr uint8_t chacha_poly_key_bytes[] = {
    0x13, 0x0e, 0x20, 0x00, 0x50, 0x8a, 0xce, 0x00, 0xef, 0x26, 0x5e,
    0x17, 0x2d, 0x09, 0x89, 0x2e, 0x46, 0x72, 0x56, 0xcb, 0x90, 0xda,
    0xd9, 0xde, 0x99, 0x53, 0x3c, 0xf5, 0x48, 0xbe, 0x6a, 0x8b};
constexpr std::size_t aes_128_gcm_nonce_bytes_size = 12;
constexpr uint8_t aes_128_gcm_nonce_bytes[] = {
    0xb5, 0x80, 0x3d, 0x82, 0xad, 0x88, 0x54, 0xd2, 0xe5, 0x98, 0x18, 0x7f};
constexpr std::size_t aes_256_gcm_nonce_bytes_size = 12;
constexpr uint8_t aes_256_gcm_nonce_bytes[] = {
    0x4d, 0xb1, 0x52, 0xd2, 0x7d, 0x18, 0x0b, 0x1e, 0xe4, 0x8f, 0xa8, 0x9d};
constexpr std::size_t chacha_poly_nonce_bytes_size = 12;
constexpr uint8_t chacha_poly_nonce_bytes[] = {
    0xb5, 0x80, 0x3d, 0x82, 0xad, 0x88, 0x54, 0xd2, 0xe5, 0x98, 0x18, 0x7f};

/** The record_one vectors are obtained by encrypting the plaintext "123456"
 *  using the above keys and sequence number 0. **/
constexpr std::size_t aes_128_gcm_record_one_bytes_size = 28;
constexpr uint8_t aes_128_gcm_record_one_bytes[] = {
    0x17, 0x03, 0x03, 0x00, 0x17, 0xf2, 0xe4, 0xe4, 0x11, 0xac,
    0x67, 0x60, 0xe4, 0xe3, 0xf0, 0x74, 0xa3, 0x65, 0x74, 0xc4,
    0x5e, 0xe4, 0xc1, 0x90, 0x61, 0x03, 0xdb, 0x0d};
constexpr std::size_t aes_256_gcm_record_one_bytes_size = 28;
constexpr uint8_t aes_256_gcm_record_one_bytes[] = {
    0x17, 0x03, 0x03, 0x00, 0x17, 0x24, 0xef, 0xee, 0x5a, 0xf1,
    0xa6, 0x21, 0x70, 0xad, 0x5a, 0x95, 0xf8, 0x99, 0xd0, 0x38,
    0xb9, 0x65, 0x38, 0x6a, 0x1a, 0x7d, 0xae, 0xd9};
constexpr std::size_t chacha_poly_record_one_bytes_size = 28;
constexpr uint8_t chacha_poly_record_one_bytes[] = {
    0x17, 0x03, 0x03, 0x00, 0x17, 0xc9, 0x47, 0xff, 0xa4, 0x70,
    0x30, 0x43, 0x70, 0x33, 0x8b, 0xb0, 0x7c, 0xe4, 0x68, 0xe6,
    0xb8, 0xa0, 0x94, 0x4a, 0x33, 0x8b, 0xa4, 0x02};

/** The record_two vectors are obtained by encrypting the plaintext "789123456"
 *  using the above keys and sequence number 1. **/
constexpr std::size_t aes_128_gcm_record_two_bytes_size = 31;
constexpr uint8_t aes_128_gcm_record_two_bytes[] = {
    0x17, 0x03, 0x03, 0x00, 0x1a, 0xd7, 0x85, 0x3a, 0xfd, 0x6d, 0x7c,
    0xea, 0xab, 0xab, 0x95, 0x0a, 0x0b, 0x67, 0x07, 0x90, 0x5d, 0x2b,
    0x90, 0x88, 0x94, 0x87, 0x1c, 0x7c, 0x62, 0x02, 0x1f};
constexpr std::size_t aes_256_gcm_record_two_bytes_size = 31;
constexpr uint8_t aes_256_gcm_record_two_bytes[] = {
    0x17, 0x03, 0x03, 0x00, 0x1a, 0x83, 0x2a, 0x5f, 0xd2, 0x71, 0xb6,
    0x44, 0x2e, 0x74, 0xbc, 0x02, 0x11, 0x1a, 0x8e, 0x8b, 0x52, 0xa7,
    0x4b, 0x14, 0xdd, 0x3e, 0xca, 0x85, 0x98, 0xb2, 0x93};
constexpr std::size_t chacha_poly_record_two_bytes_size = 31;
constexpr uint8_t chacha_poly_record_two_bytes[] = {
    0x17, 0x03, 0x03, 0x00, 0x1a, 0x0c, 0xed, 0xeb, 0x92, 0x21, 0x70,
    0xc1, 0x10, 0xc1, 0x72, 0x26, 0x25, 0x42, 0xc6, 0x79, 0x16, 0xb7,
    0x8f, 0xa0, 0xd1, 0xc1, 0x26, 0x17, 0x09, 0xcd, 0x00};

/** The record_three vectors are obtained by encrypting the plaintext "7891"
 *  using the above keys and the sequence number 2. **/
constexpr std::size_t aes_128_gcm_record_three_bytes_size = 26;
constexpr uint8_t aes_128_gcm_record_three_bytes[] = {
    0x17, 0x03, 0x03, 0x00, 0x15, 0xaf, 0x77, 0x8b, 0xe,
    0xd6, 0x6e, 0xfe, 0xe7, 0x13, 0xfb, 0xed, 0xa2, 0x35,
    0x7b, 0x83, 0x2f, 0x75, 0x95, 0x00, 0xee, 0xcd};
constexpr std::size_t aes_256_gcm_record_three_bytes_size = 26;
constexpr uint8_t aes_256_gcm_record_three_bytes[] = {
    0x17, 0x03, 0x03, 0x00, 0x15, 0x96, 0xcb, 0x84, 0xcc,
    0x5d, 0xbd, 0x27, 0xa5, 0x13, 0xc6, 0xd2, 0x23, 0xcc,
    0x0f, 0x4a, 0x58, 0x40, 0xe1, 0x7e, 0x56, 0xd8};
constexpr std::size_t chacha_poly_record_three_bytes_size = 26;
constexpr uint8_t chacha_poly_record_three_bytes[] = {
    0x17, 0x03, 0x03, 0x00, 0x15, 0x92, 0x4a, 0x53, 0x43,
    0xcf, 0x1d, 0xc6, 0x95, 0x09, 0x49, 0x41, 0xab, 0xa1,
    0x6c, 0x6c, 0x24, 0x30, 0x5c, 0xc8, 0x40, 0x8a};

/** The following buffers are obtained by encrypting |decrypt_plaintext_1|
 *  using the crypter constructed in |setup_crypter| and the
 *  sequence number 0. **/
constexpr std::size_t decrypt_plaintext_1_size = 6;
constexpr uint8_t decrypt_plaintext_1[] = {'1', '2', '3', '4', '5', '6'};
constexpr std::size_t aes_128_gcm_decrypt_record_1_size = 28;
constexpr uint8_t aes_128_gcm_decrypt_record_1[] = {
    0x17, 0x03, 0x03, 0x00, 0x17, 0xf2, 0xe4, 0xe4, 0x11, 0xac,
    0x67, 0x60, 0xe4, 0xe3, 0xf0, 0x74, 0xa3, 0x65, 0x74, 0xc4,
    0x5e, 0xe4, 0xc1, 0x90, 0x61, 0x03, 0xdb, 0x0d};
constexpr std::size_t aes_256_gcm_decrypt_record_1_size = 28;
constexpr uint8_t aes_256_gcm_decrypt_record_1[] = {
    0x17, 0x03, 0x03, 0x00, 0x17, 0x24, 0xef, 0xee, 0x5a, 0xf1,
    0xa6, 0x21, 0x70, 0xad, 0x5a, 0x95, 0xf8, 0x99, 0xd0, 0x38,
    0xb9, 0x65, 0x38, 0x6a, 0x1a, 0x7d, 0xae, 0xd9};
constexpr std::size_t chacha_poly_decrypt_record_1_size = 28;
constexpr uint8_t chacha_poly_decrypt_record_1[] = {
    0x17, 0x03, 0x03, 0x00, 0x17, 0xc9, 0x47, 0xff, 0xa4, 0x70,
    0x30, 0x43, 0x70, 0x33, 0x8b, 0xb0, 0x7c, 0xe4, 0x68, 0xe6,
    0xb8, 0xa0, 0x94, 0x4a, 0x33, 0x8b, 0xa4, 0x02};

/** The following buffers are obtained by encrypting the alert message
 *  {SSL3_AL_WARNING, SSL3_AD_CLOSE_NOTIFY} using the crypter constructed in
 *  |setup_crypter| and the sequence number 0. **/
constexpr std::size_t aes_128_gcm_decrypt_close_notify_size = 24;
constexpr uint8_t aes_128_gcm_decrypt_close_notify[] = {
    0x17, 0x03, 0x03, 0x00, 0x13, 0xc2, 0xd6, 0xc2, 0x45, 0xfb, 0x80, 0x96,
    0x9d, 0xe1, 0xdd, 0x9d, 0x14, 0x49, 0x92, 0x61, 0xb6, 0x77, 0x35, 0xb0};
constexpr std::size_t aes_256_gcm_decrypt_close_notify_size = 24;
constexpr uint8_t aes_256_gcm_decrypt_close_notify[] = {
    0x17, 0x03, 0x03, 0x00, 0x13, 0x14, 0xdd, 0xc8, 0xf3, 0xb3, 0x85, 0x66,
    0x60, 0xbb, 0x5a, 0xc8, 0x15, 0x33, 0xc1, 0x57, 0x58, 0x2f, 0x8b, 0x4c};
constexpr std::size_t chacha_poly_decrypt_close_notify_size = 24;
constexpr uint8_t chacha_poly_decrypt_close_notify[] = {
    0x17, 0x03, 0x03, 0x00, 0x13, 0xf9, 0x75, 0xd9, 0xcb, 0x2f, 0x11, 0x6d,
    0x85, 0xd4, 0xe3, 0x85, 0x9f, 0x52, 0x88, 0xa9, 0xb0, 0x13, 0xd7, 0x78};

/** The following buffers are obtained by encrypting the alert message
 *  {SSL3_AL_WARNING, SSL3_AD_CERTIFICATE_REVOKED} using the crypter
 *  constructed in |setup_crypter| and the sequence number 0. **/
constexpr std::size_t aes_128_gcm_decrypt_alert_other_size = 24;
constexpr uint8_t aes_128_gcm_decrypt_alert_other[] = {
    0x17, 0x03, 0x03, 0x00, 0x13, 0xc2, 0xfa, 0xc2, 0x3f, 0x99, 0x5c, 0xbe,
    0x79, 0xa8, 0xd1, 0xe4, 0xc8, 0xf0, 0x35, 0x3a, 0xfe, 0xfe, 0xaa, 0xc9};
constexpr std::size_t aes_256_gcm_decrypt_alert_other_size = 24;
constexpr uint8_t aes_256_gcm_decrypt_alert_other[] = {
    0x17, 0x03, 0x03, 0x00, 0x13, 0x14, 0xf1, 0xc8, 0x0a, 0xdd, 0x85, 0x19,
    0x3c, 0x95, 0x98, 0x21, 0x9a, 0xe9, 0xdc, 0x26, 0xf2, 0x47, 0x9c, 0xcf};
constexpr std::size_t chacha_poly_decrypt_alert_other_size = 24;
constexpr uint8_t chacha_poly_decrypt_alert_other[] = {
    0x17, 0x03, 0x03, 0x00, 0x13, 0xf9, 0x59, 0xd9, 0x6f, 0xed, 0x92, 0xbd,
    0xc7, 0xe8, 0x5e, 0x04, 0xe8, 0x6c, 0x19, 0xea, 0xf1, 0x54, 0xb0, 0x52};

/** The following buffers are obtained by encrypting the alert message
 *  {SSL3_AL_WARNING} using the crypter constructed in
 *  |setup_crypter| and the sequence number 0. **/
constexpr std::size_t aes_128_gcm_decrypt_alert_small_size = 23;
constexpr uint8_t aes_128_gcm_decrypt_alert_small[] = {
    0x17, 0x03, 0x03, 0x00, 0x12, 0xc2, 0xc3, 0x51, 0xfc, 0x48, 0xd9, 0xac,
    0x84, 0xfa, 0x16, 0x5a, 0xdc, 0xc9, 0xa2, 0x6f, 0xfb, 0xc3, 0xc7};
constexpr std::size_t aes_256_gcm_decrypt_alert_small_size = 23;
constexpr uint8_t aes_256_gcm_decrypt_alert_small[] = {
    0x17, 0x03, 0x03, 0x00, 0x12, 0x14, 0xc8, 0x47, 0x61, 0x02, 0xa4, 0x60,
    0xb5, 0xcf, 0x9e, 0x9b, 0xa5, 0x9e, 0x17, 0x26, 0x21, 0x5c, 0xa9};
constexpr std::size_t chacha_poly_decrypt_alert_small_size = 23;
constexpr uint8_t chacha_poly_decrypt_alert_small[] = {
    0x17, 0x03, 0x03, 0x00, 0x12, 0xf9, 0x60, 0x6a, 0x83, 0xac, 0x17, 0xb1,
    0x65, 0xa5, 0x1f, 0x3f, 0xe7, 0x64, 0xda, 0x85, 0x60, 0xc7, 0x06};

/** The empty_record vectors are obtained by encrypting an empty plaintext using
 *  the above keys and the sequence number 0. **/
constexpr std::size_t aes_128_gcm_empty_record_bytes_size = 22;
constexpr uint8_t aes_128_gcm_empty_record_bytes[] = {
    0x17, 0x03, 0x03, 0x00, 0x11, 0xd4, 0x7c, 0xb2, 0xec, 0x04, 0x0f,
    0x26, 0xcc, 0x89, 0x89, 0x33, 0x03, 0x39, 0xc6, 0x69, 0xdd, 0x4e};
constexpr std::size_t aes_256_gcm_empty_record_bytes_size = 22;
constexpr uint8_t aes_256_gcm_empty_record_bytes[] = {
    0x17, 0x03, 0x03, 0x00, 0x11, 0x02, 0xa0, 0x41, 0x34, 0xd3, 0x8c,
    0x11, 0x18, 0xf3, 0x6b, 0x01, 0xd1, 0x77, 0xc5, 0xd2, 0xdc, 0xf7};
constexpr std::size_t chacha_poly_empty_record_bytes_size = 22;
constexpr uint8_t chacha_poly_empty_record_bytes[] = {
    0x17, 0x03, 0x03, 0x00, 0x11, 0xef, 0x8f, 0x7a, 0x42, 0x8d, 0xdc,
    0x84, 0xee, 0x59, 0x68, 0xcd, 0x63, 0x06, 0xbf, 0x1d, 0x2d, 0x1b};

constexpr std::size_t key_update_message_size = 5;
constexpr uint8_t key_update_message[] = {24, 0, 0, 1, 0};

constexpr std::size_t test_message_1_size = 0;
constexpr uint8_t test_message_1[] = {};

constexpr std::size_t test_message_2_size = 1;
constexpr uint8_t test_message_2[] = {8};

constexpr std::size_t test_message_3_size = 16;
constexpr uint8_t test_message_3[] = {46,  98, 101, 255, 213, 156, 15,  100,
                                      126, 45, 130, 239, 209, 13,  156, 89};

constexpr std::size_t message_encrypted_with_padded_zeros_size = 6;
constexpr uint8_t message_encrypted_with_padded_zeros[] = {'1', '2', '3',
                                                           '4', '5', '6'};

constexpr std::size_t aes_128_gcm_padded_zeros_record_size = 38;
constexpr uint8_t aes_128_gcm_padded_zeros_record[] = {
    23,  3,   3,   0,   33,  242, 228, 228, 17,  172, 103, 96,  232,
    71,  38,  228, 136, 109, 116, 50,  227, 155, 52,  240, 252, 207,
    193, 244, 85,  131, 3,   198, 138, 25,  83,  92,  15,  245};
constexpr std::size_t aes_256_gcm_padded_zeros_record_size = 38;
constexpr uint8_t aes_256_gcm_padded_zeros_record[] = {
    23,  3,   3,   0,   33,  36,  239, 238, 90,  241, 166, 33,  232,
    164, 209, 242, 105, 147, 14,  120, 53,  207, 221, 5,   226, 208,
    190, 197, 176, 26,  103, 222, 207, 166, 55,  44,  42,  247};
constexpr std::size_t chacha_poly_padded_zeros_record_size = 38;
constexpr uint8_t chacha_poly_padded_zeros_record[] = {
    23, 3,   3,   0,   33,  201, 71,  255, 164, 112, 48,  67,  240,
    99, 231, 182, 160, 81,  159, 189, 9,   86,  207, 58,  124, 151,
    48, 193, 53,  151, 238, 193, 126, 199, 231, 0,   241, 64};

constexpr uint8_t aes_128_gcm_in_key_1[] = {
    221, 233, 95,  58,  247, 237, 190, 58, 8,   91, 130,
    27,  91,  178, 32,  41,  78,  82,  35, 250, 40, 194,
    227, 191, 72,  157, 222, 153, 106, 15, 179, 68};
constexpr uint8_t aes_128_gcm_out_key_1[] = {
    101, 104, 22,  206, 9,   92,  48,  89,  77, 139, 113,
    55,  106, 203, 81,  144, 147, 143, 199, 92, 242, 210,
    220, 165, 253, 241, 175, 177, 192, 247, 34, 32};
constexpr uint8_t aes_128_gcm_in_key_2[] = {
    45,  191, 35,  6,   211, 54,  64,  34,  16,  160, 124,
    227, 30,  108, 255, 139, 243, 205, 213, 95,  29,  54,
    137, 229, 142, 105, 146, 162, 179, 117, 138, 10};
constexpr uint8_t aes_128_gcm_out_key_2[] = {
    195, 226, 19,  233, 63,  173, 68, 102, 104, 182, 40,
    115, 134, 114, 148, 212, 10,  54, 217, 236, 211, 195,
    130, 116, 78,  159, 44,  120, 17, 233, 28,  157};
constexpr uint8_t aes_128_gcm_in_key_3[] = {
    232, 65, 149, 12,  191, 158, 201, 184, 2,  53, 9,   8,  115, 96,  118, 189,
    197, 56, 52,  242, 98,  27,  58,  134, 86, 42, 112, 72, 221, 180, 102, 152};
constexpr uint8_t aes_128_gcm_out_key_3[] = {
    118, 150, 31,  64,  217, 43,  70,  144, 40,  144, 61,
    49,  178, 27,  177, 125, 25,  39,  105, 241, 0,   59,
    213, 177, 201, 28,  105, 144, 235, 122, 218, 239};
constexpr uint8_t aes_128_gcm_in_key_4[] = {
    197, 186, 142, 248, 187, 8,   128, 198, 135, 246, 161,
    237, 146, 188, 53,  112, 203, 11,  108, 208, 39,  156,
    111, 79,  166, 139, 180, 214, 118, 246, 66,  159};
constexpr uint8_t aes_128_gcm_out_key_4[] = {
    115, 24,  42,  69,  59,  123, 156, 116, 53,  56,  43,
    204, 240, 239, 6,   138, 21,  103, 121, 153, 249, 96,
    187, 107, 2,   206, 39,  247, 36,  14,  196, 226};

/** The following records contain the alert message {SSL3_AL_WARNING,
 *  SSL3_AD_CLOSE_NOTIFY} encrypted using the crypter constructed in
 *  |setup_crypter| and the sequence number 0. **/
constexpr std::size_t aes_128_gcm_alert_with_padding_size = 34;
constexpr uint8_t aes_128_gcm_alert_with_padding[] = {
    23,  3,   3,   0,   29,  194, 214, 194, 37,  153, 81,  119,
    232, 71,  38,  228, 136, 109, 94,  167, 147, 131, 229, 213,
    41,  205, 131, 57,  251, 191, 202, 254, 36,  24};
constexpr std::size_t aes_256_gcm_alert_with_padding_size = 34;
constexpr uint8_t aes_256_gcm_alert_with_padding[] = {
    23,  3,   3,   0,   29,  20,  221, 200, 110, 196, 144, 54,
    232, 164, 209, 242, 105, 147, 53,  69,  240, 59,  15,  233,
    255, 216, 176, 42,  205, 30,  65,  247, 19,  158};
constexpr std::size_t chacha_poly_alert_with_padding_size = 34;
constexpr uint8_t chacha_poly_alert_with_padding[] = {
    23,  3,  3,   0,   29,  249, 117, 217, 144, 69,  6,   84,
    240, 99, 231, 182, 160, 81,  76,  39,  20,  201, 130, 126,
    121, 96, 113, 56,  152, 2,   244, 81,  88,  90};

/** The following records contain the key update message encrypted using the
 *  crypter constructed in |setup_crypter| and the sequence number 0. **/
constexpr std::size_t aes_128_gcm_key_update_with_padding_size = 37;
constexpr uint8_t aes_128_gcm_key_update_with_padding[] = {
    23, 3,  3,   0,   32,  219, 214, 215, 36,  153, 71, 119, 232,
    71, 38, 228, 136, 109, 116, 50,  227, 17,  167, 59, 66,  208,
    7,  63, 40,  234, 96,  227, 14,  142, 180, 152, 253};
constexpr std::size_t aes_256_gcm_key_update_with_padding_size = 37;
constexpr uint8_t aes_256_gcm_key_update_with_padding[] = {
    23,  3,   3,   0,   32,  13,  221, 221, 111, 196, 134, 54,  232,
    164, 209, 242, 105, 147, 14,  120, 53,  173, 192, 126, 115, 43,
    167, 253, 97,  127, 249, 166, 90,  81,  195, 107, 109};
constexpr std::size_t chacha_poly_key_update_with_padding_size = 37;
constexpr uint8_t chacha_poly_key_update_with_padding[] = {
    23, 3,   3,   0,   32,  224, 117, 204, 145, 69,  16,  84,  240,
    99, 231, 182, 160, 81,  159, 189, 9,   142, 131, 189, 164, 181,
    21, 190, 165, 25,  108, 204, 192, 8,   85,  106, 208};

constexpr std::size_t aes_128_gcm_advanced_record_size = 28;
constexpr uint8_t aes_128_gcm_advanced_record[] = {
    0x17, 0x03, 0x03, 0x00, 0x17, 0xdd, 0x99, 0xeb, 0xef, 0x48,
    0x29, 0x2c, 0xd4, 0xc3, 0x72, 0xa0, 0x00, 0x74, 0x03, 0x72,
    0xd2, 0xae, 0x9a, 0xad, 0x31, 0xcf, 0xd2, 0x74};
constexpr std::size_t aes_256_gcm_advanced_record_size = 28;
constexpr uint8_t aes_256_gcm_advanced_record[] = {
    0x17, 0x03, 0x03, 0x00, 0x17, 0x9c, 0xd5, 0x97, 0x2e, 0x76,
    0xba, 0xf5, 0x6a, 0xf6, 0x44, 0xc9, 0x22, 0x35, 0x46, 0x03,
    0x01, 0xc0, 0xa0, 0x13, 0xad, 0x35, 0xbe, 0x00};
constexpr std::size_t chacha_poly_advanced_record_size = 28;
constexpr uint8_t chacha_poly_advanced_record[] = {
    0x17, 0x03, 0x03, 0x00, 0x17, 0xc4, 0xe4, 0x8c, 0xca, 0xf0,
    0x36, 0xbd, 0x9b, 0xc1, 0x46, 0xbb, 0xc6, 0x19, 0x24, 0x04,
    0xf9, 0xa2, 0xd2, 0xda, 0x5d, 0x1a, 0xfe, 0x78};

}  // namespace s2a_test_data

#endif  // TEST_UTIL_S2A_TEST_DATA_H_
