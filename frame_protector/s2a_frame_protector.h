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

#ifndef FRAME_PROTECTOR_S2A_FRAME_PROTECTOR_H_
#define FRAME_PROTECTOR_S2A_FRAME_PROTECTOR_H_

#include <string>

#include "channel/s2a_channel_factory_interface.h"
#include "options/s2a_options.h"
#include "record_protocol/s2a_crypter.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/synchronization/mutex.h"
#include "absl/types/variant.h"

namespace s2a {
namespace frame_protector {

class S2AFrameProtector {
 public:
  // TODO(matthewstevenson88) Move |Iovec| definition to here.

  struct S2AFrameProtectorOptions {
    s2a_options::S2AOptions::TlsVersion tls_version;
    s2a_options::S2AOptions::Ciphersuite tls_ciphersuite;
    std::vector<uint8_t> in_traffic_secret;
    std::vector<uint8_t> out_traffic_secret;
    uint64_t in_sequence;
    uint64_t out_sequence;
    const std::string& handshaker_service_url;
    const s2a_options::S2AOptions::Identity& local_identity;
    uint64_t connection_id;
    std::unique_ptr<s2a_channel::S2AChannelFactoryInterface> channel_factory;
    std::unique_ptr<
        s2a_channel::S2AChannelFactoryInterface::S2AChannelOptionsInterface>
        channel_options;
    std::function<aead_crypter::Iovec(size_t)> allocator;
    std::function<void(aead_crypter::Iovec)> destroy;
    std::function<void(const std::string&)> logger;
  };

  struct Result {
    absl::Status status;
    std::vector<aead_crypter::Iovec> bytes;
  };

  static absl::StatusOr<std::unique_ptr<S2AFrameProtector>> Create(
      S2AFrameProtectorOptions& options);

  // |Protect| divides the plaintext in |unprotected_bytes| into blocks,
  // encrypts each block, and wraps the block into a TLS record. The TLS records
  // are concatenated and written to the buffer returned in the |Result|. This
  // buffer is allocated using |allocator_| and must be destroyed by calling
  // |destroy_|.
  //
  // |Protect| should not be called multiple times concurrently; however,
  // |Protect| and |Unprotect| may be called concurrently.
  Result Protect(const std::vector<aead_crypter::Iovec>& unprotected_bytes);

  // |Protect| divides the plaintext in |unprotected_bytes| into blocks,
  // encrypts each block, and wraps the block into a TLS record. The TLS records
  // are concatenated and written to |protected_bytes|. The caller must ensure
  // that |protected_bytes.iov_len| is at least
  // |NumberBytesToProtect(unprotected_bytes)|.
  //
  // |Protect| should not be called multiple times concurrently; however,
  // |Protect| and |Unprotect| may be called concurrently.
  absl::Status Protect(
      const std::vector<aead_crypter::Iovec>& unprotected_bytes,
      aead_crypter::Iovec& protected_bytes);

  // |Unprotect| divides the bytes in |protected_bytes| into TLS records,
  // unwraps each TLS record, and decrypts the ciphertext. The resulting
  // plaintexts are concatenated and written to the buffer returned in |Result|.
  // This buffer is allocated using |allocator_| and must be destroyed by
  // calling |destroy_|.
  //
  // The implementation of |Unprotect| assumes that |protected_bytes| consists
  // of one or more complete TLS records concatenated together. In particular,
  // if |protected_bytes| contains a partial TLS record, then |Unprotect| will
  // return an error status.
  //
  // |Unprotect| should not be called multiple times concurrently; however,
  // |Protect| and |Unprotect| may be called concurrently.
  Result Unprotect(const std::vector<aead_crypter::Iovec>& protected_bytes);

  // |Unprotect| unwraps the TLS stored in |protected_bytes|, and decrypts the
  // ciphertext. The resulting plaintext is written to |unprotected_bytes|. The
  // caller must ensure that |unprotected_bytes.iov_len| is at least
  // |NumberBytesToUnprotect(protected_bytes)|.
  //
  // The implementation of |Unprotect| assumes that |protected_bytes| consists
  // of exactly one TLS record. In particular, if |protected_bytes| contains a
  // partial TLS record or more than one TLS record, then |Unprotect| will
  // return an error status.
  //
  // |Unprotect| should not be called multiple times concurrently; however,
  // |Protect| and |Unprotect| may be called concurrently.
  absl::Status Unprotect(
      const std::vector<aead_crypter::Iovec>& protected_bytes,
      aead_crypter::Iovec& unprotected_bytes);

  // |MaxRecordSize| returns the max size (in bytes) of a single TLS record that
  // this frame protector may construct.
  size_t MaxRecordSize() const;

  // |NumberBytesToProtect| returns the number of bytes required to hold the TLS
  // records resulting from protecting the bytes in |unprotected_bytes|.
  size_t NumberBytesToProtect(
      const std::vector<aead_crypter::Iovec>& unprotected_bytes) const;

  // |NumberBytesToProtect| returns the number of bytes required to hold the TLS
  // records resulting from protecting |unprotected_bytes_length| bytes.
  size_t NumberBytesToProtect(size_t unprotected_bytes_length) const;

  // |NumberBytesToUnprotect| returns the number of bytes required in a
  // contiguous buffer in order to unprotect the TLS records stored in
  // |protected_bytes|.
  size_t NumberBytesToUnprotect(
      const std::vector<aead_crypter::Iovec>& protected_bytes) const;

  // |NumberBytesToUnprotect| returns the number of bytes required in a
  // contiguous buffer in order to unprotect a TLS record consisting of
  // |record_length| bytes.
  size_t NumberBytesToUnprotect(size_t record_length) const;

 private:
  S2AFrameProtector(std::function<aead_crypter::Iovec(size_t)> allocator,
                    std::function<void(aead_crypter::Iovec)> destroy,
                    std::function<void(const std::string&)> logger,
                    std::unique_ptr<record_protocol::S2ACrypter> crypter);

  const std::function<aead_crypter::Iovec(size_t)> allocator_;
  const std::function<void(aead_crypter::Iovec)> destroy_;
  const std::function<void(const std::string&)> logger_;
  const size_t max_record_size_;

  // |protect_mu_| guards against concurrent calls to |Protect|.
  absl::Mutex protect_mu_;
  // |unprotect_mu_| guards against concurrent calls to |Unprotect|.
  absl::Mutex unprotect_mu_;
  std::unique_ptr<record_protocol::S2ACrypter> crypter_;
};

}  // namespace frame_protector
}  //  namespace s2a

#endif  // FRAME_PROTECTOR_S2A_FRAME_PROTECTOR_H_
