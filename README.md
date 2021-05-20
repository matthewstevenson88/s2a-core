#Secure Session Agent Client Libraries

The Secure Session Agent (S2A) is a service that enables a workload to offload mTLS
handshakes and protects a workload's private key material from exfiltration. The
Secure Session Agent's client libraries enable applications to communicate with
the Secure Session Agent during the TLS handshake, and to encrypt traffic to the
peer after the TLS handshake is complete. For more details on the Secure Session
Agent model, see
[ABOUT.md](https://github.com/google/s2a-core/blob/main/ABOUT.md).

This repository contains the source code for the Secure Session Agent's C++
client libraries. These libraries are agnostic to the SSL libraries installed on
a user's machine: indeed, they are compatible with both BoringSSL and OpenSSL.
Furthermore, the C++ client libraries are low-dependency (depending only on
C++11, [Abseil](https://abseil.io/),
[UPB](https://github.com/protocolbuffers/upb),
[Googletest](https://github.com/google/googletest), and BoringSSL/OpenSSL) and
offer Bazel and CMake support.

All code in this repository is experimental and subject to change. We do not
guarantee API stability at this time.
