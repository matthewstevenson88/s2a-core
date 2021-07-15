workspace(name = "com_google_s2a_core")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# Abseil
http_archive(
  name = "com_google_absl",
  strip_prefix = "abseil-cpp-64461421222f8be8663c50e8e82c91c3f95a0d3c",
  url = "https://github.com/abseil/abseil-cpp/archive/64461421222f8be8663c50e8e82c91c3f95a0d3c.zip",
  sha256 = "41d725950d0d3ed4d00020881db84fdc79ac349d9b325ab010686c5a794a822e",
)

# Googletest
http_archive(
    name = "com_google_googletest",
    sha256 = "ff7a82736e158c077e76188232eac77913a15dac0b22508c390ab3f88e6d6d86",
    strip_prefix = "googletest-b6cd405286ed8635ece71c72f118e659f4ade3fb",
    urls = ["https://github.com/google/googletest/archive/b6cd405286ed8635ece71c72f118e659f4ade3fb.zip"]
)

# UPB
http_archive(
    name = "upb",
    sha256 = "0d240a335f61e8acc22849280668b9203d25e6616df18bcc96d13bee65bbfebc",
    strip_prefix = "upb-0723bfa700a044b1062d3db688b810455b19322e",
    urls = ["https://github.com/protocolbuffers/upb/archive/0723bfa700a044b1062d3db688b810455b19322e.tar.gz"],
)

load("@upb//bazel:workspace_deps.bzl", "upb_deps")
upb_deps()

# BoringSSL
http_archive(
    name = "boringssl",
    strip_prefix = "boringssl-597b810379e126ae05d32c1d94b1a9464385acd0",
    url = "https://github.com/google/boringssl/archive/597b810379e126ae05d32c1d94b1a9464385acd0.zip",
    sha256 = "c4e8414cb36e62d2fee451296cc864f7ad1a4670396c8a67e1ee77ae84cc4167",
)

# Rules foreign, needed to convert OpenSSL CMake to Bazel.
http_archive(
    name = "rules_foreign_cc",
    sha256 = "d54742ffbdc6924f222d2179f0e10e911c5c659c4ae74158e9fe827aad862ac6",
    strip_prefix = "rules_foreign_cc-0.2.0",
    url = "https://github.com/bazelbuild/rules_foreign_cc/archive/0.2.0.tar.gz",
)

load("@rules_foreign_cc//foreign_cc:repositories.bzl", "rules_foreign_cc_dependencies")
rules_foreign_cc_dependencies()

_ALL_CONTENT = """filegroup(name = "all", srcs = glob(["**"]), visibility = ["//visibility:public"])"""

# OpenSSL
http_archive(
    name = "openssl",
    build_file_content = _ALL_CONTENT,
    strip_prefix = "openssl-OpenSSL_1_1_1f",
    urls = ["https://github.com/openssl/openssl/archive/OpenSSL_1_1_1f.tar.gz"]
)

