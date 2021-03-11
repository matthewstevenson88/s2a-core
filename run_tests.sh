#!/bin/bash

# Fail on any error.
set -e
# Display commands being run.
set -x

fail_with_debug_output() {
  ls -l
  df -h /
  exit 1
}

run_tests() {
  local -a TEST_FLAGS=( --strategy=TestRunner=standalone --test_output=all )
  readonly TEST_FLAGS
  (
    time bazel build -- ... || fail_with_debug_output
    time bazel test "${TEST_FLAGS[@]}" -- ... || fail_with_debug_output
  )
}

install_protoc_for_macos() {
  local protoc_version='3.14.0'
  local protoc_zip="protoc-${protoc_version}-osx-x86_64.zip"
  local protoc_url="https://github.com/protocolbuffers/protobuf/releases/download/v${protoc_version}/${protoc_zip}"
  local -r protoc_tmpdir=$(mktemp -dt s2a-core-protoc.XXXXXX)
  (
    cd "${protoc_tmpdir}"
    curl -OL "${protoc_url}"
    unzip ${protoc_zip} bin/protoc
  )
  export PATH="${protoc_tmpdir}/bin:${PATH}"
}

main() {
  if [[ -n "${KOKORO_ROOT}" ]]; then
    use_bazel.sh latest
    install_protoc_for_macos
  fi

  echo "using bazel binary: $(which bazel)"
  bazel version

  echo "using protoc: $(which protoc)"
  protoc --version

  run_tests
}

main "$@"
