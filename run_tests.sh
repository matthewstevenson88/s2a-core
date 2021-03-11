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

main() {
  if [[ -n "${KOKORO_ROOT}" ]]; then
    use_bazel.sh latest
  fi

  echo "using bazel binary: $(which bazel)"
  bazel version

  echo "using protoc: $(which protoc)"
  protoc --version

  run_tests
}

main "$@"
