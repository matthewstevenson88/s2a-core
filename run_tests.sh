#!/bin/bash

# Fail on any error.
set -e

bazel build ...
bazel test --test_output=errors -- ...
