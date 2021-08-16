This doc outlines how to do various maintenance tasks around the repository.

## How to update the UPB dependency ?

To update the UPB dependency to a specific commit hash X, you need to update
the WORKSPACE file and the git submodule. To do the latter, run the following:

```
cd third_party/upb
git pull
git checkout X
cd../..
git add third_party/upb
git commit -m "Update UPB dep."
```

After the above, you must regenerate the UPB files in the
s2a/src/proto/upb-generated/s2a/src/proto directory. This can be done by running
the following script :

```
tools/upb/generate_upb_files.sh
```

Note that this script uses your machine's Bazel binary, and it requires
reasonable recent Bazel versions. If one sees errors related to e.g. `rules_cc`
not found, this is an indication that you should update your Bazel to a newer version.
