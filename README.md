Chromium
---

This repo compiles Chromium source code at a specific commit, along with
our custom benchmarking tool `cert_bench`.

Currently it is set up to build Chromium at a version around Aug, 2020 (590dcf7b)
(hence using `ubuntu:20.04` in the Docker image).

# Usage

Run `make debug`, which will download the Chromium source code, apply our `cert_bench.diff`,
and compile the tool to `src/out/Debug/cert_bench`.

# Development

After the first successful `make debug`, the source tree should be set up.
Make changes as you wish in `src`, and then save all the changes by
```
make enter
git add ...
make cert_bench.diff
```
