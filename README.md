Chromium
---

This repo compiles Chromium source code at a specific commit, along with
our custom benchmarking tool `cert_bench`.

Currently it is set up to build Chromium at a version around Aug, 2020 (590dcf7b)
(hence using `ubuntu:20.04` in the Docker image).

# Usage

Run `make release`, which will download the Chromium source code, apply our `cert_bench.diff`,
and compile the tool to `src/out/Release/cert_bench`.

NOTE: right now `make release` calls Docker with `sudo docker`.

# Development

After the first successful `make release`, the source tree should be set up.
Make changes as you wish in `src`, and then save all the changes by
```
make enter
git add ...
make cert_bench.diff
```
