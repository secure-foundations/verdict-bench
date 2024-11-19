Chromium
---

This repo sets up Chromium source code at a specific commit and then
builds a Docker image to be the build environment. This allows building
Chromium at a much older version with different build toolchains.

Currently it is set up to build Chromium at a version around Aug, 2020
(hence using `ubuntu:20.04` in the Docker image).

# Usage

Run `make debug`, which downloads the Chromium source code, adds our `cert_bench.diff`,
and compiles it (to `src/out/Debug/cert_bench`).

# Development

After the first successful `make debug`, the source tree should be set up.
Make changes as you wish in `src`, and then save all the changes by `make enter`,
`git add ...`, and run `make cert_bench.diff`.
