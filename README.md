Verdict Evaluation
---

This directory contains code for the Verdict evaluation.
There are three main evaluations:
- Eval 1: Performance benchmark against Chrome, Firefox, OpenSSL, ARMOR, CERES, and Hammurabi.
- Eval 2: Differential testing with Chrome, Firefox, OpenSSL
- Eval 3: End-to-End HTTPS performance in Rustls

# Build

If you do not need to edit the benchmarking code in any of the tools, the recommended
build method is to use Docker.

First run the following to load all git submodules:
```
git submodule update --init --recursive
```

Then run the following to compile all tools and build a standalone image
containing all necessary dependencies:
```
docker build . -t verdict-bench
```
This will take a while, since we need to build large projects such as Firefox and Chromium.
On our test machine with the Intel Core i9-10980XE CPU,
the entire build process took **about 1 hour and 120 GB of free disk space**.

The rest of the tutorial assumes that you are in the Docker container:
```
docker run -it verdict-bench
```

### Build a particular tool
To build a particular X.509 tool, run
```
docker build . --target <tool>-install --output TODO
```
where <tool> is one of `chromium`, `firefox`, `armor`, `ceres`, `hammurabi`, `openssl`, `verdict`.
This will output the final binaries of the built tool to the output directory `<output>`.

# Note on CT logs
Note that for Evals 1 and 2, we do not have the full benchmark set of 10M chains from CT logs publically available,
but there is a sample of 35,000 chains located in `data/ct-log`.

In general, you can also prepare your own test cases in the following directory structure:
```
test_suite/
  - certs/
      - cert-list-part-xx.txt
      - cert-list-part-xx.txt
      ...
  - ints/
      - int1.pem
      - int2.pem
      ...
```
where each CSV file in `test_suite/certs` should have columns (without headers)
```
<Base64 encoding of the leaf>,<SHA256 hash of the leaf>,<hostname>,<comma separated list of intermediates, e.g. int1,int2>
```

# Eval 1

Use
```
make bench-<tool>
```
to run `<tool>` on the sample of 35,000 chains in `data/ct-log`,
where `<tool>` is one of:
- `verdict-chrome`, `verdict-firefox`, `verdict-openssl` (normal versions of Verdict using verified crypto primitives)
- `verdict-chrome-aws-lc`, `verdict-firefox-aws-lc`, `verdict-openssl-aws-lc` (Verdict using unverified crypto primitives from AWS-LC)
- `chromium`
- `firefox`
- `armor`
- `ceres`
- `hammurabi-chrome`, `hammurabi-firefox` (Hammurabi's Chrome and Firefox policies)
- `openssl`

This target will output to `results/bench-<tool>.csv`.

# Eval 2

Use
```
make limbo-<tool>
```
to run `<tool>` on the [x509-limbo](https://github.com/C2SP/x509-limbo) test suite (local copy at `data/limbo.json`).
The output can be found in `results/limbo-<tool>.csv`.

# Eval 3

Currently this is separate from the Docker image.
See `rustls/README.md` for details on how to run this evaluation.
