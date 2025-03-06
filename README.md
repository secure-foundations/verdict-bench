Verdict Evaluation
---

This directory contains code for the Verdict evaluation.
There are three main evaluations:
- Eval 1: Performance benchmark against Chrome, Firefox, OpenSSL, ARMOR, CERES, and Hammurabi.
- Eval 2: Differential testing with Chrome, Firefox, OpenSSL
- Eval 3: End-to-End HTTPS performance in Rustls

Note that for Evals 1 and 2, we do not have the 10M chains from CT logs publically available,
so you might need to prepare your own test cases in the following directory structure:
```
test_suite/
  - certs/
      - test1.csv
      - test2.csv
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

Benchmark Verdict against X.509 implementations in Chrome, Firefox, OpenSSL,
as well as academic work ARMOR, CERES, and Hammurabi.

Dependencies:
- Docker 27.3.1
- Python 3.12 (w/ pip and venv)
- Cargo 1.82.0

Other versions might work too.

## Build

First run the following command to build harnesses for implementations other than Verdict:
```
make deps
```
This will take a long time since it needs to download and build large projects such as Chromium and Firefox.
Note that this command won't install random stuff to your host system, and all dependencies are installed within a Docker container.
On our test machine, this took 1.5 hours.
This target also uses `sudo` when calling docker.

Then run an implementation on the CT logs by
```
make bench-<impl> CT_LOG=...
```
where
- `<impl>` is one of `verdict-<chrome/firefox/openssl>`, `chrome`, `firefox`, `openssl`, `armor`, `ceres`, `hammurabi`
- `CT_LOG` specifies the main CT logs directory.

# Eval 2

First download `limbo.json` from the [x509-limbo](https://github.com/C2SP/x509-limbo) test suite.

Then compile Verdict by
```
cd verdict && cargo build --release
```
You can follow `verdict/README.md` for how to run Verus on it, but this command only compiles without verification.

Then let `<harness>` be any of `verdict-<chrome/firefox/openssl>`, `chrome`, `firefox`, `openssl`, `armor`, `ceres`, `hammurabi`, run
```
verdict/target/release/frontend limbo <harness> <path to limbo.json> --bench-repo . -j 32 > results.txt
```
to evaluate `<harness>` on x509-limbo (and output to `results.txt`).

To compare results from different harnesses:
```
verdict/target/release/frontend diff-results results1.txt results2.txt
```

# Eval 3

See `rustls/README.md`.

# Standalone Image

For better reproducibility, we also include a `standalone.Dockerfile`
to build a Docker image containing all required tools.

To build this image, run
```
git submodule update --init --recursive
docker build -f standalone.Dockerfile . -t verdict-bench
```

This requires an X86-64 CPU and around 120 GB of free disk space.
The build process takes roughly 50 minutes on our test machine.
