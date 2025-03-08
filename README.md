Verdict Evaluation
---

This directory contains code for the Verdict evaluation.
There are three main evaluations:
- Eval 1: Performance benchmark against Chrome, Firefox, OpenSSL, ARMOR, CERES, and Hammurabi.
- Eval 2: Differential testing with Chrome, Firefox, OpenSSL
- Eval 3: End-to-End HTTPS performance in Rustls

# TL;DR

```
$ git submodule update --init --recursive
$ docker build . -t verdict-bench
$ docker run -it --cap-add=NET_ADMIN verdict-bench
(container) $ make eval
```

Running `make eval` again will print out the results again.

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
docker run -it --cap-add=NET_ADMIN verdict-bench
```
`--cap-add=NET_ADMIN` is required for the network delay setup in Eval 3.

To make sure that all benchmarks work correctly, run `make test` in the container.

### Build a particular tool
To build a particular X.509 tool, run
```
docker build . --target <tool>-install --output type=tar | (mkdir -p build && tar -C build -x)
```
where <tool> is one of `chromium`, `firefox`, `armor`, `ceres`, `hammurabi`, `openssl`, `verdict`.
The suitable build output will be copied to `build/<tool>` (e.g. `build/chromium/src/out/Release/cert_bench` for Chromium).

### Harness development

To modify the benchmark harnesses, consider doing `cd <tool> && make` instead of using the Docker image.
Note however that some dependencies need to be installed on the host system.

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

Then in all the evaluations below, set an additional variable `CT_LOG=test_suite` for each `make` command.

# Eval 1: Performance

To run performance benchmarks on all supported tools:
```
make eval-1
```

At the end, a LaTeX table of performance statistics will be printed.
A PDF containing boxplots of more detailed performance distribution will also be stored at `results/performance.pdf`

To run individual benchmarks, use
```
make results/bench-<tool>.csv
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
The results will be saved to `results/bench-<tool>.csv`.
Note that, as also mentioned in the paper, for ARMOR and CERES, we only sample about 0.1% of the given test cases;
and for Hammurabi, we only sample 1% of all test cases.
To override these settings, make suitable adjustments in `Makefile`.

# Eval 2: Differential Testing

To run all differential tests (comparison of Verdict's Chrome, Firefox,
and OpenSSL policies against their original implementations), run
```
make eval-2
```

At the end, a LaTeX table containing results will be printed.
More detailed results can be found in `results/diff-<tool>.csv` (differential tests on CT logs),
and `results/limbo-<tool>.csv` (differential tests on [x509-limbo](https://github.com/C2SP/x509-limbo)).

Similar to Eval 1, to run individual tests, run
```
make results/diff-<tool>.csv
```
or
```
make results/limbo-<tool>.csv
```

# Eval 3: End-to-End Performance

To run end-to-end performance tests with Rustls, use
```
make eval-3 [END_TO_END_DELAY=5ms] [END_TO_END_WARMUP=20] [END_TO_END_REPEAT=100]
```
This will run Rustls's `tlsclient-mio` to simulate fetching the first HTTPS response from public domains
(these domains are simulated locally).
The results will be saved to `results/end-to-end-*.csv`, and a summarizing table will be printed at the end.
