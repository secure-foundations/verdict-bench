Firefox
---

This repo compiles Firefox source code at a specific commit around Aug, 2020.

# Usage

Run `make build` -- this might take more than 20 min.
Then run
```
./cert_bench.sh <roots.pem> <chain.pem> <domain> <timestamp> <repeat>
```
to benchmark validation of a chain.
