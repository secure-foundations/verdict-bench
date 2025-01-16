Rustls + Verdict HTTPS Performance Bench
---

This repo contains code to test Rustls's performance in making HTTPS requests to popular domains (according to the [Tranco](https://tranco-list.eu/) list).

We are using the Tranco list generated on Jan 13, 2024.

## Usage

To run the same evaluation in the paper, do the following steps:
```
# Install Python dependencies
python3 -m venv .venv
. .venv/bin/activate
pip3 install -r requirements.txt

# Build modified Rustls
# The optional feature flag enables more performant, but unverified crypto primitives from AWS-LC
git submodule update --init
cd rustls && cargo build --release [--features rustls/verdict-aws-lc]

# Test all domains and compare results of Verdict + Rustls vs. the baseline Rustls
python3 test_end_to_end.py test_data rustls/target/release/tlsclient-mio --port 1234 --delay 5ms
```

## Scripts

`fake_server_certs.py` takes a list of domains and a root store.
It first tries to make HTTPS request to each `https://<domain>/`, and fetch their HTTP responses and certificate chains.
It then replaces the public key in each certificate (including relevant roots) with freshly generated keys (along with private keys),
so that we can later mimic a public server with almost the same certificate chain.
`test_data` contains the results of running `fake_server_certs.py` on the first 100 domains in the list `top-1M-01-13-2024.txt` (skipping ones where the HTTPS request was unsuccessful).

`fake_server.py` takes one of the results from `fake_server_certs.py`, and then mimics the server locally.

`test_end_to_end.py` is a wrapper on top of `fake_server.py`, it iterates through all domains and
1. Starts `fake_server.py`
2. Use a modified version of Rustls (in `rustls/`) to make an HTTPS request to the fake server.
Before testing, it also calls `tc` to set a fixed, simulated network delay on the server port at localhost (by default 5 ms).
