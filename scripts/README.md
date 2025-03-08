Scripts
---

This directory contains some scripts used for preparing evaluation and analyzing the results.

- `perf_results.py` generates a table and boxplots containing performance stats
- `diff_results.py` generates a table containing differential testing results
- `rustls_results.py` generates the results of end-to-end performance tests in Rustls

- `fake_server_certs.py` is used for cloning server certificate chains and root certificates of public servers.
    It takes a list of domains and a root store.
    It first tries to make HTTPS request to each `https://<domain>/`, and fetch their HTTP responses and certificate chains.
    It then replaces the public key in each certificate (including relevant roots) with freshly generated keys (along with private keys),
    so that we can later mimic a public server with almost the same certificate chain.
    `data/end-to-end` contains the results of running `fake_server_certs.py` on the first 100 domains in the list `data/top-1M-01-13-2025.txt`
    (the Tranco list generated on Jan 13, 2025), skipping ones where the HTTPS request was unsuccessful.

- `fake_server.py` takes one of the results from `fake_server_certs.py`, and then mimics the server locally.

- `rustls_end_to_end.py` takes the results from `fake_server_certs.py`, and iterates through all domains and
    1. Starts `fake_server.py`
    2. Use a modified version of Rustls (in `rustls/`) to make an HTTPS request to the fake server.
    Before testing, it also calls `tc` to set a fixed, simulated network delay on the server port at localhost (by default 5 ms).
