Verdict Benchmarks
---

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
