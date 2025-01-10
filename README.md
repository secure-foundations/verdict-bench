Verified X.509 Certificate Validation
---

To build, first run (Bash or Zsh)
```
. tools/activate.sh
```
This will first compile a vendored version of Verus, and then
provide a command `vargo` with the same usage as `cargo`.

To verify and build the entire project, run
```
vargo build --release
```
Then use `target/release/frontend` to validate certificate chains or run benchmarks.
See `target/release/frontend --help` for details.

By default, we only use crypto primitives that are verified from [libcrux](https://github.com/cryspen/libcrux) and [aws-lc-rs](https://github.com/aws/aws-lc-rs).
To use primitives entirely from `aws-lc-rs` which might have better performance but include unverified signature checking for RSA and ECDSA P-256,
compile with
```
vargo build --release --feature aws-lc
```

To run some sanity checks
```
vargo test --workspace
```
