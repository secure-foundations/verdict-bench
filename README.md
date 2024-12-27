Verified X.509 Certificate Validation
---

To build, first run (Bash or Zsh)
```
. tools/activate.sh
```

A command `vargo` will be available,
and its usage is exactly the same as `cargo`.

To verify and build the entire project, run
```
vargo build --release
```
Then use `target/release/frontend` to run benchmark or tests
(see `target/release/frontend --help` for more options).

To run all tests
```
vargo test --workspace
```
