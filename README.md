# CERES
This repository contains the official release of CERES library introduced in the paper titled *[On Re-engineering the X.509 PKI with Executable Specification for Better Implementation Guarantees](https://github.com/joyantaDebnath/CERES/blob/master/ccsfp468-debnath.pdf)* published in 2021 ACM Conference on Computer and Communications Security (ACM CCS 2021).


# Actually...

This is a modified version of CERES for benchmarking.

Run `build-ceres.sh` to build some random stuff and output to `build/`
Then run
```
python3 src/driver.py /etc/ssl/certs/ca-certificates.crt --input test.pem
```
To validate `test.pem` against root certificates
