# ARMOR Driver Module (Python)

### Build and Install
`./install.sh`

### Cleanup
`./cleanup.sh`

### How to run
`python3 driver.py --chain <input chain> --trust_store <input CA store> [--purpose <expected purpose>]`

or

`./bin/armor --chain <input chain> --trust_store <input CA store> [--purpose <expected purpose>]`

##### *** List of Supported Purposes ***
`serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`, `timeStamping`, `ocspSigning`
