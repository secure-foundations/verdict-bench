
### SCP10: failed Rejected, may be related to keyusage bits parsing (in certificate 4)

#### When the Key Usage extension appears in a certificate, at least one of the bits MUST be set to 1

cert_1025086070.pem-chain.pem
- CWJ: I think the specification for SCP10 needs to be revisited (it does not check that this extension is present)
