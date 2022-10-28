### only read 4 certs, more bytes left

cert_1099558750.pem-chain.pem
- CWJ: uses the deprecated emailAddress attribute type in the RND sequence

### aeres: MAlonzo Runtime Error: postulate evaluated: Aeres.Data.X509.Properties.TBSCertFields.TBSEq

cert_1097184815.pem-chain.pem
- CWJ: passes after removing CCP5

### SCP10: failed Rejected, may be related to keyusage bits parsing (in certificate 4)

#### When the Key Usage extension appears in a certificate, at least one of the bits MUST be set to 1

cert_1025086070.pem-chain.pem
- CWJ: I think the specification for SCP10 needs to be revisited (it does not check that this extension is present)

#### Useful Links

https://lapo.it/asn1js/ 
