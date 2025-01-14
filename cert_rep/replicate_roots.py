import re
import sys
import argparse

import OpenSSL
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import SignatureAlgorithmOID


def load_certs(pem_data):
    """Load all certificates from a PEM-formatted string"""
    pattern = re.compile(b"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)", re.DOTALL)
    pem_certs = pattern.findall(pem_data)
    return tuple(
        x509.load_pem_x509_certificate(cert, default_backend())
        for cert in pem_certs)


def load_private_keys(pem_data):
    """Load all private keys from a PEM-formatted string"""
    pattern = re.compile(
        b"(-----BEGIN (RSA|EC) PRIVATE KEY-----.*?-----END (RSA|EC) PRIVATE KEY-----)",
        re.DOTALL
    )
    pem_keys = pattern.findall(pem_data)
    return tuple(key[0] for key in pem_keys)


def gen_new_key(cert):
    """Generate a new private key matching the public key type of the certificate"""
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        key_size = public_key.key_size
        new_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        curve = public_key.curve
        new_key = ec.generate_private_key(curve, backend=default_backend())
    else:
        raise ValueError("Unsupported key type.")
    return new_key


def replicate_cert(original_cert, new_private_key, new_public_key=None):
    """Create a new self-signed certificate with the same fields but using a new key."""

    subject = original_cert.subject
    issuer = original_cert.issuer

    if new_public_key is None:
        new_public_key = new_private_key.public_key()

    builder = x509.CertificateBuilder(
        issuer_name=issuer,
        subject_name=subject,
        public_key=new_public_key,
        serial_number=original_cert.serial_number,
        not_valid_before=original_cert.not_valid_before_utc,
        not_valid_after=original_cert.not_valid_after_utc,
    )

    for ext in original_cert.extensions:
        builder = builder.add_extension(ext.value, critical=ext.critical)

    # Get the hash algorithm
    oid = original_cert.signature_algorithm_oid
    if oid in {SignatureAlgorithmOID.RSA_WITH_SHA1}:
        # Use OpenSSL to sign with SHA1 (which is deprecated and disabled in cryptography)
        unsigned_cert = builder.sign(private_key=new_private_key, algorithm=hashes.SHA256(), backend=default_backend())
        cert_pem = unsigned_cert.public_bytes(serialization.Encoding.PEM)
        x509_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
        pkey = OpenSSL.crypto.PKey.from_cryptography_key(new_private_key)
        x509_cert.sign(pkey, "sha1")
        return x509.load_der_x509_certificate(
            OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, x509_cert),
            default_backend()
        )

    elif oid in {SignatureAlgorithmOID.RSA_WITH_SHA256, SignatureAlgorithmOID.ECDSA_WITH_SHA256}:
        algorithm = hashes.SHA256()
    elif oid in {SignatureAlgorithmOID.RSA_WITH_SHA384, SignatureAlgorithmOID.ECDSA_WITH_SHA384}:
        algorithm = hashes.SHA384()
    elif oid in {SignatureAlgorithmOID.RSA_WITH_SHA512, SignatureAlgorithmOID.ECDSA_WITH_SHA512}:
        algorithm = hashes.SHA512()
    else:
        raise ValueError(f"unsupported signature algorithm {oid}")

    return builder.sign(private_key=new_private_key, algorithm=algorithm, backend=default_backend())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("roots", help="Path to the root store (PEM format)")
    parser.add_argument("new_roots", help="Path to write the new roots (PEM format)")
    parser.add_argument("new_private_keys", help="Path to write the new private keys (PEM format)")
    args = parser.parse_args()

    with open(args.roots, "rb") as f:
        certs = load_certs(f.read())

    with open(args.new_roots, "wb") as new_roots, open(args.new_private_keys, "wb") as new_keys:
        for idx, cert in enumerate(certs, start=1):
            print(f"processing certificate {idx}...", file=sys.stderr)

            try:
                new_key = gen_new_key(cert)
                new_cert = replicate_cert(cert, new_key)
            except Exception as e:
                print(f"skipping certificate {idx}: {e}", file=sys.stderr)
                continue

            new_roots.write(new_cert.public_bytes(serialization.Encoding.PEM))
            new_keys.write(new_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))


if __name__ == "__main__":
    main()
