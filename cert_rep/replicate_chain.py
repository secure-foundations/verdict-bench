import argparse

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, ec

from .replicate_roots import load_certs, load_private_keys, gen_new_key, replicate_cert

def verify_issuing(issuer, subject):
    assert subject.issuer == issuer.subject

    pub_key = issuer.public_key()

    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        pub_key.verify(
            subject.signature,
            subject.tbs_certificate_bytes,
            ec.ECDSA(subject.signature_hash_algorithm)
        )
    else:
        pub_key.verify(
            subject.signature,
            subject.tbs_certificate_bytes,
            padding.PKCS1v15(),
            subject.signature_hash_algorithm
        )

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("chain", help="The certificate chain in PEM format")
    parser.add_argument("roots", help="Replicated root store in PEM format")
    parser.add_argument("root_keys", help="Private keys of each root certificate")
    parser.add_argument("new_chain", help="Output chain")
    parser.add_argument("new_priv_key", help="Output private key of the leaf certificate")
    args = parser.parse_args()

    with open(args.chain, "rb") as f:
        chain = list(load_certs(f.read()))

    with open(args.roots, "rb") as f:
        roots = load_certs(f.read())

    with open(args.root_keys, "rb") as f:
        priv_keys = load_private_keys(f.read())

    # Map subject to private key, so that
    # when we encounter certificates in the chain with the same subject
    # we can assign a consistent public key
    subject_to_priv_key = { cert.subject: priv_key for cert, priv_key in zip(roots, priv_keys) }

    # print(len(chain), len(roots), len(priv_keys))
    assert len(roots) == len(priv_keys)

    # Check that chain[i + 1] issued chain[i]
    for i in range(len(chain) - 1):
        verify_issuing(chain[i + 1], chain[i])

    # Find a root certificate that issued chain[-1]
    for i, root in enumerate(roots):
        if root.subject == chain[-1].issuer:
            break
    else:
        raise ValueError("no root certificate found")

    prev_priv_key = serialization.load_pem_private_key(
        priv_keys[i], password=None, backend=default_backend())

    # Replace keys
    with open(args.new_chain, "wb") as new_chain, open(args.new_priv_key, "wb") as new_key:
        keys = []

        for i in range(len(chain) - 1, -1, -1):
            if chain[i].subject in subject_to_priv_key:
                print(f"cross-signed subject {chain[i].subject}")
                new_priv_key = serialization.load_pem_private_key(
                    subject_to_priv_key[chain[i].subject],
                    password=None,
                    backend=default_backend(),
                )
            else:
                new_priv_key = gen_new_key(chain[i])

            chain[i] = replicate_cert(chain[i], prev_priv_key, new_priv_key.public_key())
            prev_priv_key = new_priv_key
            keys.append(new_priv_key)

        for cert in chain:
            new_chain.write(cert.public_bytes(serialization.Encoding.PEM))

        new_key.write(keys[-1].private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))


if __name__ == "__main__":
    main()
