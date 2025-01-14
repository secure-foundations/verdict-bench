"""
Given a list of hostnames and a root store,
this script makes an HTTPS request to each of them.
For each hostname, it fetches:
1. The certificate chain
2. The HTTP response (resolving any redirection)

Then it fakes a similar certificate chain by substituting
a freshly generated secret/public key pairs.

These data can be later used for benchmarking connection to
the public server, except with the generated secret keys instead
of the real ones.
"""

import os
import re
import socket
import requests
import argparse
# from concurrent.futures import ThreadPoolExecutor

import OpenSSL
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
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


def get_full_http_response(url):
    response = requests.get(url, timeout=10, headers={
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/115.0.0.0 Safari/537.36"
        )
    })
    status_line = f"HTTP/1.1 {response.status_code} {response.reason}"
    headers = "\r\n".join(f"{header}: {value}" for header, value in response.headers.items())
    return f"{status_line}\r\n{headers}\r\n\r\n{response.text}"


def get_server_chain(roots_path, hostname, port=443):
    context = OpenSSL.SSL.Context(OpenSSL.SSL.TLS_CLIENT_METHOD)
    context.set_default_verify_paths()  # load system CA certificates if needed
    context.load_verify_locations(cafile=roots_path)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection = OpenSSL.SSL.Connection(context, sock)
    connection.set_tlsext_host_name(hostname.encode())
    sock.settimeout(10)
    connection.connect((hostname, port))
    sock.settimeout(None)
    connection.set_connect_state()
    connection.do_handshake()

    # Load chain with cryptography
    chain = [
        cert.to_cryptography()
        for cert in connection.get_peer_cert_chain()
    ]

    connection.shutdown()
    connection.close()

    return chain


def verify_signature(issuer, subject):
    try:
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
    except:
        return False

    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", required=True, help="Output directory")
    parser.add_argument("-l", "--list", help="Use the given list of domain names")
    parser.add_argument("-n", type=int, help="Take the first n domains that are connecte successfully")
    parser.add_argument("roots", help="Original root store files")
    parser.add_argument("--hostnames", default=[], nargs="*", help="Hostnames to connect to")

    args = parser.parse_args()

    assert not os.path.exists(args.output), "output directory already exists"
    os.makedirs(args.output)

    # First replicate all the root certificates with custom secret keys
    with open(args.roots, "rb") as f:
        roots = load_certs(f.read())

    # Read the domain list
    if args.list is not None:
        with open(args.list) as f:
            domain_list = [line.strip() for line in f.readlines()]
    else:
        domain_list = []

    new_roots = list(roots)
    subject_to_key = {}

    num_success = 0

    # Then start requesting each hostname and replicate their chains
    for i, hostname in enumerate(args.hostnames + domain_list):
        print(f"requesting hostname {hostname} [{i + 1}/{(len(args.hostnames) + len(domain_list))}, {num_success} success]...")

        try:
            output_path = os.path.join(args.output, hostname)
            os.mkdir(output_path)

            # Fetch the certificate chain
            chain = get_server_chain(args.roots, hostname)
            assert len(chain) != 0

            # Fetch the HTTP response
            response = get_full_http_response(f"https://{hostname}/")
            with open(os.path.join(output_path, "response.txt"), "w") as f:
                f.write(response)

            # Assume that chain[i + 1] issued chain[i]
            for i in range(len(chain) - 1):
                assert verify_signature(chain[i + 1], chain[i])

            # Find a root certificate that issued chain[-1]
            for found_root_idx, found_root in enumerate(new_roots):
                if found_root.subject == chain[-1].issuer:
                    break
            else:
                raise ValueError("no root certificate issued the last certificate in the chain")

            output_chain_path = os.path.join(output_path, "chain.pem")
            output_key_path = os.path.join(output_path, "key.pem")

            with open(output_chain_path, "wb") as output_chain, open(output_key_path, "wb") as output_key:

                # Lazily replace root keys with the new ones
                if found_root.subject not in subject_to_key:
                    print(f"replicating root {found_root.subject}...")
                    subject_to_key[found_root.subject] = new_root_key = gen_new_key(found_root)
                    new_roots[found_root_idx] = replicate_cert(found_root, new_root_key)

                prev_priv_key = subject_to_key[found_root.subject]

                # Replace keys of leaf and intermediates
                for i in range(len(chain) - 1, -1, -1):
                    # Intermeidate might be a cross-signed root
                    if chain[i].subject in subject_to_key:
                        # print(f"cross-signed subject {chain[i].subject}")
                        new_priv_key = subject_to_key[chain[i].subject]
                    else:
                        new_priv_key = gen_new_key(chain[i])

                    chain[i] = replicate_cert(chain[i], prev_priv_key, new_priv_key.public_key())
                    prev_priv_key = new_priv_key

                for cert in chain:
                    output_chain.write(cert.public_bytes(serialization.Encoding.PEM))

                output_key.write(prev_priv_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()
                ))

            num_success += 1

            if num_success >= args.n:
                break

        except Exception as e:
            print(f"error processing hostname {hostname}: {e}")

    # Serialize potentially modified roots at the end
    with open(os.path.join(args.output, "roots.pem"), "wb") as new_roots_file:
        for cert in new_roots:
            new_roots_file.write(cert.public_bytes(serialization.Encoding.PEM))


if __name__ == "__main__":
    main()
