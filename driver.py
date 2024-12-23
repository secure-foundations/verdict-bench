import os.path
import subprocess
import sys
import argparse
import os
import random
import tempfile
import time

from pathlib import Path
from pem import *
from base64 import *
from verifySignature import *

def main():

    ### command-line argument processing
    # usage: ./armor-driver [-h] [--trust_store CA_STORE] [--purpose CHECK_PURPOSE]
    parser = argparse.ArgumentParser(description='ARMOR command-line arguments')
    parser.add_argument('--trust_store', type=str, default='/etc/ssl/certs/ca-certificates.crt',
                        help='Trust anchor location; default=/etc/ssl/certs/ca-certificates.crt')
    parser.add_argument('--purpose', type=str,
                        help='expected purpose for end-user certificate: serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, or OCSPSigning')
    args = parser.parse_args()

    input_CA_store = args.trust_store
    input_purpose = args.purpose

    if not (input_CA_store.endswith((".pem", ".crt")) \
        and os.path.exists(input_CA_store)):
        print("Error : CA store doesn't exist or not supported (supported formats: .pem, .crt)")
        sys.exit(-1)

    if (input_purpose != 'serverAuth' and \
        input_purpose != 'clientAuth' and \
        input_purpose != 'codeSigning' and \
        input_purpose != 'emailProtection' and \
        input_purpose != 'timeStamping' and \
        input_purpose != 'OCSPSigning' and \
        input_purpose != None):
            print(
            "Error : Purposes are not supported (supported purposes: serverAuth, "
            "clientAuth, codeSigning, emailProtection, timeStamping, OCSPSigning")
            sys.exit(-1)

    #############################

    ep = random.random()
    args = sys.argv
    # home_dir = str(Path.home())
    script_dir = os.path.dirname(os.path.realpath(__file__))

    assert input_purpose is not None
    # assert not input_chain.endswith(".der")

    def validate(chain_file):
        child.stdin.write(chain_file.encode() + b"\n")

        line = child.stderr.readline().decode().strip()
        assert line == "start"

        # Read every line between "start" and "end"
        output = []
        failed = False

        while True:
            line = child.stderr.readline().decode()
            # print(output)
            assert line, "unexpected end of stdout"
            if line.strip() == "end":
                break

            # From the original driver
            failed = failed or line.__contains__("failed") or \
                line.__contains__("error") or \
                line.__contains__("Error") or \
                line.__contains__("exception") or \
                line.__contains__("TLV: cert") or \
                line.__contains__("cannot execute binary file") or \
                line.__contains__("more bytes remain") or \
                line.__contains__("incomplete read") or \
                line.__contains__("not found")

            output.append(line)

        if failed:
            return False

        readData(output)
        sign_verify_res = verifySignatures()

        return sign_verify_res == "true"

    leaf = None
    interm = []
    repeat = 1

    # Prepare a temporary file for the chain
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            child = subprocess.Popen(
                [
                    f"{script_dir}/armor-bin",
                    "--purpose", input_purpose,
                    input_CA_store,
                ],
                stdin=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
            )

            # First wait until root certificates have been parsed
            line = child.stderr.readline()
            if not line.startswith(b"roots parsed:"):
                print(f"error: failed to parse root; {line.decode()}")
                exit(130)

            for input_line in sys.stdin:
                input_line = input_line.strip()

                if input_line == "": continue

                elif input_line.startswith("leaf: "):
                    assert leaf is None
                    leaf = input_line[len("leaf: "):]

                elif input_line.startswith("interm: "):
                    assert leaf is not None
                    interm.append(input_line[len("interm: "):])

                elif input_line.startswith("repeat: "):
                    repeat = int(input_line[len("repeat: "):])
                    assert repeat >= 1

                elif input_line == "validate":
                    durations = []

                    # Prepare a temporary file for the chain
                    with open(tmp_file.name, "wb") as f:
                        for cert in [leaf] + interm:
                            f.write(b"-----BEGIN CERTIFICATE-----\n")
                            f.writelines(cert[i:i+64].encode() + b"\n" for i in range(0, len(cert), 64))
                            f.write(b"-----END CERTIFICATE-----\n")
                        f.flush()

                    for _ in range(repeat):
                        start = time.time()
                        result = validate(tmp_file.name)
                        durations.append(time.time() - start)

                    print(f"result: {'OK' if result else 'false'} {' '.join(str(int(d * 1000000)) for d in durations)}", flush=True)

                    leaf = None
                    interm = []

                else:
                    assert False, f"unexpected input: {input_line}"

    finally:
        os.unlink(tmp_file.name)
        child.kill()
        child.wait()

if __name__ == "__main__":
    main()
