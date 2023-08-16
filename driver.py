import os.path
import subprocess
import sys
import argparse
import os
import random

from pathlib import Path
from pem import *
from base64 import *
from verifySignature import *

def decodePem(filename):
    try:
        cert_list = []
        for c in parse_file(filename):
            if (isinstance(c, Certificate)):
                cert_list.append(b64decode(str(c)[28:-26]))
            else:
                return None
        return cert_list
    except:
        return None

def main():

    ### command-line argument processing
    # usage: ./armor-driver [-h] [--chain INPUT] [--trust_store CA_STORE] [--purpose CHECK_PURPOSE [CHECK_PURPOSE ...]]
    parser = argparse.ArgumentParser(description='ARMOR command-line arguments')
    parser.add_argument('--chain', type=str,
                        help='Input certificate chain location')
    parser.add_argument('--trust_store', type=str, default='/etc/ssl/certs/ca-certificates.crt',
                        help='Trust anchor location; default=/etc/ssl/certs/ca-certificates.crt')
    parser.add_argument('--purpose', nargs='+',
                        help='list of expected purposes of end-user certificate: serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, OCSPSigning, digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly; default=anyPurpose',
                        default=[])
    args = parser.parse_args()

    input_chain = args.chain
    input_CA_store = args.trust_store
    input_purposes = args.purpose

    for purpose in input_purposes:
        if purpose == 'serverAuth':
            continue
        elif purpose == 'clientAuth':
            continue
        elif purpose == 'codeSigning':
            continue
        elif purpose == 'emailProtection':
            continue
        elif purpose == 'timeStamping':
            continue
        elif purpose == 'OCSPSigning':
            continue
        elif purpose == 'digitalSignature':
            continue
        elif purpose == 'nonRepudiation':
            continue
        elif purpose == 'keyEncipherment':
            continue
        elif purpose == 'dataEncipherment':
            continue
        elif purpose == 'keyAgreement':
            continue
        elif purpose == 'keyCertSign':
            continue
        elif purpose == 'cRLSign':
            continue
        elif purpose == 'encipherOnly':
            continue
        elif purpose == 'decipherOnly':
            continue
        else:
            print(
                "Error : Purposes are not supported (supported purposes: serverAuth, "
                "clientAuth, codeSigning, emailProtection, timeStamping, OCSPSigning, "
                "digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, "
                "keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly"
                ")")
            sys.exit(-1)

    if not (input_chain.endswith((".pem", ".crt")) \
        and input_CA_store.endswith((".pem", ".crt")) \
        and os.path.exists(input_chain) and os.path.exists(input_CA_store)):
        print("Error : Input file or CA store doesn't exist or not supported (supported formats: .pem, .crt)")
        sys.exit(-1)

    #############################

    ep = random.random()
    args = sys.argv
    home_dir = str(Path.home())
    filename_certchain = input_chain
    filename_aeres_output = home_dir + "/.residuals/temp_{}.txt".format(ep)

    if not os.path.exists(home_dir + "/.residuals/"):
        os.mkdir(home_dir + "/.residuals/")

    cmd = ['cat {} | {}/.armor/armor-bin > {}'.format(filename_certchain, home_dir, filename_aeres_output)]
    aeres_res = subprocess.getoutput(cmd)
    print(aeres_res)
    if aeres_res.__contains__("failed") or aeres_res.__contains__("error") \
            or aeres_res.__contains__("exception") or aeres_res.__contains__("TLV: cert") \
            or aeres_res.__contains__("cannot execute binary file") or aeres_res.__contains__("more bytes remain"):
        print("AERES syntactic or semantic checks: failed")
        os.remove(filename_aeres_output)
        return False
    else:
        print("AERES syntactic and semantic checks: passed")

    readData(filename_aeres_output)
    os.remove(filename_aeres_output)

    purpose_verify_res = verifyCertificatePurpose(input_purposes)
    if not purpose_verify_res:
        print("Error: Incorrect certificate purpose")
        return False

    decoded_rootcert_bytes = decodePem(input_CA_store)
    decoded_certchain_bytes = decodePem(input_chain)
    trusted_ca_index = -1
    if (decoded_rootcert_bytes == None):
        print("Error: Failed to decode input PEM trusted CA certs")
        return False
    elif (decoded_certchain_bytes == None):
        print("Error: Failed to decode input PEM certificate chain")
        return False
    else:
        for i in range(0, len(decoded_certchain_bytes)):
            if decoded_certchain_bytes[i] in decoded_rootcert_bytes:
                print("Trusted CA: passed")
                trusted_ca_index = i
                break

    if trusted_ca_index == -1:
        print("Trusted CA: failed")
        return False

    sign_verify_res = verifySignatures(trusted_ca_index)
    if not sign_verify_res:
        print("Signature verification: failed")
        return False
    else:
        print("Signature verification: passed")

    return True

if __name__ == "__main__":
    res = main()
    if res:
        print("success")
    else:
        print("failed")
