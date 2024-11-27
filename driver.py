import os.path
import subprocess
import sys
import argparse
import os
import random
import tempfile

from pathlib import Path
from pem import *
from base64 import *
from verifySignature import *

def main():

    ### command-line argument processing
    # usage: ./armor-driver [-h] [--chain INPUT] [--trust_store CA_STORE] [--purpose CHECK_PURPOSE]
    parser = argparse.ArgumentParser(description='ARMOR command-line arguments')
    parser.add_argument('--chain', type=str,
                        help='Input certificate chain location')
    parser.add_argument('--trust_store', type=str, default='/etc/ssl/certs/ca-certificates.crt',
                        help='Trust anchor location; default=/etc/ssl/certs/ca-certificates.crt')
    parser.add_argument('--purpose', type=str,
                        help='expected purpose for end-user certificate: serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, or OCSPSigning')
    args = parser.parse_args()

    input_chain = args.chain
    input_CA_store = args.trust_store
    input_purpose = args.purpose

    if input_chain == None:
        print("Error : missing input certificate chain")
        sys.exit(-1)

    if not (input_chain.endswith((".pem", ".crt", ".der")) \
        and input_CA_store.endswith((".pem", ".crt")) \
        and os.path.exists(input_chain) and os.path.exists(input_CA_store)):
        print("Error : Input file or CA store doesn't exist or not supported (supported formats: .pem, .crt)")
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

    with tempfile.TemporaryDirectory() as tmp_dir:
        filename_certchain = input_chain
        filename_aeres_output = tmp_dir + "/.residuals/temp_{}.txt".format(ep)

        if not os.path.exists(tmp_dir + "/.residuals/"):
            os.mkdir(tmp_dir + "/.residuals/")

        if input_chain.endswith(".der"):
            if input_purpose == None:
                cmd = ['{}/armor-bin --DER {} {} > {}'.format(script_dir, filename_certchain, input_CA_store, filename_aeres_output)]
            else:
                cmd = ['{}/armor-bin --DER --purpose {} {} {} > {}'.format(script_dir, input_purpose, filename_certchain, input_CA_store, filename_aeres_output)]
        else: ## for .pem and .crt
            if input_purpose == None:
                cmd = ['{}/armor-bin {} {} > {}'.format(script_dir, filename_certchain, input_CA_store, filename_aeres_output)]
            else:
                cmd = ['{}/armor-bin --purpose {} {} {} > {}'.format(script_dir, input_purpose, filename_certchain, input_CA_store, filename_aeres_output)]

        # print(cmd[0])
        # exit()

        aeres_res = subprocess.getoutput(cmd)
        print(aeres_res)

        if aeres_res.__contains__("failed") or aeres_res.__contains__("error") or aeres_res.__contains__("Error") \
                or aeres_res.__contains__("exception") or aeres_res.__contains__("TLV: cert") \
                or aeres_res.__contains__("cannot execute binary file") or aeres_res.__contains__("more bytes remain") \
                or aeres_res.__contains__("incomplete read") or aeres_res.__contains__("not found"):
            print("AERES syntactic or semantic checks: failed", file=sys.stderr)
            os.remove(filename_aeres_output)
            return False
        else:
            print("AERES syntactic and semantic checks: passed", file=sys.stderr)

        readData(filename_aeres_output)
        os.remove(filename_aeres_output)

        sign_verify_res = verifySignatures()
        if sign_verify_res == "false":
            print("Signature verification: failed", file=sys.stderr)
            return False
        else:
            print("Signature verification: passed", file=sys.stderr)

        return True

if __name__ == "__main__":
    res = main()
    if res:
        print("success")
    else:
        print("failed")
