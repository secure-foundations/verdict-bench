import os.path
import subprocess
import sys
from base64 import *
from pathlib import Path

from pem import *

from verifySignature import *

import os
import random

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
    ep = random.random()
    args = sys.argv
    home_dir = str(Path.home())
    filename_certchain = args[3]
    filename_aeres_output = home_dir + "/.residuals/temp_{}.txt".format(ep)
    filename_aeres_bin = args[1]

    if not os.path.exists(home_dir + "/.residuals/"):
        os.mkdir(home_dir + "/.residuals/")

    cmd = ['cat {} | {} > {}'.format(filename_certchain, filename_aeres_bin, filename_aeres_output)]
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
    sign_verify_res = verifySignatures()
    if not sign_verify_res:
        print("Signature verification: failed")
        return False
    else:
        print("Signature verification: passed")

    decoded_rootcert_bytes = decodePem(args[2])
    decoded_certchain_bytes = decodePem(args[3])
    if (decoded_rootcert_bytes == None):
        print("Error: Failed to decode input PEM trusted root CA certs")
        return False
    elif (decoded_certchain_bytes == None):
        print("Error: Failed to decode input PEM certificate chain")
        return False
    else:
        if decoded_certchain_bytes[len(decoded_certchain_bytes) - 1] in decoded_rootcert_bytes:
            print("Trusted root CA: passed")
        else:
            print("Trusted root CA: failed")
            return False

    return True


if __name__ == "__main__":
    res = main()
    if res:
        print("success")
    else:
        print("failed")
