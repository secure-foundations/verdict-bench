import os.path
import subprocess
import sys
from base64 import *

from pem import *

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
    args = sys.argv
    filename_certchain_dump = ".residuals/temp1.txt"
    filename_aeres_output = ".residuals/temp2.txt"
    filename_aeres_bin = args[3]

    if not os.path.exists(".residuals/"):
        os.mkdir(".residuals/")

    decoded_certchain_bytes = decodePem(args[1])
    if (decoded_certchain_bytes == None):
        print("Error: Failed to decode input PEM certificate chain")
        return False
    else:
        output = b''
        for c in decoded_certchain_bytes:
            output = output + c
        f = open(filename_certchain_dump, 'wb')
        f.write(output)
        f.close()

    cmd = ['cat {} | ./{} > {}'.format(filename_certchain_dump, filename_aeres_bin, filename_aeres_output)]
    aeres_res = subprocess.getoutput(cmd)
    if aeres_res.__contains__("failed") or aeres_res.__contains__("error") \
            or aeres_res.__contains__("exception") or aeres_res.__contains__("TLV: cert") \
            or aeres_res.__contains__("cannot execute binary file"):
        print("AERES syntactic or semantic checks: failed")
        print(aeres_res)
        return False
    else:
        print("AERES syntactic and semantic checks: passed")

    readData(filename_aeres_output)
    sign_verify_res = verifySignatures()
    if not sign_verify_res:
        print("Signature verification: failed")
        return False
    else:
        print("Signature verification: passed")

    decoded_rootcert_bytes = decodePem(args[2])
    if (decoded_rootcert_bytes == None):
        print("Error: Failed to decode input PEM trusted root CA certs")
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
        print("Accepted")
    else:
        print("Rejected")
