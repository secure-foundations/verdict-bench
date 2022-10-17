import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key

from helpers import *

tbs_bytes = []
sign_oids = []
signatures = []
pks = []

sign_oid_map = {
    "6 9 42 134 72 134 247 13 1 1 11": "sha256WithRSAEncryption",
    "6 9 42 134 72 134 247 13 1 1 12": "sha384WithRSAEncryption",
    "6 9 42 134 72 134 247 13 1 1 5": "sha1WithRSAEncryption"
}


def readData(filepath):
    f = open(filepath, "r")
    lines = f.readlines()

    for i in range(0, len(lines)):
        if (i % 5 == 0):  # tbs bytes
            tbs_bytes.append(int_to_Bytes(lines[i].strip()))
        elif (i % 5 == 1):  # signature
            # if lines[i].strip().startswith("0 "):
            lines_i_0_stripped = lines[i].strip()
            signatures.append(int_to_Bytes(lines_i_0_stripped)[5:])
            # else:
            #     signatures.append(int_to_Bytes(lines[i].strip()))
        elif (i % 5 == 2):  # pk
            pks.append(load_der_public_key(int_to_Bytes(lines[i].strip()), backend=default_backend()))
        elif (i % 5 == 3):  # sign oid
            sign_oids.append(sign_oid_map.get(lines[i].strip()))


def verifySign(signature, sign_algo, msg, pk):
    if sign_algo == "sha256WithRSAEncryption":
        try:
            pk.verify(signature, msg, padding.PKCS1v15(), hashes.SHA256())
            return True
        except InvalidSignature:
            return False
    elif sign_algo == "sha384WithRSAEncryption":
        try:
            pk.verify(signature, msg, padding.PKCS1v15(), hashes.SHA384())
            return True
        except InvalidSignature:
            return False
    elif sign_algo == "sha1WithRSAEncryption":
        try:
            pk.verify(signature, msg, padding.PKCS1v15(), hashes.SHA1())
            return True
        except InvalidSignature:
            return False
    else:
        print("Singnature algorithm is not supported")
        return False


def verifySignatures():
    res = False
    for i in range(0, len(signatures)):
        if i == len(signatures) - 1:
            res = verifySign(signatures[i], sign_oids[i], tbs_bytes[i], pks[i])
        else:
            res = verifySign(signatures[i], sign_oids[i], tbs_bytes[i], pks[i + 1])

        if res == False:
            print("Failed to verify signature of certificate {}".format(i))
            break
    return res


def main():
    filename = sys.argv[1]
    readData(filename)
    res = verifySignatures()

    if res:
        print("Signature verification: passed")
    else:
        print("Signature verification: failed")


if __name__ == "__main__":
    main()
