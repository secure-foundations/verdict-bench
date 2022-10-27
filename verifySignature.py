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
    "6 9 42 134 72 134 247 13 1 1 13": "sha512WithRSAEncryption",
    "6 9 42 134 72 134 247 13 1 1 14": "sha224WithRSAEncryption",
    "6 9 42 134 72 134 247 13 1 1 5": "sha1WithRSAEncryption",
    '6 8 42 134 72 206 61 4 3 1': 'ecdsa-with-SHA224',
    '6 8 42 134 72 206 61 4 3 2': 'ecdsa-with-SHA256',
    '6 8 42 134 72 206 61 4 3 3': 'ecdsa-with-SHA384',
    '6 8 42 134 72 206 61 4 3 4': 'ecdsa-with-SHA512'
}

sign_oid_map_insecure = {
    "6 9 42 134 72 134 247 13 1 1 2": "md2WithRSAEncryption",
    "6 9 42 134 72 134 247 13 1 1 3": "md4WithRSAEncryption",
    "6 9 42 134 72 134 247 13 1 1 4": "md5WithRSAEncryption"
}


def readData(filepath):
    f = open(filepath, "r")
    lines = f.readlines()

    for i in range(0, len(lines)):
        if (i % 5 == 0):  # tbs bytes
            tbs_bytes.append(int_to_Bytes(lines[i].strip()))
        elif (i % 5 == 1):  # signature
            if lines[i].strip().startswith("0 "):  ## 0 as padding byte
                lines_i_0_stripped = lines[i].strip()[2:]
                signatures.append(int_to_Bytes(lines_i_0_stripped))
            else:  ## without padding byte
                signatures.append(int_to_Bytes(lines[i].strip()))
        elif (i % 5 == 2):  # pk
            pks.append(load_der_public_key(int_to_Bytes(lines[i].strip()), backend=default_backend()))
        elif (i % 5 == 3):  # sign oid
            sign_oids.append(lines[i].strip())


def verifySign(signature, sign_algo, msg, pk):
    if sign_algo in sign_oid_map_insecure:
        print("Signature algorithm is insecure:", sign_oid_map_insecure[sign_algo])
        return False

    if sign_algo in sign_oid_map:
        if sign_oid_map[sign_algo] == "sha256WithRSAEncryption":
            try:
                pk.verify(signature, msg, padding.PKCS1v15(), hashes.SHA256())
                return True
            except InvalidSignature:
                return False
        elif sign_oid_map[sign_algo] == "sha384WithRSAEncryption":
            try:
                pk.verify(signature, msg, padding.PKCS1v15(), hashes.SHA384())
                return True
            except InvalidSignature:
                return False
        elif sign_oid_map[sign_algo] == "sha512WithRSAEncryption":
            try:
                pk.verify(signature, msg, padding.PKCS1v15(), hashes.SHA512())
                return True
            except InvalidSignature:
                return False
        elif sign_oid_map[sign_algo] == "sha224WithRSAEncryption":
            try:
                pk.verify(signature, msg, padding.PKCS1v15(), hashes.SHA224())
                return True
            except InvalidSignature:
                return False
        elif sign_oid_map[sign_algo] == "sha1WithRSAEncryption":
            try:
                pk.verify(signature, msg, padding.PKCS1v15(), hashes.SHA1())
                return True
            except InvalidSignature:
                return False
        else:
            print("Singnature algorithm is not supported, verification bypassed:", sign_oid_map[sign_algo])
            return True
    else:
        print("Singnature algorithm is not supported, verification bypassed:", int_to_hex(sign_algo).upper())
        return True


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
