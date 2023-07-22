# from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key

from helpers import *

import hashlib
import subprocess

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

## with cryptography library
# def verifySign(signature, sign_algo, msg, pk, i):
#     if sign_algo in sign_oid_map_insecure:
#         print("Singnature algorithm {} is insecure in certificate {}".format(sign_oid_map_insecure[sign_algo], i))
#         return False

#     if sign_algo in sign_oid_map:
#         if sign_oid_map[sign_algo] == "sha256WithRSAEncryption":
#             try:
#                 pk.verify(signature, msg, padding.PKCS1v15(), hashes.SHA256())
#                 return True
#             except InvalidSignature:
#                 return False
#         elif sign_oid_map[sign_algo] == "sha384WithRSAEncryption":
#             try:
#                 pk.verify(signature, msg, padding.PKCS1v15(), hashes.SHA384())
#                 return True
#             except InvalidSignature:
#                 return False
#         elif sign_oid_map[sign_algo] == "sha512WithRSAEncryption":
#             try:
#                 pk.verify(signature, msg, padding.PKCS1v15(), hashes.SHA512())
#                 return True
#             except InvalidSignature:
#                 return False
#         elif sign_oid_map[sign_algo] == "sha224WithRSAEncryption":
#             try:
#                 pk.verify(signature, msg, padding.PKCS1v15(), hashes.SHA224())
#                 return True
#             except InvalidSignature:
#                 return False
#         elif sign_oid_map[sign_algo] == "sha1WithRSAEncryption":
#             try:
#                 pk.verify(signature, msg, padding.PKCS1v15(), hashes.SHA1())
#                 return True
#             except InvalidSignature:
#                 return False
#         else:
#             print("Singnature algorithm {} is not supported - verification bypassed in certificate {}".format(sign_oid_map[sign_algo], i))
#             return True
#     else:
#         print("Singnature algorithm {} is not supported - verification bypassed in certificate {}".format(int_to_hex(sign_algo).upper(), i))
#         return True

# def readData(filepath):
#     f = open(filepath, "r")
#     lines = f.readlines()

#     for i in range(0, len(lines)):
#         if (i % 5 == 0):  # tbs bytes
#             tbs_bytes.append(int_to_Bytes(lines[i].strip()))
#         elif (i % 5 == 1):  # signature
#             if lines[i].strip().startswith("0 "):  ## 0 as padding byte
#                 lines_i_0_stripped = lines[i].strip()[2:]
#                 signatures.append(int_to_hex(lines_i_0_stripped))
#             else:  ## without padding byte
#                 signatures.append(int_to_hex(lines[i].strip()))
#         elif (i % 5 == 2):  # pk
#             pks.append(load_der_public_key(int_to_Bytes(lines[i].strip()), backend=default_backend()))
#         elif (i % 5 == 3):  # sign oid
#             sign_oids.append(lines[i].strip())

## with morpheous formally verified oracle
def verifySign(signature, sign_algo, msg, pk, i):
    if sign_algo in sign_oid_map_insecure:
        print("Singnature algorithm {} is insecure in certificate {}".format(sign_oid_map_insecure[sign_algo], i))
        return False

    if sign_algo in sign_oid_map:
        if sign_oid_map[sign_algo] == "sha256WithRSAEncryption":
            try:
                signature_mod = pow(int.from_bytes(signature, byteorder='big'), pk.public_numbers().e, pk.public_numbers().n)
                signature_mod_hex = '00' + signature_mod.to_bytes((signature_mod.bit_length() + 7) // 8, byteorder='big').hex()
                tbs_hash = hashlib.sha256(msg).hexdigest()
                n_length = pk.public_numbers().n.bit_length() // 8
                hash_size = 256
                cmd = ['./oracle {} {} {} {}'.format(signature_mod_hex, n_length, tbs_hash, hash_size)]
                morpheous_res = subprocess.getoutput(cmd)
                return morpheous_res
            except InvalidSignature:
                return False
        elif sign_oid_map[sign_algo] == "sha384WithRSAEncryption":
            try:
                signature_mod = pow(int.from_bytes(signature, byteorder='big'), pk.public_numbers().e, pk.public_numbers().n)
                signature_mod_hex = '00' + signature_mod.to_bytes((signature_mod.bit_length() + 7) // 8, byteorder='big').hex()
                tbs_hash = hashlib.sha384(msg).hexdigest()
                n_length = pk.public_numbers().n.bit_length() // 8
                hash_size = 384
                cmd = ['./oracle {} {} {} {}'.format(signature_mod_hex, n_length, tbs_hash, hash_size)]
                morpheous_res = subprocess.getoutput(cmd)
                return morpheous_res
            except InvalidSignature:
                return False
        elif sign_oid_map[sign_algo] == "sha512WithRSAEncryption":
            try:
                signature_mod = pow(int.from_bytes(signature, byteorder='big'), pk.public_numbers().e, pk.public_numbers().n)
                signature_mod_hex = '00' + signature_mod.to_bytes((signature_mod.bit_length() + 7) // 8, byteorder='big').hex()
                tbs_hash = hashlib.sha512(msg).hexdigest()
                n_length = pk.public_numbers().n.bit_length() // 8
                hash_size = 512
                cmd = ['./oracle {} {} {} {}'.format(signature_mod_hex, n_length, tbs_hash, hash_size)]
                morpheous_res = subprocess.getoutput(cmd)
                return morpheous_res
            except InvalidSignature:
                return False
        elif sign_oid_map[sign_algo] == "sha224WithRSAEncryption":
            try:
                signature_mod = pow(int.from_bytes(signature, byteorder='big'), pk.public_numbers().e, pk.public_numbers().n)
                signature_mod_hex = '00' + signature_mod.to_bytes((signature_mod.bit_length() + 7) // 8, byteorder='big').hex()
                tbs_hash = hashlib.sha224(msg).hexdigest()
                n_length = pk.public_numbers().n.bit_length() // 8
                hash_size = 224
                cmd = ['./oracle {} {} {} {}'.format(signature_mod_hex, n_length, tbs_hash, hash_size)]
                morpheous_res = subprocess.getoutput(cmd)
                return morpheous_res
            except InvalidSignature:
                return False
        elif sign_oid_map[sign_algo] == "sha1WithRSAEncryption":
            try:
                signature_mod = pow(int.from_bytes(signature, byteorder='big'), pk.public_numbers().e, pk.public_numbers().n)
                signature_mod_hex = '00' + signature_mod.to_bytes((signature_mod.bit_length() + 7) // 8, byteorder='big').hex()
                tbs_hash = hashlib.sha1(msg).hexdigest()
                n_length = pk.public_numbers().n.bit_length() // 8
                hash_size = 1
                cmd = ['./oracle {} {} {} {}'.format(signature_mod_hex, n_length, tbs_hash, hash_size)]
                morpheous_res = subprocess.getoutput(cmd)
                return morpheous_res
            except InvalidSignature:
                return False
        else:
            print("Singnature algorithm {} is not supported - verification bypassed in certificate {}".format(sign_oid_map[sign_algo], i))
            return True
    else:
        print("Singnature algorithm {} is not supported - verification bypassed in certificate {}".format(int_to_hex(sign_algo).upper(), i))
        return True


def verifySignatures(trusted_ca_index):
    res = True
    for i in range(0, trusted_ca_index):
        res = verifySign(signatures[i], sign_oids[i], tbs_bytes[i], pks[i + 1], i + 1)

        if res == False:
            print("Failed to verify signature of certificate {}".format(i + 1))
            break
    return res
