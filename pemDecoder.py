import sys
from base64 import *

from pem import *


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
    decoded_certchain_bytes = decodePem(args[1])
    decoded_rootcert_bytes = decodePem(args[2])

    if decoded_certchain_bytes[len(decoded_certchain_bytes) - 1] in decoded_rootcert_bytes:
        print("Trusted root CA: passed")
    else:
        print("Trusted root CA: failed")

    if (decoded_certchain_bytes != None):
        output = b''
        for c in decoded_certchain_bytes:
            output = output + c
        f = open('out1.txt', 'wb')
        f.write(output)
    else:
        print("Error: Failed to decode input PEM file")


if __name__ == "__main__":
    main()
