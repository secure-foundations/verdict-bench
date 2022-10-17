def hex_to_int(inp):
    res = ""
    for x in inp.strip().split(" "):
        res = res + str(int(x, 16)) + " "
    return res.strip()


def int_to_hex(inp):
    res = ""
    for x in inp.strip().split(" "):
        res = res + " " + '{:02x}'.format(int(x))
    return res


def hex_to_bytes(inp):
    return bytes.fromhex(inp)


def int_to_Bytes(inp):
    return hex_to_bytes(int_to_hex(inp))
