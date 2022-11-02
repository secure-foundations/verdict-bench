import sys
from helpers import *

f = open("temp.txt", "wb")
f.write(hex_to_bytes(sys.argv[1]))
f.close()