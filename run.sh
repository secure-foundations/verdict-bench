#!/bin/bash


rm out1.txt
rm out2.txt

cert_chain_file=$1
root_store_file=$2

python3 pemDecoder.py $cert_chain_file $root_store_file
cat out1.txt | ./aeres > out2.txt
python3 verifySignature.py out2.txt
