# import sys
#
# import pem
# from OpenSSL import crypto
# import helpers
#
#
# def verify_certificate_chain(cert_chain_path, trusted_certs_path):
#     try:
#         # process given cert chain
#         cert_chain = []
#         for c in pem.parse_file(cert_chain_path):
#             cert = crypto.load_certificate(crypto.FILETYPE_PEM, str(c))
#             cert_chain.append(cert)
#
#         # process given trusted certs
#         trusted_store = crypto.X509Store()
#         for c in pem.parse_file(trusted_certs_path):
#             cert = crypto.load_certificate(crypto.FILETYPE_PEM, str(c))
#             trusted_store.add_cert(cert)
#
#         # Create a certificate context using the store and the downloaded certificate
#         store_ctx = crypto.X509StoreContext(trusted_store, cert_chain[0], cert_chain[1:])
#
#         # Verify the certificate, returns None if it can validate the certificate
#         store_ctx.verify_certificate()
#         # print("success")
#
#         # process returns
#         result = []
#         i = 0
#         for cert in cert_chain:
#             i = i+ 1
#             # if i == 3:
#                 # print("@@@@@@")
#                 # print(cert.to_cryptography().tbs_certificate_bytes)
#                 # print(cert.to_cryptography().signature)
#                 # print(cert.to_cryptography().signature_algorithm_oid)
#                 # print(cert.to_cryptography().signature_hash_algorithm)
#                 # print(cert.to_cryptography().public_key().public_numbers().e)
#                 # print(cert.to_cryptography().public_key().public_numbers().n)
#             cert_crypto = cert.to_cryptography()
#
#             tbs_cert_bytes = cert_crypto.tbs_certificate_bytes.hex(" ", 1)
#             # print(tbs_cert_bytes, "@@@")
#
#             public_key_value = cert_crypto.public_key()
#             # print("@@@@@@@@@@@@@@@")
#             # print(crypto.dump_publickey(crypto.FILETYPE_ASN1, cert.get_pubkey()))
#             x = crypto.dump_publickey(crypto.FILETYPE_ASN1, cert.get_pubkey()).hex(" ", 1)
#             print(x)
#             return x
#
#
#             # print(crypto.dump_publickey(crypto.FILETYPE_ASN1, cert.get_pubkey()).hex(" ", 1))
#
#             signature_type = cert_crypto.signature_algorithm_oid._name
#             # print(signature_type)
#
#             signature_value = cert_crypto.signature.hex(" ", 1)
#             # print(public_key_value, "@@@@")
#
#
#             # result.append([signature_value])
#
#
#         # f = open("data.txt", "wb")
#         # for x in result:
#         #     f.write(b"***************\n")
#         #     for y in x:
#         #         f.write(y)
#         #         f.write(b"\n")
#
#
#
#         return True
#     except Exception as e:
#         print(e)
#         raise
#         return False
#
#
# # def read_data_file():
# #     f = open("data.txt", "rb")
# #     lines = f.readlines()
# #
# #     print(len(lines), "########")
# #     for line in lines:
# #         if line == b"***************\n":
# #             print("*********")
# #             continue
# #         print(line.hex())
#
#
#
# def main():
#     args = sys.argv
#
#     # call verify with command line arguments: arg1 = cert chain path, arg2 = trusted-root store
#     result = verify_certificate_chain(args[1], args[2])
#     # print(result)
#
#     # read_data_file()
#     return result
#
#
# if __name__ == "__main__":
#     result = main()
#     sys.exit(result)
