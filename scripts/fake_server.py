"""
Using the output of fake_server_certs.py, actually start a TLS server with the given certificates.
"""

import os
import sys
import ssl
import socket
import argparse


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, flush=True, **kwargs)


def recv_full_http_request(conn):
    # Assuming the HTTP request is from rustls/tlsclient-mio
    # which has a known size less than 1024 bytes
    return conn.recv(1024)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("setup", help="Path to a specific domain in the output of fake_server_certs.py")

    parser.add_argument("--host", default="localhost", help="Hostname to listen on")
    parser.add_argument("--port", type=int, default=443, help="Port to listen on")

    args = parser.parse_args()

    response_path = os.path.join(args.setup, "response.txt")
    chain_path = os.path.join(args.setup, "chain.pem")
    key_path = os.path.join(args.setup, "key.pem")

    with open(response_path, "rb") as f:
        response = f.read()

    # Create an SSL context with TLS server settings
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=chain_path, keyfile=key_path)

    # Start a TLS server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((args.host, args.port))
            sock.listen(5)
            eprint(f"[*] server listening on {args.host}:{args.port}...")

            while True:
                client_sock, addr = sock.accept()
                # print(f"[*] connection from {addr}")

                try:
                    # Wrap the client socket with TLS
                    with context.wrap_socket(client_sock, server_side=True) as tls_conn:
                        recv_full_http_request(tls_conn)
                        tls_conn.sendall(response)
                        # print(f"[*] closing connection to {addr}")

                except Exception as e:
                    eprint(f"[!] error with {addr}: {e}")

                finally:
                    client_sock.close()
        except KeyboardInterrupt:
            eprint(f"[*] server shutting down")

        finally:
            sock.close()


if __name__ == "__main__":
    main()
