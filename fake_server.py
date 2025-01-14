"""
Using the output of fake_server_certs.py, actually start a TLS server with the given certificates.
"""

import os
import ssl
import socket
import argparse


def recv_full_http_request(conn):
    request_data = b""

    while True:
        chunk = conn.recv(1024)
        if not chunk: break
        request_data += chunk

        # Check if end of HTTP headers has been reached
        if b"\r\n\r\n" in request_data:
            break

    return request_data


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
        sock.bind((args.host, args.port))
        sock.listen(5)
        print(f"[*] server listening on {args.host}:{args.port}...")

        while True:
            client_sock, addr = sock.accept()
            print(f"[*] connection from {addr}")

            try:
                # Wrap the client socket with TLS
                with context.wrap_socket(client_sock, server_side=True) as tls_conn:
                    print(recv_full_http_request(tls_conn))
                    tls_conn.sendall(response)
                    print(f"[*] closing connection to {addr}")

            except Exception as e:
                print(f"[!] error with {addr}: {e}")

            finally:
                client_sock.close()


if __name__ == "__main__":
    main()
