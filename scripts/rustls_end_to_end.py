"""
Perform end-to-end tests of Rustls performance (w/ and w/o Verdict)
"""

from typing import List, Optional, Iterator

import os
import sys
import ssl
import csv
import time
import socket
import signal
import argparse
import subprocess
import multiprocessing


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, flush=True, **kwargs)


def fake_server(
    start_event,
    response: bytes,
    chain_path: str,
    key_path: str,
    host: str,
    port: int,
    affinity: Optional[Iterator[int]] = None,
):
    """
    Start a HTTPS server that always responds with the content in `response`
    and uses the given certificate chain and private key
    """

    # Set CPU affinity if specified
    if affinity is not None:
        os.sched_setaffinity(os.getpid(), affinity)

    # Create an SSL context with TLS server settings
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=chain_path, keyfile=key_path)

    # Start a TLS server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.listen(5)
            eprint(f"[*] server listening on {host}:{port}...")

            start_event.set()

            while True:
                client_sock, addr = sock.accept()

                try:
                    # TLS connection
                    with context.wrap_socket(client_sock, server_side=True) as tls_conn:
                        # Assuming the HTTP request is from rustls/tlsclient-mio
                        # which has a known size less than 1024 bytes
                        tls_conn.recv(1024)
                        tls_conn.sendall(response)

                except Exception as e:
                    eprint(f"[!] error with {addr}: {e}")

                finally:
                    client_sock.close()

        except KeyboardInterrupt:
            eprint(f"[*] server shutting down")

        finally:
            sock.close()


def test_domain(
    path: str,
    domain: str,
    port: int,
    rustls_client: str,
    validators: List[str],
    isolated_cores: List[int],
    warmup: int,
    repeat: int,
) -> List[List[int]]:
    """
    1. Start an HTTPS server locally
    2. Call rustls_client to collect samples
    """

    assert len(isolated_cores) >= 2

    domain_data_path = os.path.join(path, domain)
    response_path = os.path.join(domain_data_path, "response.txt")
    chain_path = os.path.join(domain_data_path, "chain.pem")
    key_path = os.path.join(domain_data_path, "key.pem")
    roots_path = os.path.join(path, "roots.pem")

    # Read response
    with open(response_path, "rb") as f:
        response = f.read()

    server_start_event = multiprocessing.Event()
    server_proc = multiprocessing.Process(
        target=fake_server,
        args=(
            server_start_event,
            response,
            chain_path,
            key_path,
            "127.0.0.1",
            port,
            [int(isolated_cores[0])],
        ),
    )
    server_proc.start()

    # Wait for server to start
    if not server_start_event.wait(timeout=5):
        eprint("[!] failed to start server")
        server_proc.terminate()
        server_proc.join()
        return

    try:
        all_samples = []

        for validator in validators:
            result = subprocess.run([
                "taskset", "-c", str(isolated_cores[1]),
                rustls_client,
                "--connect", "127.0.0.1",
                "--port", str(port),
                "--cafile", roots_path,
                "--http",
                "--repeat", str(warmup + repeat),
                "--validator", validator,
                domain,
            ], capture_output=True, text=True)

            if result.returncode != 0:
                eprint(f"[!] rustls returned non-zero exit code {result.returncode}:")
                eprint(result.stderr)

            samples = result.stdout.strip().split()
            assert len(samples) == warmup + repeat, f"unexpected output from rustls: unmatched sample number {len(samples)}"
            all_samples.append(list(map(int, samples))[warmup:])

        return all_samples

    finally:
        os.kill(server_proc.pid, signal.SIGINT)
        server_proc.join()


def set_network_delay(port, delay):
    # Add priority qdisc
    subprocess.run(["sudo", "tc", "qdisc", "add", "dev", "lo", "root", "handle", "1:", "prio"], check=True)

    # Add netem delay
    subprocess.run(["sudo", "tc", "qdisc", "add", "dev", "lo", "parent", "1:3", "handle", "30:", "netem", "delay", delay], check=True)

    # Add outbound filter
    subprocess.run([
        "sudo", "tc", "filter", "add", "dev", "lo", "protocol", "ip", "parent", "1:", "prio", "1",
        "u32", "match", "ip", "sport", str(port), "0xffff", "flowid", "1:3"
    ], check=True)

    # Add inbound filter
    subprocess.run([
        "sudo", "tc", "filter", "add", "dev", "lo", "protocol", "ip", "parent", "1:", "prio", "1",
        "u32", "match", "ip", "dport", str(port), "0xffff", "flowid", "1:3"
    ], check=True)


def reset_network_delay():
    subprocess.run(["sudo", "tc", "qdisc", "del", "dev", "lo", "root"], check=True)


def analyze_results(domain: str, samples: List[List[int]]):
    """
    Analyze the output samples and write results to the output file
    """


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("fake_servers", help="Output of fake_server_certs.py")
    parser.add_argument("rustls_client", help="Path to tlsclient-mio in Rustls")
    parser.add_argument("--port", type=int, default=1234, help="Port to bind for the test server")
    parser.add_argument("--cores", default="2,4", help="Isolated cores for test (e.g. --cores 1,2,3,4)")
    parser.add_argument("--delay", default="1ms", help="Impose simulated network delay (e.g. 10ms)")
    parser.add_argument("--warmup", type=int, default=20, help="Number of samples to discard")
    parser.add_argument("--repeat", type=int, default=100, help="Number of samples to collect")
    parser.add_argument("--validators", default="default,verdict-chrome,verdict-firefox,verdict-openssl", help="Validators to test in Rustls (comma-separated)")
    parser.add_argument("-o", "--output", help="Output CSV file")
    args = parser.parse_args()

    isolated_cores = list(map(int, args.cores.split(",")))
    validators = args.validators.split(",")

    with (open(args.output, "w") if args.output is not None
        else os.fdopen(os.dup(sys.stdout.fileno()), "w")) as f:
        writer = csv.writer(f)
        writer.writerow(["domain", "validator", "samples"])

        try:
            set_network_delay(args.port, args.delay)

            for domain in os.listdir(args.fake_servers):
                full_path = os.path.join(args.fake_servers, domain)

                if os.path.isdir(full_path):
                    eprint(f"### testing domain {domain} ({full_path})")

                    start = time.time()
                    all_samples = test_domain(
                        args.fake_servers,
                        domain,
                        args.port,
                        args.rustls_client,
                        validators,
                        isolated_cores,
                        args.warmup,
                        args.repeat,
                    )
                    eprint(f"[*] took {round(time.time() - start, 2)} s")

                    assert len(all_samples) == len(validators)

                    for validator, samples in zip(validators, all_samples):
                        writer.writerow([domain, validator, ",".join(map(str, samples))])

                    # if samples is not None and len(samples) != 0:
                    #     # Perform statistical test of samples[0] against samples[1], ..., samples[-1]
                    #     samples_0_mean = statistics.mean(samples[0])
                    #     for i in range(1, len(samples)):
                    #         samples_i_mean = statistics.mean(samples[i])
                    #         change_perc = (samples_i_mean - samples_0_mean) / samples_0_mean * 100
                    #         t_stat, p_value = stats.ttest_ind(samples[0], samples[i], equal_var=False)
                    #         print(f"{validators[0]}: {samples_0_mean}, {validators[i]}: {samples_i_mean} ({round(change_perc, 2)}%), t-stat: {round(t_stat, 3)}, p-value: {round(p_value, 3)}")

        finally:
            reset_network_delay()


if __name__ == "__main__":
    main()
