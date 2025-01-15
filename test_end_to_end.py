"""
Perform end-to-end tests of Rustls performance (w/ or w/o Verdict)
"""

from typing import List

import os
import time
import signal
import argparse
import subprocess
import statistics

from scipy import stats


WARMUP = 20
REPEAT = 50

VALIDATORS = [ "default", "verdict-chrome", "verdict-firefox", "verdict-openssl" ]


def test_domain(path, domain, port, rustls_client, isolated_cores) -> List[List[int]]:
    """
    1. Start an HTTPS server locally
    2. Call rustls_client to collect samples
    """

    assert len(isolated_cores) >= 2

    server_proc = subprocess.Popen([
        "taskset", "-c", isolated_cores[0],
        "python3", "fake_server.py",
        "--host", "localhost",
        "--port", str(port), os.path.join(path, domain),
    ], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    # Wait for server to start
    while True:
        line = server_proc.stdout.readline()
        if not line:
            print("failed to start server")
            server_proc.send_signal(signal.SIGINT)
            server_proc.wait()
            return

        if "server listening" in line.rstrip():
            print("server started")
            break

    try:
        all_samples = []

        for validator in VALIDATORS:
            result = subprocess.run([
                "taskset", "-c", isolated_cores[1],
                rustls_client,
                "--connect", "localhost",
                "--port", str(port),
                "--cafile", os.path.join(path, "roots.pem"),
                "--http",
                "--repeat", str(WARMUP + REPEAT),
                "--validator", validator,
                domain,
            ], capture_output=True, text=True)

            if "error" in result.stderr:
                print(f"rustls failed to connect")

            if result.returncode != 0:
                print(f"rustls returned non-zero exit code {result.returncode}")

            samples = result.stdout.strip().split()
            assert len(samples) == WARMUP + REPEAT, f"unmatched sample number {len(samples)}"
            all_samples.append(list(map(int, samples))[WARMUP:])

        return all_samples
    finally:
        server_proc.send_signal(signal.SIGINT)
        server_proc.wait()


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("fake_servers", help="Output of fake_server_certs.py")
    parser.add_argument("rustls_client", help="Path to tlsclient-mio in Rustls")
    parser.add_argument("--port", type=int, default=1234, help="Port to bind for the test server")
    parser.add_argument("--cores", default="2,4", help="Isolated cores for test (e.g. --cores 1,2,3,4)")
    parser.add_argument("--delay", default="1ms", help="Impose simulated network delay (e.g. 10ms)")
    args = parser.parse_args()

    isolated_cores = args.cores.split(",")

    try:
        set_network_delay(args.port, args.delay)

        for domain in os.listdir(args.fake_servers):
            full_path = os.path.join(args.fake_servers, domain)
            if os.path.isdir(full_path):
                print(f"### testing domain {domain} ({full_path})", flush=True)
                start = time.time()
                samples = test_domain(args.fake_servers, domain, args.port, args.rustls_client, isolated_cores)
                print(f"took {round(time.time() - start, 2)} s")

                if samples is not None and len(samples) != 0:
                    # Perform statistical test of samples[0] against samples[1], ..., samples[-1]

                    samples_0_mean = statistics.mean(samples[0])

                    for i in range(1, len(samples)):
                        samples_i_mean = statistics.mean(samples[i])
                        change_perc = round((samples_i_mean - samples_0_mean) / samples_0_mean * 100, 2)
                        t_stat, p_value = stats.ttest_ind(samples[0], samples[i], equal_var=False)
                        print(f"{VALIDATORS[0]}: {samples_0_mean}, {VALIDATORS[i]}: {samples_i_mean} ({change_perc}%), t-stat: {round(t_stat, 3)}, p-value: {round(p_value, 3)}")

    finally:
        reset_network_delay()


if __name__ == "__main__":
    main()
