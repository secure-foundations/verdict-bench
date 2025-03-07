"""
Generate a table to show the differential testing results
"""

import sys
import subprocess

bench_dir = f"{sys.path[0]}/.."
results_dir = f"{bench_dir}/results"
results = [
    ("CT", (
        ("Chrome", f"{results_dir}/diff-chrome.csv", f"{results_dir}/diff-verdict-chrome.csv"),
        ("Firefox", f"{results_dir}/diff-firefox.csv", f"{results_dir}/diff-verdict-firefox.csv"),
        ("OpenSSL", f"{results_dir}/diff-openssl.csv", f"{results_dir}/diff-verdict-openssl.csv"),
    )),
    ("Limbo", (
        ("Chrome", f"{results_dir}/limbo-chrome.csv", f"{results_dir}/limbo-verdict-chrome.csv"),
        ("Firefox", f"{results_dir}/limbo-firefox.csv", f"{results_dir}/limbo-verdict-firefox.csv"),
        ("OpenSSL", f"{results_dir}/limbo-openssl.csv", f"{results_dir}/limbo-verdict-openssl.csv"),
    )),
]

diff_command = [f"{bench_dir}/verdict/target/release/verdict", "diff-results"]

print("\\begin{tabular}{clrrrr}")
print("Test & Impl. & A/A & A/R & R/A & R/R \\\\")
print("\\hline")

for i, (suite, impls) in enumerate(results):
    if i != 0:
        print("\\hline")

    for j, (name, original_impl, our_impl) in enumerate(impls):
        res = subprocess.run(diff_command + [ original_impl, our_impl ], capture_output=True, text=True)

        class_tt = 0
        class_tf = 0
        class_ft = 0
        class_ff = 0

        matching_true_prefix = "matching class Singleton(\"true\"): "
        matching_false_prefix = "matching class Singleton(\"false\"): "

        for line in res.stdout.splitlines():
            if line.endswith("true vs false"):
                class_tf += 1
            elif line.endswith("false vs true"):
                class_ft += 1
            elif line.startswith(matching_true_prefix):
                class_tt = int(line[len(matching_true_prefix):])
            elif line.startswith(matching_false_prefix):
                class_ff = int(line[len(matching_false_prefix):])
            else:
                assert False, f"failure to diff {original_impl} and {our_impl}: unknown line {line}"

        # total = class_tt + class_tf + class_ft + class_ff

        prefix = f"\\multirow{{{len(impls)}}}{{*}}{{{suite}}} "
        print(f"{prefix if j == 0 else ''}& {name} & {class_tt:,} & {class_tf:,} & {class_ft:,} & {class_ff:,} \\\\")

print("\\end{tabular}")
