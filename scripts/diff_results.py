"""
Generate a table to show the differential testing results
"""

import sys
import argparse
import subprocess

from pathlib import Path

def print_table(args):
    results = [
        ("CT", (
            ("Chrome", f"{args.results}/diff-chrome.csv", f"{args.results}/diff-verdict-chrome.csv"),
            ("Firefox", f"{args.results}/diff-firefox.csv", f"{args.results}/diff-verdict-firefox.csv"),
            ("OpenSSL", f"{args.results}/diff-openssl.csv", f"{args.results}/diff-verdict-openssl.csv"),
        )),
        ("Limbo", (
            ("Chrome", f"{args.results}/limbo-chrome.csv", f"{args.results}/limbo-verdict-chrome.csv"),
            ("Firefox", f"{args.results}/limbo-firefox.csv", f"{args.results}/limbo-verdict-firefox.csv"),
            ("OpenSSL", f"{args.results}/limbo-openssl.csv", f"{args.results}/limbo-verdict-openssl.csv"),
        )),
    ]

    diff_command = [args.verdict_path, "diff-results"]

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

def main():
    repo_root = Path(__file__).parent.parent.absolute()
    parser = argparse.ArgumentParser(description="Generate a LaTeX tabular to show the differential testing results")
    parser.add_argument("-r", "--results", default=f"{repo_root}/results", help="Directory containing test results")
    parser.add_argument("--verdict-path", default=f"{repo_root}/verdict/target/release/verdict", help="Path to the Verdict binary")
    args = parser.parse_args()
    print_table(args)

if __name__ == "__main__":
    main()
