"""
Analyze and summarize the output of test_end_to_end.py
"""

from typing import Dict, List

import re
import csv
import argparse
import statistics
from scipy import stats


def read_results(csv_path: str, suffix: str) -> Dict[str, Dict[str, List[int]]]:
    # { domain: { validator: samples } }
    all_samples = {}

    with open(csv_path) as f:
        reader = csv.DictReader(f)

        for row in reader:
            domain = row["domain"]
            validator = row["validator"]

            if validator != "default":
                validator += suffix

            samples = list(map(int, row["samples"].split(",")))

            if domain not in all_samples:
                all_samples[domain] = {}

            assert validator not in all_samples[domain], f"duplicate validator samples for domain {domain}"
            all_samples[domain][validator] = samples

    return all_samples


def analyze_results(results: Dict[str, Dict[str, List[int]]]) -> Dict[str, Dict[str, List[float]]]:
    """
    Return results of statistical tests: for each domain, we perform t-test on the samples of "default" against each "verdict-*" validator
    { domain: { non-default-validator: [t_stat, p_value, change in the mean] } }
    """
    
    stat_tests = {}

    for domain, all_samples in results.items():
        assert "default" in all_samples

        default_samples_mean = statistics.mean(all_samples["default"])

        for validator, samples in all_samples.items():
            if validator == "default":
                continue

            if domain not in stat_tests:
                stat_tests[domain] = {}

            samples_mean = statistics.mean(samples)
            change_ratio = samples_mean / default_samples_mean
            
            t_stat, p_value = stats.ttest_ind(all_samples["default"], samples, equal_var=False)
            stat_tests[domain][validator] = [t_stat, p_value, change_ratio]

    return stat_tests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("results_aws_lc", help="Output CSV of test_end_to_end.py for the AWS-LC version")
    parser.add_argument("results_libcrux", help="Output CSV of test_end_to_end.py for the libcrux version")
    args = parser.parse_args()

    results_aws_lc = read_results(args.results_aws_lc, "-aws-lc")
    results_libcrux = read_results(args.results_libcrux, "")

    stats_aws_lc = analyze_results(results_aws_lc)
    stats_libcrux = analyze_results(results_libcrux)

    stats_merged = { domain: { **stats_aws_lc[domain], **stats_libcrux[domain] } for domain in stats_aws_lc }

    validators = ["verdict-chrome-aws-lc", "verdict-firefox-aws-lc", "verdict-openssl-aws-lc", "verdict-chrome", "verdict-firefox", "verdict-openssl"]
    display_names = {
        "verdict-chrome-aws-lc": "V/Chrome$^\\star$",
        "verdict-firefox-aws-lc": "V/Firefox$^\\star$",
        "verdict-openssl-aws-lc": "V/OpenSSL$^\\star$",
        "verdict-chrome": "V/Chrome",
        "verdict-firefox": "V/Firefox",
        "verdict-openssl": "V/OpenSSL",
    }

    print(r"\begin{tabular}{lrrrrrr}")
    print(r"Impl. & Mean & Max & Min & $\approx$ & $+$ & $-$ \\")
    print(r"\hline")
    for validator in validators:
        num_insig = 0
        num_outperforms = 0
        num_lower = 0
        change_ratios = []

        for stats in stats_merged.values():
            _, p_value, change_ratio = stats[validator]

            if p_value >= 0.05:
                num_insig += 1

            if change_ratio < 1 and p_value < 0.05:
                num_outperforms += 1

            if change_ratio >= 1 and p_value < 0.05:
                num_lower += 1

            change_ratios.append(change_ratio)

        # # Filter out outliers
        # result = list(filter(lambda t: -10 < t[2] < 10,result))

        gmean = (statistics.geometric_mean(change_ratios) - 1) * 100
        max_mean = (max(change_ratios) - 1) * 100
        min_mean = (min(change_ratios) - 1) * 100

        print(f"{display_names[validator]} & {round(gmean, 2)}\\% & {round(max_mean, 2)}\\% & {round(min_mean, 2)}\\% & {num_insig} & {num_outperforms} & {num_lower} \\\\")

    print(r"\end{tabular}")


if __name__ == "__main__":
    main()
