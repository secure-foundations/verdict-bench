"""
Analyze and summarize the output of test_end_to_end.py
"""

import re
import argparse
import statistics


def read_results(path, suffix=""):
    # name: [(default, <name>_result)]
    results = {}
    p_values = []

    # Read results
    with open(path) as f:
        content = f.read()

        match = re.search(r"all p-values: \[(.*)\]", content)
        assert match is not None

        for match in re.finditer(r"np.float64\(([\d.e\-]+)\)", match.group(1)):
            p_values.append(float(match.group(1)))

        match = re.search(r"all percentage diff: (\[.*\])", content)
        assert match is not None
        percent_diffs = eval(match.group(1))

        for p_value, percent_diff, match in zip(p_values, percent_diffs, re.finditer(r"default: ([\d.e\-]+), ([\w\-]+): ([\d.e\-]+) \((-?[\d.e\-]+)%\), t-stat: -?[\d.e\-]+, p-value: ([\d.e\-]+)", content)):
            name = match.group(2) + suffix
            if name not in results:
                results[name] = []

            assert abs(percent_diff - float(match.group(4))) < 0.01
            assert abs(p_value - float(match.group(5))) < 0.01
            results[name].append((float(match.group(1)), float(match.group(3)), percent_diff, p_value))

    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("results_aws_lc", help="Output of test_end_to_end.py for the AWS-LC version")
    parser.add_argument("results_libcrux", help="Output of test_end_to_end.py for the libcrux version")
    args = parser.parse_args()

    results_aws_lc = read_results(args.results_aws_lc, "-aws-lc")
    results_libcrux = read_results(args.results_libcrux)

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
    for name, result in list(results_libcrux.items()) + list(results_aws_lc.items()):
        num_insig = 0
        num_outperforms = 0
        num_lower = 0

        for _, _, perc, p in result:
            if p >= 0.05:
                num_insig += 1

            if perc < 0 and p < 0.05:
                num_outperforms += 1

            if perc >= 0 and p < 0.05:
                num_lower += 1

        # Filter out outliers
        result = list(filter(lambda t: -10 < t[2] < 10,result))

        gmean = (statistics.geometric_mean(map(lambda t: t[2] / 100 + 1, result)) - 1) * 100
        max_mean = (max(map(lambda t: t[2] / 100 + 1, result)) - 1) * 100
        min_mean = (min(map(lambda t: t[2] / 100 + 1, result)) - 1) * 100

        print(f"{display_names[name]} & {round(gmean, 2)}\\% & {round(max_mean, 2)}\\% & {round(min_mean, 2)}\\% & {num_insig} & {num_outperforms} & {num_lower} \\\\")

    print(r"\end{tabular}")


if __name__ == "__main__":
    main()
