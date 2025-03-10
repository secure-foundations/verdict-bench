"""
Generate a boxplot of performance comparison between implementations
"""

import sys
import csv
import argparse

from pathlib import Path

import pandas as pd
import matplotlib as mpl
import matplotlib.pyplot as plt
import matplotlib.backends.backend_pdf
import seaborn as sns

# Set up the same font as the USENIX security template
# mpl.rcParams["text.usetex"] = True
# mpl.rcParams["font.family"] = "serif"
# mpl.rcParams["font.serif"] = ["Times"]
# mpl.rcParams["text.latex.preamble"] = r"\usepackage{mathptmx}"

mpl.rcParams["font.size"] = 24
mpl.rcParams["axes.titlesize"] = 24
mpl.rcParams["axes.labelsize"] = 24
mpl.rcParams["xtick.labelsize"] = 24
mpl.rcParams["ytick.labelsize"] = 24
mpl.rcParams["legend.fontsize"] = 24

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def print_table(args):
    """
    Load and print a table showing performance statistics
    """

    # List of implementations and their corresponding CSV file paths
    implementations = [
        ("CERES", f"{args.results}/perf-ceres.csv"),
        ("ARMOR", f"{args.results}/perf-armor.csv"),
        ("HM/Firefox", f"{args.results}/perf-hammurabi-firefox.csv"),
        ("HM/Chrome", f"{args.results}/perf-hammurabi-chrome.csv"),
        ("Chrome", f"{args.results}/perf-chrome.csv"),
        ("V/Chrome", f"{args.results}/perf-verdict-chrome.csv"),
        ("V/Chrome*", f"{args.results}/perf-verdict-chrome-aws-lc.csv"),
        ("Firefox", f"{args.results}/perf-firefox.csv"),
        ("V/Firefox", f"{args.results}/perf-verdict-firefox.csv"),
        ("V/Firefox*", f"{args.results}/perf-verdict-firefox-aws-lc.csv"),
        ("OpenSSL", f"{args.results}/perf-openssl.csv"),
        ("V/OpenSSL", f"{args.results}/perf-verdict-openssl.csv"),
        ("V/OpenSSL*", f"{args.results}/perf-verdict-openssl-aws-lc.csv"),
    ]

    all_data = []

    for impl_label, csv_file in implementations:
        eprint(f"% processing data for {impl_label} at {csv_file}")

        # Determine the number of columns
        with open(csv_file, "r", newline="") as f:
            reader = csv.reader(f)
            num_measurements = len(next(reader)) - 4

        df = pd.read_csv(csv_file, header=None, dtype={
            0: "str",
            1: "str",
            2: "str",
            3: "str",
            **{
                i: "int64"
                for i in range(4, 4 + num_measurements)
            }
        }, usecols=[2] + list(range(4, 4 + num_measurements)), engine="c")

        # Assign column names
        sample_cols = [f"sample{i + 1}" for i in range(num_measurements)]
        columns = ["result"] + sample_cols
        df.columns = columns

        # Normalize the "result" column
        df["result"] = df["result"].str.strip().str.lower()

        # Min performance for each row across all samples
        df["min_time"] = df[sample_cols].min(axis=1)
        df["impl"] = impl_label

        all_data.append(df[["impl", "result", "min_time"]])

    # Concatenate all data into a single DataFrame
    combined_df = pd.concat(all_data, ignore_index=True)
    combined_df = combined_df[["impl", "min_time", "result"]]

    # Print some stats
    print("\\begin{tabular}{lrrrr}")
    print("Impl. & Mean & Median & Min & Max \\\\")
    print("\\hline")

    grouped = combined_df.groupby("impl")
    sorted_impls = sorted(grouped, key=lambda x: x[1]["min_time"].mean())
    for impl, subset in sorted_impls:
        stats_mean = int(subset["min_time"].mean())
        stats_median = int(subset["min_time"].median())
        stats_min = int(subset["min_time"].min())
        stats_max = int(subset["min_time"].max())

        print(f"{impl} & {stats_mean:,} & {stats_median:,} & {stats_min:,} & {stats_max:,} \\\\")
        # print(f"{impl}: {true_subset.shape[0]}/{subset.shape[0]} valid certs, mean {round(true_subset["min_time"].mean(), 2) if not true_subset.empty else 'N/A'}μs")
    print("\\end{tabular}")

    return combined_df

def plot_comparison(args, combined_df):
    """
    Generate a boxplot comparing a subset of implementations
    """

    slow_group = ["CERES", "ARMOR", "HM/Firefox", "HM/Chrome"]

    # Plotting the combined box plot
    combined_df["result"] = combined_df["result"].replace({
        "true": "Accept",
        "false": "Reject"
    })

    plt.figure(figsize=(20, 4.5))

    combined_df = combined_df[~combined_df["impl"].isin(slow_group)]

    eprint("% plotting...")

    sns.boxplot(
        x="impl", y="min_time", data=combined_df,
        showfliers=False,
        hue="result",
        palette={"Accept": "#40B0A6", "Reject": "#E1BE6A"},
    ).legend(title="Result", loc="upper left")
    plt.xlabel("")
    plt.ylabel("Performance (μs)")
    # plt.ylim(0, 300)

    # Draw vertical separators for every 3 items
    num_categories = len(combined_df["impl"].unique())
    line_positions = [i - 0.5 for i in range(3, num_categories + 1, 3)]
    for xpos in line_positions:
        plt.axvline(x=xpos, color="gray", linestyle="dashed")

    plt.tight_layout(pad=0.1)
    eprint(f"% saving to {args.output}...")
    plt.savefig(args.output)
    plt.close()

def main():
    repo_root = Path(__file__).parent.parent.absolute()
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--results", default=f"{repo_root}/results", help="Directory containing performance benchmark results")
    parser.add_argument("-o", "--output", help="Output PDF plot")
    args = parser.parse_args()

    combined_df = print_table(args)
    if args.output:
        plot_comparison(args, combined_df)

if __name__ == "__main__":
    main()
