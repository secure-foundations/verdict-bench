"""
Generate a boxplot of performance comparison between implementations
"""

import pandas as pd
import matplotlib as mpl
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns

# Set up the same font as the USENIX security template
mpl.rcParams["text.usetex"] = True
mpl.rcParams["font.family"] = "serif"
mpl.rcParams["font.serif"] = ["Times"]
mpl.rcParams["text.latex.preamble"] = r"\usepackage{mathptmx}"

mpl.rcParams["font.size"] = 22
mpl.rcParams["axes.titlesize"] = 22
mpl.rcParams["axes.labelsize"] = 22
mpl.rcParams["xtick.labelsize"] = 22
mpl.rcParams["ytick.labelsize"] = 22
mpl.rcParams["legend.fontsize"] = 22

slow_group = ["CERES", "ARMOR", "HM/Firefox", "HM/Chrome"]

# List of implementations and their corresponding CSV file paths
implementations = [
    ("CERES", "~/work/verdict-bench/bench-results/ceres.txt"),
    ("ARMOR", "~/work/verdict-bench/bench-results/armor.txt"),
    ("HM/Firefox", "~/work/verdict-bench/bench-results/hammurabi-firefox.txt"),
    ("HM/Chrome", "~/work/verdict-bench/bench-results/hammurabi-chrome.txt"),

    ("OpenSSL", "~/work/verdict-bench/bench-results/openssl.txt"),
    ("\\textbf{V/OpenSSL}", "~/work/verdict-bench/bench-results/verdict-openssl.txt"),
    ("\\textbf{V/OpenSSL$^\\star$}", "~/work/verdict-bench/bench-results/verdict-openssl-aws-lc.txt"),

    ("Firefox", "~/work/verdict-bench/bench-results/firefox.txt"),
    ("\\textbf{V/Firefox}", "~/work/verdict-bench/bench-results/verdict-firefox.txt"),
    ("\\textbf{V/Firefox$^\\star$}", "~/work/verdict-bench/bench-results/verdict-firefox-aws-lc.txt"),

    ("Chrome", "~/work/verdict-bench/bench-results/chrome.txt"),
    ("\\textbf{V/Chrome}", "~/work/verdict-bench/bench-results/verdict-chrome.txt"),
    ("\\textbf{V/Chrome$^\\star$}", "~/work/verdict-bench/bench-results/verdict-chrome-aws-lc.txt"),
]

num_measurements = 10

all_data = []

for impl_label, csv_file in implementations:
    print(f"### Processing data for {impl_label} at {csv_file}")

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

# Plotting the combined box plot
combined_df["result"] = combined_df["result"].replace({
    "true": "Accept",
    "false": "Reject"
})


def plot_two_groups(combined_df):
    # Define the two groups:
    groupA = combined_df[combined_df["impl"].isin(slow_group)]
    groupB = combined_df[~combined_df["impl"].isin(slow_group)]

    num_cats_A = groupA["impl"].nunique()  # number of categories in group A
    num_cats_B = groupB["impl"].nunique()  # number of categories in group B

    width_per_category = 2
    total_width = (num_cats_A + num_cats_B) * width_per_category
    fig = plt.figure(figsize=(total_width, 5))

    gs = gridspec.GridSpec(1, 2, width_ratios=[num_cats_A, num_cats_B])
    ax1 = fig.add_subplot(gs[0])
    ax2 = fig.add_subplot(gs[1])

    # Left plot: ARMOR and Hammurabi
    sns.boxplot(
        ax=ax1,
        x="impl", y="min_time", data=groupA,
        flierprops=dict(marker=".", color="black", alpha=0.3, markersize=3, markeredgewidth=0.5),
        boxprops=dict(linewidth=0.5),
        whiskerprops=dict(linewidth=0.5),
        capprops=dict(linewidth=0.5),
        medianprops=dict(linewidth=0.5),
        hue="result",
        palette={"Accept": "#40B0A6", "Reject": "#E1BE6A"},
    )
    ax1.set_xlabel("")
    ax1.set_ylabel("Validation time (microseconds)")
    ax1.set_yscale("log")
    ax1.legend_.remove()  # Remove legend here and add it once on the second plot or outside

    # Right plot: Others
    sns.boxplot(
        ax=ax2,
        x="impl", y="min_time", data=groupB,
        flierprops=dict(marker=".", color="black", alpha=0.3, markersize=3, markeredgewidth=0.5),
        boxprops=dict(linewidth=0.5),
        whiskerprops=dict(linewidth=0.5),
        capprops=dict(linewidth=0.5),
        medianprops=dict(linewidth=0.5),
        hue="result",
        palette={"Accept": "#40B0A6", "Reject": "#E1BE6A"},
    ).legend(title="Result", loc="upper right")
    ax2.set_xlabel("")
    ax2.set_ylabel("")
    ax2.set_ylim(0, 260)
    # ax2.set_yscale("log")


def plot_simple(combined_df):
    plt.figure(figsize=(20, 5))

    combined_df = combined_df[~combined_df["impl"].isin(slow_group)]

    print("plotting...")

    sns.boxplot(
        x="impl", y="min_time", data=combined_df,
        # flierprops=dict(marker=".", color="black", alpha=0.1),
        # boxprops=dict(linewidth=0.5),
        # whiskerprops=dict(linewidth=0.5),
        # capprops=dict(linewidth=0.5),
        # medianprops=dict(linewidth=0.5),
        showfliers=False,
        hue="result",
        palette={"Accept": "#40B0A6", "Reject": "#E1BE6A"},
    ).legend(title="Result", loc="upper left")
    plt.xlabel("")
    plt.ylabel("Performance (microseconds)")
    plt.ylim(0, 300)

    # Draw vertical separators for every 3 items
    num_categories = len(combined_df["impl"].unique())
    line_positions = [i - 0.5 for i in range(3, num_categories + 1, 3)]
    for xpos in line_positions:
        plt.axvline(x=xpos, color="gray", linestyle="dashed")

# plot_two_groups(combined_df)
plot_simple(combined_df)

plt.tight_layout(pad=0.1)
print("saving...")
plt.savefig("performance.pdf")
plt.close()
