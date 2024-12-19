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

mpl.rcParams["font.size"] = 18
mpl.rcParams["axes.titlesize"] = 18
mpl.rcParams["axes.labelsize"] = 18
mpl.rcParams["xtick.labelsize"] = 18
mpl.rcParams["ytick.labelsize"] = 18
mpl.rcParams["legend.fontsize"] = 18

# List of implementations and their corresponding CSV file paths
implementations = [
    ("ARMOR", "../frontend/perf-results/results-armor-part-2.txt"),
    ("Hammurabi", "../frontend/perf-results/results-hammurabi-part-2.txt"),

    ("OpenSSL", "../frontend/perf-results/results-openssl-part-2.txt"),

    # ("Verdict/Chrome", "../frontend/perf-results/results-verdict-chrome-part-2.txt"),
    # ("Verdict/Chrome", "../frontend/perf-results/results-verdict-chrome-part-2-v2.txt"),
    # ("Verdict/Chrome 2", "../frontend/perf-results/results-verdict-chrome-part-2-v3.txt"),
    # ("Verdict/Chrome", "../frontend/perf-results/results-verdict-chrome-part-2-v4.txt"),
    # ("Verdict/Chrome", "../frontend/perf-results/results-verdict-chrome-part-2-v7.txt"),
    ("Verdict/Chrome", "../frontend/perf-results/results-verdict-chrome-part-2-v8.txt"),
    # ("Verdict/Firefox", "../frontend/perf-results/results-verdict-firefox-part-2.txt"),
    ("Verdict/OpenSSL", "../frontend/perf-results/results-verdict-openssl-part-2-v5.txt"),
    ("Verdict/Firefox", "../frontend/perf-results/results-verdict-firefox-part-2-v5.txt"),

    ("Firefox", "../frontend/perf-results/results-firefox-part-2.txt"),
    ("Chrome", "../frontend/perf-results/results-chrome-part-2.txt"),
]

all_data = []

for impl_label, csv_file in implementations:
    df = pd.read_csv(csv_file, header=None)

    num_columns = df.shape[1]
    num_sample_cols = num_columns - 4

    # Assign column names
    sample_cols = [f"sample{i + 1}" for i in range(num_sample_cols)]
    columns = ["hash", "hostname", "result", "err_msg"] + sample_cols
    df.columns = columns

    # Normalize the "result" column
    df["result"] = df["result"].astype(str).str.strip().str.lower()

    # Min performance for each row across all samples
    df["min_time"] = df[sample_cols].min(axis=1)
    df["impl"] = impl_label

    all_data.append(df[["impl", "result", "min_time"]])

# Concatenate all data into a single DataFrame
combined_df = pd.concat(all_data, ignore_index=True)

# Print some stats
print("\\begin{tabular}{lrrrr}")
print("Implementation & Mean & Median & Min & Max \\\\")
print("\\hline")
for impl in combined_df["impl"].unique():
    subset = combined_df[combined_df["impl"] == impl]
    # true_subset = subset[subset["result"] == "true"]

    stats_mean = int(subset["min_time"].mean())
    stats_median = int(subset["min_time"].median())
    stats_min = int(subset["min_time"].min())
    stats_max = int(subset["min_time"].max())

    print(f"{impl} & {stats_mean} & {stats_median} & {stats_min} & {stats_max} \\\\")

    # print(f"{impl}: {true_subset.shape[0]}/{subset.shape[0]} valid certs, mean {round(true_subset["min_time"].mean(), 2) if not true_subset.empty else 'N/A'}μs")
print("\\end{tabular}")

# Plotting the combined box plot
combined_df["result"] = combined_df["result"].replace({
    "true": "Accept",
    "false": "Reject"
})

# Define the two groups:
groupA = combined_df[combined_df["impl"].isin(["ARMOR", "Hammurabi"])]
groupB = combined_df[~combined_df["impl"].isin(["ARMOR", "Hammurabi"])]

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

plt.tight_layout(pad=0.1)
plt.savefig("performance.pdf")
plt.close()
