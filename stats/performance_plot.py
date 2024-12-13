import pandas as pd
import matplotlib as mpl
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns

# Use LaTeX for all text
mpl.rcParams["text.usetex"] = True
mpl.rcParams["font.family"] = "serif"
mpl.rcParams["font.serif"] = ["Times"]
mpl.rcParams["text.latex.preamble"] = r"\usepackage{mathptmx}"
mpl.rcParams["font.size"] = 18        # Base font size
mpl.rcParams["axes.titlesize"] = 18   # Axis title font size
mpl.rcParams["axes.labelsize"] = 18   # Axis label font size
mpl.rcParams["xtick.labelsize"] = 18  # X-tick label font size
mpl.rcParams["ytick.labelsize"] = 18  # Y-tick label font size
mpl.rcParams["legend.fontsize"] = 18  # Legend font size

# List of implementations and their corresponding CSV file paths
implementations = [
    # ("Chromium", "/home/zhengyao/work/x509/frontend/results-chromium-part-2.txt"),
    # ("Chromium (No EV)", "/home/zhengyao/work/x509/frontend/results-chromium-part-2-without-logs-ev.txt"),
    # ("Chromium (No EV/Error)", "/home/zhengyao/work/x509/frontend/results-chromium-part-2-without-logs-ev-err-msg.txt"),
    # ("Chromium (No EV, builtin roots)", "/home/zhengyao/work/x509/frontend/results-chromium-part-2-without-logs-ev-builtin-roots.txt"),
    # ("Chromium (No EV/Parsing)", "/home/zhengyao/work/x509/frontend/results-chromium-part-2-without-logs-ev-no-parsing.txt"),
    # ("Chromium (No EV/Revocation)", "/home/zhengyao/work/x509/frontend/results-chromium-part-2-without-logs-ev-no-revocation.txt"),
    # ("Firefox (Old Harness)", "/home/zhengyao/work/x509/frontend/results-firefox-part-2-old-harness.txt"),
    # ("Firefox (New Harness)", "/home/zhengyao/work/x509/frontend/results-firefox-part-2-no-builtin-roots.txt"),
    # ("Firefox (No EV/SHA1)", "/home/zhengyao/work/x509/frontend/results-firefox-part-2-no-ev-no-sha1.txt"),
    # ("Firefox (Builtin Roots)", "/home/zhengyao/work/x509/frontend/results-firefox-part-2-builtin-roots.txt"),

    # ("ARMOR", "/home/zhengyao/work/x509/frontend/results-armor-part-2.txt"),
    ("ARMOR", "/home/zhengyao/work/x509/frontend/perf-results/results-armor-part-2.txt"),
    ("Hammurabi", "/home/zhengyao/work/x509/frontend/perf-results/results-hammurabi-part-2.txt"),

    ("OpenSSL", "/home/zhengyao/work/x509/frontend/perf-results/results-openssl-part-2.txt"),

    # ("Chrome 1", "/home/zhengyao/work/x509/frontend/results-chromium-part-2-without-logs-ev-err-msg.txt"),
    # ("Verdict-Chromium", "/home/zhengyao/work/x509/frontend/results-verdict-chrome-part-2.txt"),
    ("Verdict/Chrome", "/home/zhengyao/work/x509/frontend/perf-results/results-verdict-chrome-part-2.txt"),
    # ("Verdict-Chromium (opt2)", "/home/zhengyao/work/x509/frontend/results-verdict-chrome-part-2-opt-2.txt"),
    ("Verdict/Firefox", "/home/zhengyao/work/x509/frontend/perf-results/results-verdict-firefox-part-2.txt"),
    ("Verdict/OpenSSL", "/home/zhengyao/work/x509/frontend/perf-results/results-verdict-openssl-part-2-refactor-2.txt"),

    ("Firefox", "/home/zhengyao/work/x509/frontend/perf-results/results-firefox-part-2.txt"),
    ("Chrome", "/home/zhengyao/work/x509/frontend/perf-results/results-chrome-part-2.txt"),
    # ("Chrome (No Logs)", "/home/zhengyao/work/x509/frontend/results-chromium-part-2-release-no-log.txt"),
    # ("Firefox 2", "/home/zhengyao/work/x509/frontend/results-firefox-part-2-with-sha1-no-ev.txt"),
    # ("Firefox (50)", "/home/zhengyao/work/x509/frontend/results-firefox-part-2-50-reset.txt"),
    # ("Firefox (New)", "/home/zhengyao/work/x509/frontend/results-firefox-part-2-100-reset.txt"),
    # ("Firefox", "/home/zhengyao/work/x509/frontend/results-firefox-part-2-30-reset.txt"),
    # ("Firefox (10)", "/home/zhengyao/work/x509/frontend/results-firefox-part-2-10-reset.txt"),
    # ("Firefox (1)", "/home/zhengyao/work/x509/frontend/results-firefox-part-2-1-reset.txt"),
]

# # Dictionary to store median performance data for each implementation
# data = {}

# for impl_label, csv_file in implementations:
#     # Read the CSV file without headers
#     df = pd.read_csv(csv_file, header=None)

#     # df = df[:4867]

#     # Determine the number of sample columns dynamically
#     num_columns = df.shape[1]
#     num_sample_cols = num_columns - 3  # Assuming first three columns are "hash", "hostname", "result"

#     # Assign column names
#     columns = ["hash", "hostname", "result"] + [f"sample{i+1}" for i in range(num_sample_cols)]
#     df.columns = columns

#     # Normalize the "result" column to strings and convert to lowercase
#     df["result"] = df["result"].astype(str).str.strip().str.lower()

#     # Filter rows where result is "true"
#     df_success = df[df["result"] == "true"].copy()
#     # df_success = df.copy()

#     # Calculate median of the sample columns for each row
#     sample_cols = [f"sample{i+1}" for i in range(num_sample_cols)]
#     df_success["min_performance"] = df_success[sample_cols].min(axis=1)

#     # Collect the median performance data
#     data[impl_label] = df_success["min_performance"].tolist()

#     print(f"{df_success.shape[0]}/{df.shape[0]} valid certs for {impl_label}, mean {round(df_success['min_performance'].mean(), 2)}μs")

# # Convert the data dictionary to a DataFrame suitable for plotting
# boxplot_data = pd.DataFrame(dict([(k, pd.Series(v)) for k, v in data.items()]))

# # Plotting the combined box plot
# plt.figure(figsize=(16, 8))
# sns.boxplot(data=boxplot_data, flierprops=dict(marker='.', color='black', alpha=0.3, markersize=5))
# plt.title("Performance on 20,000 certs")
# plt.xlabel("Implementation")
# plt.ylabel("Validation time (microseconds)")
# plt.yscale("log")

# # Explicitly set y-axis ticks to include 10000 and other relevant ticks
# # y_ticks = list(range(1, 6))
# # plt.yticks([ 10 * 10**n for n in y_ticks ], [f"10e{n}" for n in y_ticks])

# plt.savefig("test.png")
# plt.close()

# Create a list to store all data
all_data = []

for impl_label, csv_file in implementations:
    # Read the CSV file without headers
    df = pd.read_csv(csv_file, header=None)

    # Determine the number of sample columns dynamically
    num_columns = df.shape[1]
    num_sample_cols = num_columns - 4

    # Assign column names
    columns = ["hash", "hostname", "result", "err_msg"] + [f"sample{i+1}" for i in range(num_sample_cols)]
    df.columns = columns

    # Normalize the "result" column
    df["result"] = df["result"].astype(str).str.strip().str.lower()

    # Calculate the min performance for each row (across all samples)
    sample_cols = [f"sample{i+1}" for i in range(num_sample_cols)]

    # print(df[df[sample_cols].isna().any(axis=1)])
    # for col in sample_cols:
    #     df[col] = df[col].astype(int)

    df["min_performance"] = df[sample_cols].min(axis=1)

    # Store Implementation name
    df["Implementation"] = impl_label

    # Add this DataFrame's relevant info to all_data
    all_data.append(df[["Implementation", "result", "min_performance"]])

# Concatenate all data into a single DataFrame
combined_df = pd.concat(all_data, ignore_index=True)

# Print some stats
for impl in combined_df["Implementation"].unique():
    subset = combined_df[combined_df["Implementation"] == impl]
    true_subset = subset[subset["result"] == "true"]
    print(f"{impl}: {true_subset.shape[0]}/{subset.shape[0]} valid certs, mean {round(true_subset['min_performance'].mean(), 2) if not true_subset.empty else 'N/A'}μs")

# Plotting the combined box plot
combined_df["result"] = combined_df["result"].replace({
    "true": "Valid",
    "false": "Invalid"
})

# Define the two groups:
groupA = combined_df[combined_df["Implementation"].isin(["ARMOR", "Hammurabi"])]
groupB = combined_df[~combined_df["Implementation"].isin(["ARMOR", "Hammurabi"])]

num_cats_A = groupA["Implementation"].nunique()  # number of categories in group A
num_cats_B = groupB["Implementation"].nunique()  # number of categories in group B

width_per_category = 2
total_width = (num_cats_A + num_cats_B) * width_per_category
fig = plt.figure(figsize=(total_width, 5))

gs = gridspec.GridSpec(1, 2, width_ratios=[num_cats_A, num_cats_B])

ax1 = fig.add_subplot(gs[0])
ax2 = fig.add_subplot(gs[1])
# fig, (ax1, ax2) = plt.subplots(ncols=2, figsize=(16, 5))

# Left plot: ARMOR and Hammurabi
# sns.boxplot(x="Implementation", y="min_performance", hue="result", data=groupA, ax=ax1, width=0.5)
sns.boxplot(
    ax=ax1,
    x="Implementation", y="min_performance", data=groupA,
    flierprops=dict(marker=".", color="black", alpha=0.3, markersize=3, markeredgewidth=0.5),
    # boxprops=dict(edgecolor='none', facecolor='lightgray'),
    boxprops=dict(linewidth=0.5),
    whiskerprops=dict(linewidth=0.5),
    capprops=dict(linewidth=0.5),
    medianprops=dict(linewidth=0.5),
    hue="result",
    palette={"Valid": "green", "Invalid": "red"},
)
# ax1.set_title("Group A (ARMOR & Hammurabi)")
ax1.set_xlabel("")
ax1.set_ylabel("Validation time (microseconds)")
ax1.set_yscale("log")
ax1.legend_.remove()  # Remove legend here and add it once on the second plot or outside

# Right plot: Others
# sns.boxplot(x="Implementation", y="min_performance", hue="result", data=groupB, ax=ax2, width=0.5)
sns.boxplot(
    ax=ax2,
    x="Implementation", y="min_performance", data=groupB,
    flierprops=dict(marker=".", color="black", alpha=0.3, markersize=3, markeredgewidth=0.5),
    # boxprops=dict(edgecolor='none', facecolor='lightgray'),
    boxprops=dict(linewidth=0.5),
    whiskerprops=dict(linewidth=0.5),
    capprops=dict(linewidth=0.5),
    medianprops=dict(linewidth=0.5),
    hue="result",
    palette={"Valid": "green", "Invalid": "red"},
).legend(title="Result", loc="upper right")
# ax2.set_title("Group B (Others)")
ax2.set_xlabel("")
ax2.set_ylabel("")
ax2.set_ylim(50, 260)
# ax2.set_yscale("log")

# Optionally add a single legend outside the plots
# handles, labels = ax2.get_legend_handles_labels()
# fig.legend(handles, labels, title="Validation Result", loc='upper center', ncol=len(labels))

# plt.tight_layout()
# plt.show()

# plt.figure(figsize=(16, 5))
# ax = sns.boxplot(
#     x="Implementation", y="min_performance", data=combined_df,
#     flierprops=dict(marker=".", color="black", alpha=0.3, markersize=3, markeredgewidth=0.5),
#     # boxprops=dict(edgecolor='none', facecolor='lightgray'),
#     boxprops=dict(linewidth=0.5),
#     whiskerprops=dict(linewidth=0.5),
#     capprops=dict(linewidth=0.5),
#     medianprops=dict(linewidth=0.5),
#     hue="result",
#     palette={"Valid": "green", "Invalid": "red"},
# )
# ax.legend(title="Result")

# # Explicitly set y-axis ticks to include 10000 and other relevant ticks
# # y_ticks = list(range(1, 4))
# # plt.yticks([ 10 * 10**n for n in y_ticks ], [f"10e{n}" for n in y_ticks])

# # plt.title("Performance on Certificates from CT Logs")
# plt.xlabel("Implementation")
# plt.ylabel("Validation Time (microseconds)")
# plt.yscale("log")

plt.tight_layout(pad=0.1)
plt.savefig("test.pdf")
plt.close()
