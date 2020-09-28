import matplotlib as mpl
mpl.use('agg')
import matplotlib.pyplot as plt
import csv
import numpy as np

eval_names = ['filter_blur', 'filter_brightness', 'filter_denoise_easy', 'filter_gray', 'filter_sharpen', 'filter_white_balance']
legend_names = ['Blur', 'Brightness', 'Denoise', 'Gray Scale', 'Sharpening', 'White Balance']
fig_name = 'images/filter_latency.png'
x_ticks = ['Read Sig', 'Read Frame', 'Alloc Mem', 'Filter Frame', 'Write Frame', 'Write Metadata', 'Free Mem', 'Total Time\nto Filter Frame', 'Init Enclave', 'Remote Att.']
bps = []
fig = plt.figure(figsize=(16, 9))

for i, e in enumerate(eval_names):
    data_file = '../' + e + '/sgx/video_data/eval_filter.csv'
    data = []
    with open(data_file) as f:
        predata = csv.reader(f)
        for _ in range(10):
            data.append([])
        for j, row in enumerate(predata):
            if j == 0:
                for k, d in enumerate(row):
                    if k == 0 or k == 1:
                        data[8 + k].append(int(d)/1000)
            if j != 0:
                for k, d in enumerate(row):
                    data[k].append(int(d)/1000)
        adj = 0.05 * (2 * i - len(eval_names) + 1)
        color = "C" + str(i)
        bp = plt.boxplot(data, positions=[x + adj for x in range(0, len(data))], widths=0.1, patch_artist=True, boxprops=dict(facecolor=color), medianprops=dict(color='black', linewidth='2'))
        bps.append(bp)
        f.close()

plt.legend([bps[x]["boxes"][0] for x in range(0, len(eval_names))], legend_names)
plt.xticks([x for x in range(0, len(x_ticks))], x_ticks, rotation='vertical')
plt.xlabel("Different Operations")
plt.ylabel("Latency [ms]")
plt.yscale("log")
fig.savefig(fig_name, bbox_inches='tight')
