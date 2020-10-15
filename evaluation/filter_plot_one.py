import matplotlib as mpl
mpl.use('agg')
import matplotlib.pyplot as plt
import csv
import os, sys

eval_names = ['filter_blur', 'filter_brightness', 'filter_denoise_easy', 'filter_gray', 'filter_sharpen', 'filter_white_balance']
legend_names = ['Blur', 'Brightness', 'Denoise', 'Gray Scale', 'Sharpening', 'White Balance']

folder = 'figures'
try:
    os.mkdir( folder, 0o755 )
except FileExistsError:
    pass
fig_name = folder + '/filter_one.png'
x_ticks = ['Enclave Init', 'RA', 'Receive IAS Cert', 'Verify IAS Cert', 'Send IAS Cert', '(Receive & Process & Send)*']
bps = []
fig = plt.figure(figsize=(16, 9))

for i, e in enumerate(eval_names):
    data_file = 'eval_result/eval_' + e + '_one_time.csv'
    data = []
    with open(data_file) as f:
        predata = csv.reader(f)
        for _ in range(len(x_ticks)):
            data.append([])
        for j, row in enumerate(predata):
            for k, d in enumerate(row):
                data[k].append(int(d)/1000)
        adj = 0.05 * (2 * i - len(eval_names) + 1)
        color = "C" + str(i)
        bp = plt.boxplot(data, positions=[x + adj for x in range(0, len(data))], widths=0.1, patch_artist=True, boxprops=dict(facecolor=color), medianprops=dict(color=color, linewidth='2'))
        bps.append(bp)
        f.close()

plt.legend([bps[x]["boxes"][0] for x in range(0, len(eval_names))], legend_names)
plt.xticks([x for x in range(0, len(x_ticks))], x_ticks)
plt.xlabel("Different Operations")
plt.ylabel("Latency [ms]")
plt.yscale("log")
fig.savefig(fig_name, bbox_inches='tight')
