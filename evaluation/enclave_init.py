import matplotlib as mpl
mpl.use('agg')
import matplotlib.pyplot as plt
import csv
import os, sys

eval_names = ['heap', 'stack']
legend_names = ['HeapMaxSize', 'StackMaxSize']

folder = 'figures'
try:
    os.mkdir( folder, 0o755 )
except FileExistsError:
    pass
fig_name = folder + '/enclave_init_one.png'
x_ticks = ['0.256MB (0.016x)', '16MB (1x)', '32MB (2x)', '64MB (4x)', '100MB (6.25x)', '128MB (8x)', '256MB (16x)']
bps = []
fig = plt.figure(figsize=(16, 9))

for i, e in enumerate(eval_names):
    data_file = 'eval_result/enclave_init_one_' + e + '.csv'
    data = []
    with open(data_file) as f:
        predata = csv.reader(f)
        for _ in range(len(x_ticks)):
            data.append([])
        for j, row in enumerate(predata):
            for d in row:
                data[j].append(int(d)/1000)
        adj = 0.05 * (2 * i - len(eval_names) + 1)
        color = "C" + str(i)
        bp = plt.boxplot(data, positions=[x + adj for x in range(0, len(data))], widths=0.1, patch_artist=True, boxprops=dict(facecolor=color), medianprops=dict(color='black', linewidth='2'))
        bps.append(bp)
        f.close()

plt.legend([bps[x]["boxes"][0] for x in range(0, len(eval_names))], legend_names)
plt.xticks([x for x in range(0, len(x_ticks))], x_ticks)
plt.xlabel("Different Max Size of Heap")
plt.ylabel("Latency of start_enclave[ms]")
plt.yscale("log")
fig.savefig(fig_name, bbox_inches='tight')
