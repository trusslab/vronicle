import matplotlib as mpl
mpl.use('agg')
import matplotlib.pyplot as plt
import csv

x_ticks = ['Init Enclave', 'Remote Att.']
fig_name = 'images/filter_init_only_latency.png'
bps = []
fig = plt.figure()

data_file = '../evaluation/enclave_init/sgx/video_data/eval_init.csv'
data = []
with open(data_file) as f:
    predata = csv.reader(f)
    for _ in range(2):
        data.append([])
    for j, row in enumerate(predata):
        for k, d in enumerate(row):
            data[k].append(int(d)/1000)
    bp = plt.boxplot(data, positions=[x for x in range(0, len(data))], widths=0.1, patch_artist=True, medianprops=dict(color='black', linewidth='2'))
    bps.append(bp)
    f.close()

    plt.xticks([x for x in range(0, len(x_ticks))], x_ticks)
    plt.xlabel("Different Operations")
    plt.ylabel("Latency [ms]")
    fig.savefig(fig_name, bbox_inches='tight')
