import matplotlib as mpl
mpl.use('agg')
import matplotlib.pyplot as plt
import csv

eval_names = ['filter_blur', 'filter_brightness', 'filter_denoise_easy', 'filter_gray', 'filter_sharpen', 'filter_white_balance']
legend_names = ['Blur', 'Brightness', 'Denoise', 'Gray Scale', 'Sharpening', 'White Balance']
fig_name = 'images/filter_only_latency.png'
bps = []
fig = plt.figure()

for i, e in enumerate(eval_names):
    data_file = '../' + e + '/sgx/video_data/eval_filter.csv'
    data = []
    with open(data_file) as f:
        predata = csv.reader(f)
        for j, row in enumerate(predata):
            if j != 0:
                for k, d in enumerate(row):
                    if k == 3:
                        data.append(int(d)/1000)
        adj = 0.05 * (2 * i - len(eval_names) + 1)
        color = "C" + str(i)
        bp = plt.boxplot(data, positions=[adj], widths=0.1, patch_artist=True, boxprops=dict(facecolor=color), medianprops=dict(color='black', linewidth='2'))
        bps.append(bp)
        f.close()

plt.legend([bps[x]["boxes"][0] for x in range(0, len(eval_names))], legend_names)
plt.xticks([])
plt.xlabel("Different Filter")
plt.ylabel("Latency [ms]")
fig.savefig(fig_name, bbox_inches='tight')
