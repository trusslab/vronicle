typedef struct
{
    int gen, gop, qp, kbps, max_frames, threads, speed, denoise, stats, psnr, fps, is_yuyv, is_rgb, is_input_multi;
} cmdline;

// PSNR estimation results
typedef struct
{
    double psnr[4];             // PSNR, db
    double kpbs_30fps;          // bitrate, kbps, assuming 30 fps
    double psnr_to_logkbps_ratio;  // cumulative quality metric
    double psnr_to_kbps_ratio;  // another variant of cumulative quality metric
} rd_t;

static struct
{
    // Y,U,V,Y+U+V
    double noise[4];
    double count[4];
    double bytes;
    int frames;
} g_psnr;