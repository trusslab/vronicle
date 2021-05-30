/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <iostream>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fstream>
#include <bits/stdc++.h> 
#include <sys/stat.h> 
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>

#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
// #include <pthread.h>

# define MAX_PATH FILENAME_MAX
# define TARGET_NUM_TIMES_RECEIVED 2
# define TARGET_NUM_FILES_RECEIVED 1
// #define SIZEOFPACKAGE 40000

#include "TestApp.h"

#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h> /* gettimeofday() */
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <time.h> /* for time() and ctime() */

#include "minih264e.h"
#include "../common/metadata.h"
#include "SampleFilters.h"

#include "yuvconverter.h"

#include "basetype.h"

// For TCP module
#include <ctime>
#include <cerrno>
#include <cstring>
#include "../tcp_module/TCPServer.h"
#include "../tcp_module/TCPClient.h"

// For TCP module
int incoming_port;
TCPServer tcp_server;   // For direct use
TCPClient tcp_client_rec;    // For scheduler use
TCPClient **tcp_clients;
pthread_t msg1[MAX_CLIENT];
int num_message = 0;
int time_send   = 1;
int num_of_times_received = 0;
int size_of_msg_buf_for_rec = REPLYMSGSIZE;
char* msg_buf_for_rec;

// For multi bundle-filter enclaves
int num_of_pair_of_output = -1;
int current_sending_target_id = 0;
vector<pair<string, int>*> output_filters_info;

// For data
long contentSize = 0;
u8* contentBuffer = NULL;
long md_json_len = 0;
char* md_json = NULL;

// For SafetyNet data
char *original_md_json;
long original_md_json_len;

int is_decoding_finished = 0;

// Include for Decoder
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

// For ffmpeg Decoder
// TO-DO: Move this extern "C" to header files and add #if defined (__cplusplus)
extern "C" 
{
#include "libavcodec/avcodec.h"
#include "ffmpeg_decoder/decoder.h"
}
#define BUFFER_CAPACITY 4096*64
extern AVCodec ff_h264_decoder;
extern AVCodecParser ff_h264_parser;
AVCodec *codec;
AVCodecContext *codec_ctx;
AVCodecParserContext* parser;
AVFrame *frame;
int ending = 0;
int frame_index = 0;
uint8_t buffer[BUFFER_CAPACITY];
uint8_t* buf = buffer;
int buf_size = 0;
AVPacket packet;
u8 *byteStrm, *audio_strm, *audio_meta_strm;
unsigned char *audio_sig;
u8 *tempByteStrm; // For (moving) byteStrm pointer...
size_t readBytes;
size_t len;
size_t size_of_audio_strm = 0, size_of_audio_meta_strm = 0, size_of_audio_sig = 0;

#define MINIMP4_IMPLEMENTATION
#include "minimp4.h"
#define ADD_ENTROPY_SIZE	32

// For Decoding use
char* s_md_json;
long s_md_json_len;
u32 status;
// storage_t dec;
int numPics = 0;
size_t frame_size_in_rgb = 0;
u8* pic;
size_t pic_sig_len = 0;
u32 picId, isIdrPic, numErrMbs;
u32 top, left, width = 0, height = 0, croppingFlag;
metadata* tmp;
unsigned char* data_buf = NULL;
// Obtain signature length and allocate memory for signature
int tmp_total_digests = 0;

using namespace std;

#include <chrono> 
using namespace std::chrono;

unsigned char* image_buffer = NULL;	/* Points to large array of R,G,B-order data */
unsigned char* pure_input_image_str = NULL; /* for signature verification purpose */
pixel* image_pixels;    /* also RGB, but all 3 vales in a single instance (used for processing filter) */
int image_height = 0;	/* Number of rows in image */
int image_width = 0;		/* Number of columns in image */

char* hash_of_file;  /* temp test */

/* Encoder Related definitions and variables */
#define DEFAULT_GOP 20
#define DEFAULT_QP 33
#define DEFAULT_DENOISE 0
#define DEFAULT_FPS 30
#define DEFAULT_IS_YUYV 0
#define DEFAULT_IS_RGB 0

#define ENABLE_TEMPORAL_SCALABILITY 0
#define MAX_LONG_TERM_FRAMES        8 // used only if ENABLE_TEMPORAL_SCALABILITY==1

#define DEFAULT_MAX_FRAMES  99999

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

// For Encoding data

// For Encoding use
H264E_persist_t *enc;
H264E_scratch_t *scratch;
H264E_create_param_t create_param;
H264E_run_param_t run_param;
H264E_io_yuv_t yuv;
H264E_io_yuy2_t yuyv;
uint8_t *buf_in, *buf_save;
uint8_t *temp_buf_in, *p;
uint8_t *coded_data, *all_coded_data;
int sizeof_coded_data, frame_size, yuyv_frame_size, temp_frame_size, g_w, g_h, _qp, frame_counter;
size_t total_coded_data_size;
unsigned char* total_coded_data;
cmdline* cl;
metadata* in_md;
metadata* out_md;

// For muxing
uint8_t *mp4_strm = NULL;
size_t sizeof_mp4_strm = 0;
size_t sizeof_current_mp4_strm = 0;
size_t sizeof_used_mp4_strm = 0;
size_t standard_block_size = 1000000;	// For controlling how mp4_strm grows

// For TCP to viewer
int port_for_viewer = 0;
TCPServer tcp_server_for_viewer;

// For evaluation
ofstream eval_file;
ofstream alt_eval_file;

// For multi thread usage
int current_encoding_frame_num = 0;
pthread_mutex_t current_encoding_frame_num_lock;
#define MAX_NUM_OF_THREADS_FOR_PROCESSING 2
int current_num_of_threads_proc = 0;
pthread_mutex_t current_num_of_threads_proc_lock;
pthread_t last_proc_thread;

typedef struct frame_4_proc {
    // Common frame info
    int total_frames;
    int frame_id;

    // Original frame info
    u8* original_frame_buf;
    int original_frame_size;
    char* original_frame_md_json;
    int original_md_size;
    u8* original_frame_sig;
    int original_sig_size;

    // Processed frame info
    u8* processed_frame_buf;
    int processed_frame_size;
    char* processed_frame_md_json;
    int processed_md_size;
    unsigned char* processed_frame_sig;
    int processed_sig_size;
} frame_4_proc;

static void psnr_init()
{
    memset(&g_psnr, 0, sizeof(g_psnr));
}

static void psnr_add(unsigned char *p0, unsigned char *p1, int w, int h, int bytes)
{
    int i, k;
    for (k = 0; k < 3; k++)
    {
        double s = 0;
        for (i = 0; i < w*h; i++)
        {
            int d = *p0++ - *p1++;
            s += d*d;
        }
        g_psnr.count[k] += w*h;
        g_psnr.noise[k] += s;
        if (!k) w >>= 1, h >>= 1;
    }
    g_psnr.count[3] = g_psnr.count[0] + g_psnr.count[1] + g_psnr.count[2];
    g_psnr.noise[3] = g_psnr.noise[0] + g_psnr.noise[1] + g_psnr.noise[2];
    g_psnr.frames++;
    g_psnr.bytes += bytes;
}

int num_digits(int x)  
{  
    x = abs(x);  
    return (x < 10 ? 1 :   
        (x < 100 ? 2 :   
        (x < 1000 ? 3 :   
        (x < 10000 ? 4 :   
        (x < 100000 ? 5 :   
        (x < 1000000 ? 6 :   
        (x < 10000000 ? 7 :  
        (x < 100000000 ? 8 :  
        (x < 1000000000 ? 9 :  
        10)))))))));  
}  

#define UTC_NTP 2208988800U /* 1970 - 1900 */

/* get Timestamp for NTP in LOCAL ENDIAN */
void gettime64(uint32_t ts[])
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	ts[0] = tv.tv_sec + UTC_NTP;
	ts[1] = (4294*(tv.tv_usec)) + ((1981*(tv.tv_usec))>>11);
}

int die(const char *msg)
{
	if (msg) {
		fputs(msg, stderr);
	}
	exit(-1);
}

void log_ntp_event(char *msg)
{
	puts(msg);
}

static rd_t psnr_get()
{
    int i;
    rd_t rd;
    double fps = 30;    // Modified for adjusting fps output (Note that this is just for psnr output)
    double realkbps = g_psnr.bytes*8./((double)g_psnr.frames/(fps))/1000;
    double db = 10*log10(255.*255/(g_psnr.noise[0]/g_psnr.count[0]));
    for (i = 0; i < 4; i++)
    {
        rd.psnr[i] = 10*log10(255.*255/(g_psnr.noise[i]/g_psnr.count[i]));
    }
    rd.psnr_to_kbps_ratio = 10*log10((double)g_psnr.count[0]*g_psnr.count[0]*3/2 * 255*255/(g_psnr.noise[0] * g_psnr.bytes));
    rd.psnr_to_logkbps_ratio = db / log10(realkbps);
    rd.kpbs_30fps = realkbps;
    return rd;
}

static void psnr_print(rd_t rd)
{
    int i;
    printf("%5.0f kbps@30fps  ", rd.kpbs_30fps);
    for (i = 0; i < 3; i++)
    {
        //printf("  %.2f db ", rd.psnr[i]);
        printf(" %s=%.2f db ", i ? (i == 1 ? "UPSNR" : "VPSNR") : "YPSNR", rd.psnr[i]);
    }
    printf("  %6.2f db/rate ", rd.psnr_to_kbps_ratio);
    printf("  %6.3f db/lgrate ", rd.psnr_to_logkbps_ratio);
    printf("  \n");
}

static int str_equal(const char *pattern, char **p)
{
    if (!strncmp(pattern, *p, strlen(pattern)))
    {
        *p += strlen(pattern);
        return 1;
    } else
    {
        return 0;
    }
}

static int read_cmdline_options(int argc, char *argv[])
{
    // printf("[all_in_one]: There are a total of %d arguments\n", argc);
    int i;
    cl = (cmdline*)malloc(sizeof(cmdline));
    memset(cl, 0, sizeof(cmdline));
    cl->gop = DEFAULT_GOP;
    cl->qp = DEFAULT_QP;
    cl->max_frames = DEFAULT_MAX_FRAMES;
    cl->kbps = 0;
    //cl->kbps = 2048;
    cl->denoise = DEFAULT_DENOISE;
    cl->fps = DEFAULT_FPS;
    cl->is_yuyv = DEFAULT_IS_YUYV;
    cl->is_rgb = DEFAULT_IS_RGB;
    for (i = 1; i < argc; i++)
    {
        char *p = argv[i];
        if (*p == '-')
        {
            p++;
            if (str_equal(("gen"), &p))
            {
                cl->gen = 1;
            } else if (str_equal(("gop"), &p))
            {
                cl->gop = atoi(p);
            } else if (str_equal(("qp"), &p))
            {
                cl->qp = atoi(p);
            } else if (str_equal(("kbps"), &p))
            {
                cl->kbps = atoi(p);
            } else if (str_equal(("maxframes"), &p))
            {
                cl->max_frames = atoi(p);
            } else if (str_equal(("threads"), &p))
            {
                cl->threads = atoi(p);
            } else if (str_equal(("speed"), &p))
            {
                cl->speed = atoi(p);
            } else if (str_equal(("denoise"), &p))
            {
                cl->denoise = 1;
            } else if (str_equal(("stats"), &p))
            {
                cl->stats = 1;
            } else if (str_equal(("psnr"), &p))
            {
                cl->psnr = 1;
            } else if (str_equal(("fps"), &p))
            {
                cl->fps = atoi(p);
            } else if (str_equal(("is_yuyv"), &p))
            {
                cl->is_yuyv = 1;
            } else if (str_equal(("is_rgb"), &p))
            {
                cl->is_rgb = 1;
            } else
            {
                printf("ERROR: Unknown option {%s}\n", p - 1);
                return 0;
            }
        } else if (!incoming_port && !cl->gen)
        {
            incoming_port = atoi(p);
            printf("[all_in_one:TestApp]: incoming_port set to: [%d]\n", incoming_port);
        } else if (!port_for_viewer)
        {
            port_for_viewer = atoi(p);
            printf("[all_in_one:TestApp]: port_for_viewer set to: [%d]\n", port_for_viewer);
        } else
        {
            printf("ERROR: Unknown option {%s}\n", p);
            return 0;
        }
    }
    if (!incoming_port && !cl->gen)
    {
        printf("Usage:\n"
               "    EncoderApp [options] <incoming_port> <port_for_viewer>\n"
               "Frame size can be: WxH sqcif qvga svga 4vga sxga xga vga qcif 4cif\n"
               "    4sif cif sif pal ntsc d1 16cif 16sif 720p 4SVGA 4XGA 16VGA 16VGA\n"
               "Options:\n"
               "    -gen            - generate input instead of passing <input.yuv>\n"
               "    -qop<n>         - key frame period >= 0\n"
               "    -qp<n>          - set QP [10..51]\n"
               "    -kbps<n>        - set bitrate (fps=30 assumed)\n"
               "    -maxframes<n>   - encode no more than given number of frames\n"
               "    -threads<n>     - use <n> threads for encode\n"
               "    -speed<n>       - speed [0..10], 0 means best quality\n"
               "    -denoise        - use temporal noise supression\n"
               "    -stats          - print frame statistics\n"
               "    -psnr           - print psnr statistics\n"
               "    -fps<n>         - set target fps of the video, default is 30\n"
               "    -is_yuyv        - if the frames' chroma is in yuyv 4:2:2 packed format(note that psnr might not work when using yuyv)\n"
               "    -is_rgb         - if the frames' chroma is in rgb packed format(note that psnr might not work when using rgb)\n"
               "    -multi_in<n>    - set num of incoming sources(polling)\n");
        return 0;
    }
    return 1;
}

typedef struct
{
    const char *size_name;
    int g_w;
    int h;
} frame_size_descriptor_t;

static const frame_size_descriptor_t g_frame_size_descriptor[] =
{
    {"sqcif",  128,   96},
    { "qvga",  320,  240},
    { "svga",  800,  600},
    { "4vga", 1280,  960},
    { "sxga", 1280, 1024},
    {  "xga", 1024,  768},
    {  "vga",  640,  480},
    { "qcif",  176,  144},
    { "4cif",  704,  576},
    { "4sif",  704,  480},
    {  "cif",  352,  288},
    {  "sif",  352,  240},
    {  "pal",  720,  576},
    { "ntsc",  720,  480},
    {   "d1",  720,  480},
    {"16cif", 1408, 1152},
    {"16sif", 1408,  960},
    { "720p", 1280,  720},
    {"4SVGA", 1600, 1200},
    { "4XGA", 2048, 1536},
    {"16VGA", 2560, 1920},
    {"16VGA", 2560, 1920},
    {NULL, 0, 0},
};

/**
*   Guess image size specification from ASCII string.
*   If string have several specs, only last one taken.
*   Spec may look like "352x288" or "qcif", "cif", etc.
*/
static int guess_format_from_name(const char *file_name, int *w, int *h)
{
    int i = (int)strlen(file_name);
    int found = 0;
    while(--i >= 0)
    {
        const frame_size_descriptor_t *fmt = g_frame_size_descriptor;
        const char *p = file_name + i;
        int prev_found = found;
        found = 0;
        if (*p >= '0' && *p <= '9')
        {
            char * end;
            int width = strtoul(p, &end, 10);
            if (width && (*end == 'x' || *end == 'X') && (end[1] >= '1' && end[1] <= '9'))
            {
                int height = strtoul(end + 1, &end, 10);
                if (height)
                {
                    *w = width;
                    *h = height;
                    found = 1;
                }
            }
        }
        do
        {
            if (!strncmp(file_name + i, fmt->size_name, strlen(fmt->size_name)))
            {
                *w = fmt->g_w;
                *h = fmt->h;
                found = 1;
            }
        } while((++fmt)->size_name);

        if (!found && prev_found)
        {
            return prev_found;
        }
    }
    return found;
}

char* read_file_as_str(const char* file_name, long* str_len){
    // Return str_to_return on success, otherwise, return NULL
    // Need to free the return after finishing using
    FILE* file = fopen(file_name, "r");
    if(file == NULL){
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *str_len = ftell(file) + 1;
    fseek(file, 0, SEEK_SET);
    char* str_to_return = (char*)malloc(*str_len);
    memset(str_to_return, 0, *str_len);
    fread(str_to_return, 1, *str_len - 1, file);
    str_to_return[*str_len - 1] = '\0';

    fclose(file);
    return str_to_return;
}

void createContentBuffer(char* contentPath, u8** pContentBuffer, size_t* pContentSize) {
    struct stat sb;
    if (stat(contentPath, &sb) == -1) {
      perror("[decoder]: stat failed");
      exit(1);
    }

    *pContentSize = sb.st_size;
    *pContentBuffer = (u8*)malloc(*pContentSize);
}

void loadContent(char* contentPath, u8* contentBuffer, long contentSize) {
    FILE *input = fopen(contentPath, "r");
    if (input == NULL) {
      perror("[decoder]: open failed");
      exit(1);
    }

    off_t offset = 0;
    while (offset < contentSize) {
      offset += fread(contentBuffer + offset, sizeof(u8), contentSize - offset, input);
    }

    fclose(input);
}

void close_app(int signum) {
	printf("[decoder]: There is a SIGINT error happened...exiting......(%d)\n", signum);
	tcp_server.closed();
    tcp_client_rec.exit();
    for(int i = 0; i < num_of_pair_of_output; ++i){
	    tcp_clients[i]->exit();
    }
	exit(0);
}

void * received(void * m)
{
    // Assume there is a connection for tcp_server
    // Will use the latest connected one

	int current_mode = 0;	// 0 means awaiting reading file's nickname; 1 means awaiting file size; 2 means awaiting file content
    int current_file_indicator = -1;   // 0 means video; 1 means metadata; 2 means signature; 3 means certificate 
    char* current_writing_location = NULL;
    long* current_writing_size = NULL;
	long remaining_file_size = 0;

	int num_of_files_received = 0;

    // Set uniformed msg to skip sleeping
    int size_of_reply = 100;
    char* reply_msg = (char*) malloc(size_of_reply);

	while(num_of_files_received != TARGET_NUM_FILES_RECEIVED)
	{
        if(current_mode == 0){
            string file_name = tcp_server.receive_name();
            // printf("[decoder]: Got new file_name: %s\n", file_name.c_str());
            if(file_name == "vid"){
                current_file_indicator = 0;
                current_writing_size = &contentSize;
            } else if (file_name == "meta"){
                current_file_indicator = 1;
                current_writing_size = &md_json_len;
            } else {
                printf("[decoder]: The file_name is not valid: %s\n", file_name.c_str());
                free(reply_msg);
                return 0;
            }
            current_mode = 1;
        } else if (current_mode == 1){
            long size_of_data = tcp_server.receive_size_of_data();
            *current_writing_size = size_of_data;
            remaining_file_size = size_of_data;
            // printf("File size got: %ld, which should be equal to: %ld\n", remaining_file_size, *current_writing_size);
            // printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!current file indicator is: %d\n", current_file_indicator);
            switch(current_file_indicator){
                case 0:
                    contentBuffer = (u8*) malloc(*current_writing_size * sizeof(u8));
                    current_writing_location = (char*)contentBuffer;
                    break;
                case 1:
                    md_json = (char*) malloc(*current_writing_size * sizeof(char));
                    current_writing_location = md_json;
                    break;
                default:
                    printf("[decoder]: No file indicator is set, aborted...\n");
                    free(reply_msg);
                    return 0;
            }
            current_mode = 2;
        } else {
            char* data_received;
            if(remaining_file_size > SIZEOFPACKAGE){
                // printf("!!!!!!!!!!!!!!!!!!!Going to write data to current file location: %d\n", current_file_indicator);
                data_received = tcp_server.receive_exact(SIZEOFPACKAGE);
                memcpy(current_writing_location, data_received, SIZEOFPACKAGE);
                current_writing_location += SIZEOFPACKAGE;
                remaining_file_size -= SIZEOFPACKAGE;
            } else {
                // printf("???????????????????Last write to the current file location: %d\n", current_file_indicator);
                data_received = tcp_server.receive_exact(remaining_file_size);
                memcpy(current_writing_location, data_received, remaining_file_size);
                remaining_file_size = 0;
                current_mode = 0;
                ++num_of_files_received;
            }
		}
        memset(reply_msg, 0, size_of_reply);
        memcpy(reply_msg, "ready", 5);
        tcp_server.send_to_last_connected_client(reply_msg, size_of_reply);
	}
    free(reply_msg);
	return 0;
}

void try_receive_something(void* data_for_storage, long data_size){
    long remaining_data_size = data_size;
    char* temp_data_for_storage = (char*)data_for_storage;
    char* data_received;
    while(remaining_data_size > 0){
        // printf("Receiving data with remaining_data_size: %ld\n", remaining_data_size);
        if(remaining_data_size > SIZEOFPACKAGE){
            data_received = tcp_client_rec.receive_exact(SIZEOFPACKAGE);
            memcpy(temp_data_for_storage, data_received, SIZEOFPACKAGE);
            temp_data_for_storage += SIZEOFPACKAGE;
            remaining_data_size -= SIZEOFPACKAGE;
        } else {
            data_received = tcp_client_rec.receive_exact(remaining_data_size);
            memcpy(temp_data_for_storage, data_received, remaining_data_size);
            remaining_data_size = 0;
        }
        free(data_received);
        // printf("Received with data and going to receive again after replying...\n");
        memset(msg_buf_for_rec, 0, size_of_msg_buf_for_rec);
        memcpy(msg_buf_for_rec, "ready", 5);
        tcp_client_rec.Send(msg_buf_for_rec, size_of_msg_buf_for_rec);
    }
    return;
}

int send_buffer(void* buffer, long buffer_length, TCPClient* target_tcp_client) {
    // Return 0 on success, return 1 on failure

    // Send size of buffer
	target_tcp_client->Send(&buffer_length, sizeof(long));
	string rec = target_tcp_client->receive_exact(REPLYMSGSIZE);
	if( rec != "" )
	{
		// cout << rec << endl;
	}

    long remaining_size_of_buffer = buffer_length;
    void* temp_buffer = buffer;
    int is_finished = 0;

	while(1)
	{
        if(remaining_size_of_buffer > SIZEOFPACKAGE_HIGH){
		    target_tcp_client->Send(temp_buffer, SIZEOFPACKAGE_HIGH);
            remaining_size_of_buffer -= SIZEOFPACKAGE_HIGH;
            temp_buffer += SIZEOFPACKAGE_HIGH;
        } else {
		    target_tcp_client->Send(temp_buffer, remaining_size_of_buffer);
            is_finished = 1;
        }
        // printf("(inside)Going to wait for receive...just send buffer with size: %d\n", remaining_size_of_buffer);
		string rec = target_tcp_client->receive_exact(REPLYMSGSIZE);
        // printf("(inside)Going to wait for receive(finished)...\n");
		if( rec != "" )
		{
			// cout << "send_buffer received: " << rec << "where remaining size is: " << remaining_size_of_buffer << endl;
		}
        // if(rec == "received from received 1"){
        //     printf("send_buffer: Buffer should be sent completed: %d\n", is_finished);
        // }
        if(is_finished){
            // printf("send_buffer: This buffer should be all sent: [%s]\n", rec.c_str());
            break;
        }
	}
    
    return 0;
}

int send_buffer_to_viewer(void* buffer, long buffer_lenth){
    // Return 0 on success, return 1 on failure

	// Send size of buffer
	// printf("Sending buffer size: %d\n", buffer_lenth);
	tcp_server_for_viewer.send_to_last_connected_client(&buffer_lenth, sizeof(long));
    // printf("Going to wait for receive...\n");
	string rec = tcp_server_for_viewer.receive_name();
    // printf("Going to wait for receive(finished)...\n");
	if( rec != "" )
	{
		// cout << rec << endl;
	}

    long remaining_size_of_buffer = buffer_lenth;
    void* temp_buffer = buffer;
    int is_finished = 0;

	while(1)
	{
        if(remaining_size_of_buffer > SIZEOFPACKAGE){
		    tcp_server_for_viewer.send_to_last_connected_client(temp_buffer, SIZEOFPACKAGE);
            remaining_size_of_buffer -= SIZEOFPACKAGE;
            temp_buffer += SIZEOFPACKAGE;
        } else {
		    tcp_server_for_viewer.send_to_last_connected_client(temp_buffer, remaining_size_of_buffer);
            remaining_size_of_buffer = 0;
            is_finished = 1;
        }
        // printf("(inside)Going to wait for receive...just send buffer with size: %d\n", remaining_size_of_buffer);
		string rec = tcp_server_for_viewer.receive_name();
        // printf("(inside)Going to wait for receive(finished)...\n");
		if( rec != "" )
		{
			// cout << "send_buffer received: " << rec << endl;
		}
        if(is_finished){
            break;
        }
	}

    return 0;
}

int send_buffer(void* buffer, long buffer_lenth, int sending_target_id){
    // Return 0 on success, return 1 on failure

	// Send size of buffer
	tcp_clients[sending_target_id]->Send(&buffer_lenth, sizeof(long));
	string rec = tcp_clients[sending_target_id]->receive_exact(REPLYMSGSIZE);
	if( rec != "" )
	{
		// cout << rec << endl;
	}

    long remaining_size_of_buffer = buffer_lenth;
    char* temp_buffer = (char*)buffer;
    int is_finished = 0;

	while(1)
	{
        if(remaining_size_of_buffer > SIZEOFPACKAGE_HIGH){
		    tcp_clients[sending_target_id]->Send(temp_buffer, SIZEOFPACKAGE_HIGH);
            remaining_size_of_buffer -= SIZEOFPACKAGE_HIGH;
            temp_buffer += SIZEOFPACKAGE_HIGH;
        } else {
		    tcp_clients[sending_target_id]->Send(temp_buffer, remaining_size_of_buffer);
            is_finished = 1;
        }
        // printf("(inside)Going to wait for receive...just send buffer with size: %d\n", remaining_size_of_buffer);
		string rec = tcp_clients[sending_target_id]->receive_exact(REPLYMSGSIZE);
        // printf("(inside)Going to wait for receive(finished)...\n");
		if( rec != "" )
		{
			// cout << "send_buffer received: " << rec << "where remaining size is: " << remaining_size_of_buffer << endl;
		}
        // if(rec == "received from received 1"){
        //     printf("send_buffer: Buffer should be sent completed: %d\n", is_finished);
        // }
        if(is_finished){
            // printf("send_buffer: This buffer should be all sent: [%s]\n", rec.c_str());
            break;
        }
	}

    return 0;
}

void send_message(char* message, int msg_size, int sending_target_id){
	tcp_clients[sending_target_id]->Send(message, msg_size);
    // printf("(send_message)Going to wait for receive...\n");
	string rec = tcp_clients[sending_target_id]->receive_exact(REPLYMSGSIZE);
    // printf("(send_message)Going to wait for receive(finished)...\n");
	if( rec != "" )
	{
		// cout << "send_message received: " << rec << endl;
	}
}

void send_message(char* message, int msg_size, TCPClient *target_tcp_client) {
    target_tcp_client->Send(message, msg_size);
    // printf("(send_message)Going to wait for receive...\n");
	string rec = target_tcp_client->receive_exact(REPLYMSGSIZE);
    // printf("(send_message)Going to wait for receive(finished)...\n");
	if( rec != "" )
	{
		// cout << "send_message received: " << rec << endl;
	}
}

int check_and_change_to_main_scheduler(){
    // Return 0 on success, otherwise return 1

    // printf("[decoder]: In check_and_change_to_main_scheduler, going to receive...\n");
    string scheduler_mode = tcp_client_rec.receive_name();
    // printf("[decoder]: In check_and_change_to_main_scheduler, received: {%s}\n", scheduler_mode.c_str());
    int mode_of_scheduler = 0;  // 0 means main; 1 means helper
    // printf("[decoder]: In check_and_change_to_main_scheduler, is it main: {%d}\n", scheduler_mode == "main");
    if(scheduler_mode == "main"){
        mode_of_scheduler = 0;
    } else if (scheduler_mode == "helper"){
        mode_of_scheduler = 1;
    } else {
        return 1;
    }

    // printf("[decoder]: In check_and_change_to_main_scheduler, going to reply...mode_of_scheduler = [%d]\n", mode_of_scheduler);
    char* reply_to_scheduler = (char*)malloc(REPLYMSGSIZE);
    memset(reply_to_scheduler, 0, REPLYMSGSIZE);
    memcpy(reply_to_scheduler, "ready", 5);
    tcp_client_rec.Send(reply_to_scheduler, REPLYMSGSIZE);
    // printf("[decoder]: In check_and_change_to_main_scheduler, reply finished...\n");

    // Change the scheduler connected accordingly
    if(mode_of_scheduler == 1){
        // Get ip and port of main scheduler from current helper scheduler
        string ip_addr = tcp_client_rec.receive_name();
        memset(reply_to_scheduler, 0, REPLYMSGSIZE);
        memcpy(reply_to_scheduler, "ready", 5);
        tcp_client_rec.Send(reply_to_scheduler, REPLYMSGSIZE);
        string port = tcp_client_rec.receive_name();
        memset(reply_to_scheduler, 0, REPLYMSGSIZE);
        memcpy(reply_to_scheduler, "ready", 5);
        tcp_client_rec.Send(reply_to_scheduler, REPLYMSGSIZE);

        // Reconnect to the actual main scheduler
        tcp_client_rec.exit();
        bool connection_result = tcp_client_rec.setup(ip_addr.c_str(), atoi(port.c_str()));

        if(!connection_result){
            printf("[decoder]: Connection cannot be established with main scheduler...\n");
            return 1;
        }
    }

    free(reply_to_scheduler);

    return 0;
}

int set_num_of_pair_of_output(){
    // Return 0 on success, otherwise return 1

    long new_num = tcp_client_rec.receive_size_of_data();

    char* reply_to_scheduler = (char*)malloc(REPLYMSGSIZE);
    memset(reply_to_scheduler, 0, REPLYMSGSIZE);
    memcpy(reply_to_scheduler, "ready", 5);
    tcp_client_rec.Send(reply_to_scheduler, REPLYMSGSIZE);

    if(new_num < 1){
        printf("[decoder]: num_of_pair_of_output with main scheduler invalid: [%ld]...\n", new_num);
        return 1;
    }

    num_of_pair_of_output = (int)new_num;

    return 0;
}

int setup_tcp_clients_auto(){
    // Return 0 on success, otherwise return 1
    tcp_clients = (TCPClient**) malloc(sizeof(TCPClient*) * num_of_pair_of_output);
    char* reply_to_scheduler = (char*)malloc(REPLYMSGSIZE);
    string ip_addr, port;

    for(int i = 0; i < num_of_pair_of_output; ++i){
        tcp_clients[i] = new TCPClient();
        // printf("[decoder]: Setting up tcp client with args: %s, %s...\n", argv[2 + i * 2], argv[3 + i * 2]);

        ip_addr = tcp_client_rec.receive_name();
        memset(reply_to_scheduler, 0, REPLYMSGSIZE);
        memcpy(reply_to_scheduler, "ready", 5);
        tcp_client_rec.Send(reply_to_scheduler, REPLYMSGSIZE);
        port = tcp_client_rec.receive_name();
        memset(reply_to_scheduler, 0, REPLYMSGSIZE);
        memcpy(reply_to_scheduler, "ready", 5);
        tcp_client_rec.Send(reply_to_scheduler, REPLYMSGSIZE);

        // printf("[decoder]: In setup_tcp_clients_auto, going to connect to next filter_enclave with ip: {%s} and port: {%s}\n", ip_addr.c_str(), port.c_str());

        bool result_of_connection_setup = tcp_clients[i]->setup(ip_addr.c_str(), atoi(port.c_str()));
        if(!result_of_connection_setup){
            free(reply_to_scheduler);
            return 1;
        }
    }
    free(reply_to_scheduler);
    return 0;
}

void free_if_exist(void* item_to_free) {
    if (item_to_free) {
        free(item_to_free);
    }
}

void free_frame_4_proc(frame_4_proc* f_to_delete){
    free_if_exist(f_to_delete->original_frame_buf);
    free_if_exist(f_to_delete->original_frame_md_json);
    free_if_exist(f_to_delete->original_frame_sig);
    free_if_exist(f_to_delete->processed_frame_buf);
    free_if_exist(f_to_delete->processed_frame_md_json);
    free_if_exist(f_to_delete->processed_frame_sig);
    free_if_exist(f_to_delete);
}

int get_filter_idx(metadata* md, const char* filter_name)
{
	for (int i = 0; i < md->total_filters; i++) {
		if (strcmp(md->filters[i], filter_name) == 0)
			return i;
	}
	return -1;
}

int encoder_init (uint8_t* frame, size_t frame_size,
                    char* md_json,  size_t md_json_size)
{
    // Return 0 on success, otherwise fail
    int res = -1;
    // printf("frame_size: %d, md_json_size: %d\n", frame_size, md_json_size);
    md_json[md_json_size - 18] = '}'; // Remove frame_id from metadata
    memset(md_json + (md_json_size - 17), '\0', 17);
    // printf("[all_in_one]: Let's see if we actually remove frame_id(%d)(%d): [%s]\n", strlen(md_json), md_json_size - 17, md_json);
    in_md = json_2_metadata(md_json, md_json_size - 17);

    // char* output_json_4_in = metadata_2_json_without_frame_id(in_md);
    
    // printf("[all_in_one]: In t_encoder_init, we have output_json_4_in(%d): [%s]\n", strlen(output_json_4_in), output_json_4_in);
    // free(output_json_4_in);

    g_h = in_md->height;
    g_w = in_md->width;
    frame_counter = 0;

    create_param.enableNEON = 1;
#if H264E_SVC_API
    create_param.num_layers = 1;
    create_param.inter_layer_pred_flag = 1;
    create_param.inter_layer_pred_flag = 0;
#endif
    create_param.gop = cl->gop;
    create_param.height = g_h;
    create_param.width  = g_w;
    create_param.max_long_term_reference_frames = 0;
#if ENABLE_TEMPORAL_SCALABILITY
    create_param.max_long_term_reference_frames = MAX_LONG_TERM_FRAMES;
#endif
    create_param.fine_rate_control_flag = 0;
    create_param.const_input_flag = cl->psnr ? 0 : 1;
    create_param.vbv_size_bytes = 100000/8;
    create_param.temporal_denoise_flag = cl->denoise;

    // Allocate space for yuv420 (the one used for actually process data)
    buf_in   = (uint8_t*)malloc(frame_size);
    memset(buf_in, 0, frame_size);
    buf_save = (uint8_t*)malloc(frame_size);
    memset(buf_save, 0, frame_size);

    // If yuyv frames are used, allocate space for both the src and temp space for converting chroma format
    if(cl->is_yuyv){
        // Allocate space for temp space
        temp_frame_size = g_w * g_h * 2;
        temp_buf_in = (uint8_t*)malloc(temp_frame_size * sizeof(uint8_t));
        memset(temp_buf_in, 0, temp_frame_size);
        // printf("yuyv detected\n");
    }

    // If rgb frames are used, allocate space for both the src and temp space for converting chroma format
    if(cl->is_rgb){
        // Allocate space for temp space of dest (yuv 4:2:0 planar)
        // Update: Probably no longer needed
        // temp_frame_size = g_w * g_h * 3 / 2;
        // temp_buf_in = (uint8_t*)malloc(temp_frame_size * sizeof(uint8_t));
        // memset(temp_buf_in, 0, temp_frame_size);
        // printf("rgb detected, init with width: %d, height: %d\n", g_w, g_h);
        // Init rgbToYuv conversion
        InitConvt(g_w, g_h);
    }

    if (!buf_in || !buf_save)
    {
        printf("ERROR: not enough memory\n");
        return 1;
    }
    enc = NULL;
    scratch = NULL;
    total_coded_data = NULL;
    total_coded_data_size = 0;
    int sizeof_persist = 0, sizeof_scratch = 0, error;
    if (cl->psnr)
        psnr_init();

    error = H264E_sizeof(&create_param, &sizeof_persist, &sizeof_scratch);
    if (error)
    {
        printf("H264E_sizeof error = %d\n", error);
        return 1;
    }
    enc     = (H264E_persist_t *)malloc(sizeof_persist);
    memset(enc, 0, sizeof_persist);
    scratch = (H264E_scratch_t *)malloc(sizeof_scratch);
    memset(scratch, 0, sizeof_scratch);
    error = H264E_init(enc, &create_param);
    if (error)
    {
        printf("H264E_init error = %d\n", error);
        return 1;
    }

    return 0;
}

int encode_frame (uint8_t* frame, size_t frame_size,
                    char* md_json,  size_t md_json_size)
{
    // Return 0 on success, otherwise fail
    int res = -1;
    // printf("frame_size: %d, md_json_size: %d\n", frame_size, md_json_size);
    metadata* md;
    md = json_2_metadata(md_json, md_json_size);
    if (frame_counter != md->frame_id) {
        printf("Frame out of order\n");
        return -1;
    }
    int fps = md->frame_rate;
    free_metadata(md);
    frame_counter++;
    // Encode frame
    if (cl->is_yuyv) {
        p = frame;   // Record head adddress

        // temp conversion address
        yuyv.Y = temp_buf_in;
        yuyv.U = yuyv.Y + g_w * g_h;
        yuyv.V = yuyv.U + (g_w * g_h >> 1);   // Y  U  V  =4 : 2 ; 2

        // final incoming yuv data address
        yuv.yuv[0] = buf_in; yuv.stride[0] = g_w;
        yuv.yuv[1] = buf_in + g_w*g_h; yuv.stride[1] = g_w/2;
        yuv.yuv[2] = buf_in + g_w*g_h*5/4; yuv.stride[2] = g_w/2;

        // yuyv to yuv
        int k, j;
        for (k = 0; k < g_h; ++k)
        {
            for (j = 0; j < (g_w >> 1); ++j)
            {
                yuyv.Y[j * 2] = p[4 * j];
                yuyv.U[j] = p[4 * j + 1];
                yuyv.Y[j * 2 + 1] = p[4 * j + 2];
                yuyv.V[j] = p[4 * j + 3];
            }
            p = p + g_w * 2;

            yuyv.Y = yuyv.Y + g_w;
            yuyv.U = yuyv.U + (g_w >> 1);
            yuyv.V = yuyv.V + (g_w >> 1);
        }
        // Now packed is planar
        // reset
        yuyv.Y = temp_buf_in;
        yuyv.U = yuyv.Y + g_w * g_h;
        yuyv.V = yuyv.U + (g_w * g_h >> 1);

        int l;
        for (l = 0; l < g_h / 2; ++l)
        {
            memcpy(yuv.yuv[1], yuyv.U, g_w >> 1);
            memcpy(yuv.yuv[2], yuyv.V, g_w >> 1);

            yuv.yuv[1] = yuv.yuv[1] + (g_w >> 1);
            yuv.yuv[2] = yuv.yuv[2] + (g_w >> 1);

            yuyv.U = yuyv.U + (g_w);
            yuyv.V = yuyv.V + (g_w);
        }

        memcpy(yuv.yuv[0], yuyv.Y, g_w * g_h);

        // reset
        yuv.yuv[0] = buf_in;
        yuv.yuv[1] = buf_in + g_w*g_h;
        yuv.yuv[2] = buf_in + g_w*g_h*5/4;
    } else if (cl->is_rgb) {
        // printf("Processing rgb frame with frame size: %d...\n", frame_size);
        rgb_packed_to_yuv420_prog_planar(frame, buf_in, g_w, g_h);
        yuv.yuv[0] = buf_in; yuv.stride[0] = g_w;
        yuv.yuv[1] = buf_in + g_w*g_h; yuv.stride[1] = g_w/2;
        yuv.yuv[2] = buf_in + g_w*g_h*5/4; yuv.stride[2] = g_w/2;
    } else {
        buf_in = frame;
        yuv.yuv[0] = buf_in; yuv.stride[0] = g_w;
        yuv.yuv[1] = buf_in + g_w*g_h; yuv.stride[1] = g_w/2;
        yuv.yuv[2] = buf_in + g_w*g_h*5/4; yuv.stride[2] = g_w/2;
    }

    // For printing psnr
    if (cl->psnr)
        memcpy(buf_save, buf_in, frame_size);

    run_param.frame_type = 0;
    run_param.encode_speed = cl->speed;
    run_param.target_fps = fps;
    //run_param.desired_nalu_bytes = 100;

    if (cl->kbps)
    {
        printf("kbps is set manually to %i\n", cl->kbps);
        run_param.desired_frame_bytes = cl->kbps*1000/8/30;    // Modified for framerates
        run_param.qp_min = 10;
        run_param.qp_max = 50;
    } else
    {
        run_param.qp_min = run_param.qp_max = cl->qp;
    }

#if ENABLE_TEMPORAL_SCALABILITY
    int level, logmod = 1;
    int j, mod = 1 << logmod;
    static int fresh[200] = {-1,-1,-1,-1};

    run_param.frame_type = H264E_FRAME_TYPE_CUSTOM;

    for (level = logmod; level && (~i & (mod >> level)); level--){}

    run_param.long_term_idx_update = level + 1;
    if (level == logmod && logmod > 0)
        run_param.long_term_idx_update = -1;
    if (level == logmod - 1 && logmod > 1)
        run_param.long_term_idx_update = 0;

    //if (run_param.long_term_idx_update > logmod) run_param.long_term_idx_update -= logmod+1;
    //run_param.long_term_idx_update = logmod - 0 - level;
    //if (run_param.long_term_idx_update > 0)
    //{
    //    run_param.long_term_idx_update = logmod - run_param.long_term_idx_update;
    //}
    run_param.long_term_idx_use    = fresh[level];
    for (j = level; j <= logmod; j++)
    {
        fresh[j] = run_param.long_term_idx_update;
    }
    if (!i)
    {
        run_param.long_term_idx_use = -1;
    }
#endif
    res = H264E_encode(enc, scratch, &run_param, &yuv, &coded_data, &sizeof_coded_data);
    if (res)
    {
        printf("t_encode_frame: ERROR during encoding\n");
        return res;
    }

    if (cl->psnr)
        psnr_add(buf_save, buf_in, g_w, g_h, sizeof_coded_data);

    // Save encoded frame to global variable
    unsigned char* tmp;
    tmp = (unsigned char*)realloc(total_coded_data, (size_t)(total_coded_data_size + sizeof_coded_data));
    if (tmp)
    {
        memset(tmp + total_coded_data_size, 0, sizeof_coded_data);
        memcpy(tmp + total_coded_data_size, coded_data, sizeof_coded_data);
        total_coded_data_size += sizeof_coded_data;
        total_coded_data = tmp;
    }
    else
    {
        printf("t_encode_frame: ERROR no memory available\n");
        res = -1;
    }
   
    return res;
}

void* apply_filters_and_encode(void* m){

    frame_4_proc* processing_frame_info = (frame_4_proc*) m;

    if(processing_frame_info->frame_id + 1 != processing_frame_info->total_frames){
        pthread_detach(pthread_self());
    }

    const char* filter_name = "all_in_one";

    auto start = high_resolution_clock::now();

    // Parse metadata
    if (processing_frame_info->original_frame_md_json[processing_frame_info->original_md_size - 1] == '\0') (processing_frame_info->original_md_size)--;
    if (processing_frame_info->original_frame_md_json[processing_frame_info->original_md_size - 1] == '\0') (processing_frame_info->original_md_size)--;
    // printf("[all_in_one]: md_json(%ld) going to be used is: [%s]\n", processing_frame_info->original_md_size, processing_frame_info->original_frame_md_json);
    metadata* md = json_2_metadata(processing_frame_info->original_frame_md_json, processing_frame_info->original_md_size);
    // printf("[all_in_one]: now we have metadata for frame: %d in frame: %d\n", md->frame_id, processing_frame_info->frame_id);
    if (!md) {
        printf("[all_in_one]: Failed to parse metadata\n");
        close_app(0);
    }
	int filter_idx = get_filter_idx(md, filter_name);
	int current_filter_parameter_start_pos = 0;
	for(int i = 0; i < filter_idx; ++i){
		current_filter_parameter_start_pos += (int)(md->filters_parameters_registry[i]);
	}

    // Set up some basic parameters
    processing_frame_info->processed_frame_size = md->width * md->height * 3 * sizeof(unsigned char);

    // Parse Raw Image
    // printf("[all_in_one]: Image pixels: %d, %d, %ld should all be the same...\n", sizeof(pixel) * md->width * md->height, frame_size_p * sizeof(char), raw_frame_buf_len);
    pixel* image_pixels = (pixel*)malloc(processing_frame_info->processed_frame_size * sizeof(char));
    if (!image_pixels) {
        printf("[all_in_one]: No memory left(image_pixels)\n");
        close_app(0);
    }

    // size_t vid_frame_length = 0;
    // unsigned char* vid_frame = decode_signature(raw_frame_buf, raw_frame_buf_len, &vid_frame_length);

    memcpy(image_pixels, processing_frame_info->original_frame_buf, processing_frame_info->original_frame_size);
    // printf("[all_in_one]: Very first set of image pixel: %d, %d, %d\n", image_pixels[0].r, image_pixels[0].g, image_pixels[0].b);
    // int last_pixel_position = md->height * md->width - 1;
    // printf("[all_in_one]: Very last set of image pixel: %d, %d, %d\n", image_pixels[last_pixel_position].r, image_pixels[last_pixel_position].g, image_pixels[last_pixel_position].b);

    // Prepare processed Image
    size_t processed_pixels_size = sizeof(pixel) * md->height * md->width;
    pixel* processed_pixels_p = (pixel*)malloc(processed_pixels_size);
    if (!processed_pixels_p) {
        printf("[all_in_one]: No memory left(processed_pixels_p)\n");
        close_app(0);
    }

    // Prepare buffer for metadata output
    processing_frame_info->processed_md_size = processing_frame_info->original_md_size + 48;
    // processing_frame_info->processed_frame_md_json = (char*)malloc(processing_frame_info->processed_md_size);
    // memset(processing_frame_info->processed_frame_md_json, 0, processing_frame_info->processed_md_size);
    // if (!processing_frame_info->processed_frame_md_json) {
    //     printf("[all_in_one]: No memory left(out_md_json_p)\n");
    //     return;
    // }
	// Generate metadata
    const char* dummy_mrenclave = "11111111111111111111111111111111111111111111";
	int tmp_total_digests = md->total_digests;
	md->total_digests = tmp_total_digests + 1;
	md->digests = (char**)realloc(md->digests, sizeof(char*) * (/*decoder*/1 + /*filter*/filter_idx + 1));
	md->digests[filter_idx + 1] = (char*)malloc(45);
	memset(md->digests[filter_idx + 1], 0, 45);
	memcpy(md->digests[filter_idx + 1], dummy_mrenclave, 45);
	processing_frame_info->processed_frame_md_json = metadata_2_json(md);

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(end - start);
    eval_file << duration.count() << ", "; 

    // Going to get into enclave
    start = high_resolution_clock::now();

    // printf("[all_in_one]: Going to start processing frame %d\n", md->frame_id);

	// Process image
    // printf("[filter_brightness]: For filter brightness, we are using argument: %f\n", md->filters_parameters[current_filter_parameter_start_pos++]);
	// change_brightness((pixel*)image_pixels, processed_pixels_p, md->width, md->width * md->height, md->filters_parameters[current_filter_parameter_start_pos++]);
    blur((pixel*)image_pixels, processed_pixels_p, md->width, md->width * md->height, (int)md->filters_parameters[current_filter_parameter_start_pos++]);
	memcpy((pixel*)image_pixels, processed_pixels_p, processed_pixels_size);
	memset(processed_pixels_p, 0, processed_pixels_size);
	// printf("Going to call sharpen\n");
	sharpen((pixel*)image_pixels, processed_pixels_p, md->width, md->width * md->height, (int)md->filters_parameters[current_filter_parameter_start_pos++]);
	
	// memcpy((pixel*)image_pixels, processed_pixels_p, processed_pixels_size);
	// memset(processed_pixels_p, 0, processed_pixels_size);
	// auto_white_balance((pixel*)image_pixels, processed_pixels_p, md->width, md->width * md->height);
	// memcpy((pixel*)image_pixels, processed_pixels_p, processed_pixels_size);
	// memset(processed_pixels_p, 0, processed_pixels_size);
	// denoise_simple((pixel*)image_pixels, processed_pixels_p, md->width, md->width * md->height);
	// memcpy((pixel*)image_pixels, processed_pixels_p, processed_pixels_size);
	// memset(processed_pixels_p, 0, processed_pixels_size);
	// change_brightness((pixel*)image_pixels, processed_pixels_p, md->width, md->width * md->height, md->filters_parameters[current_filter_parameter_start_pos++]);
	// memcpy((pixel*)image_pixels, processed_pixels_p, processed_pixels_size);
	// memset(processed_pixels_p, 0, processed_pixels_size);
	// gray_frame((pixel*)image_pixels, processed_pixels_p, md->width, md->width * md->height);

    // printf("[all_in_one]: Finished processing frame %d\n", md->frame_id);

    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    eval_file << duration.count() << ", "; 
    
    start = high_resolution_clock::now();

    if(processing_frame_info->frame_id == 0){
        // Initialize variables in Enclave
        // printf("[all_in_one]: Going to init encoder...\n");
        status = encoder_init(processing_frame_info->processed_frame_buf, processing_frame_info->processed_frame_size,
                                processing_frame_info->processed_frame_md_json, processing_frame_info->processed_md_size);
        if (status) {
            printf("[all_in_one]: encoder_init failed\n");
            close_app(0);
        }
    }

    pthread_mutex_lock(&current_num_of_threads_proc_lock);
    --current_num_of_threads_proc;
    pthread_mutex_unlock(&current_num_of_threads_proc_lock);

    int is_frame_encoded = 0;
    // printf("[all_in_one]: Going to start encoding frame %d\n", md->frame_id);

    while(!is_frame_encoded){
        pthread_mutex_lock(&current_encoding_frame_num_lock);
        if(processing_frame_info->frame_id == current_encoding_frame_num){
            // printf("[all_in_one]: Going to encode frame %d...\n", processing_frame_info->frame_id);
            status = encode_frame((uint8_t*)processed_pixels_p, processing_frame_info->processed_frame_size,
                                    processing_frame_info->processed_frame_md_json, processing_frame_info->processed_md_size);
            if (status) {
                printf("[all_in_one]: Encoding of frame %d failed...\n", processing_frame_info->frame_id);
                close_app(0);
            }
            is_frame_encoded = 1;
            ++current_encoding_frame_num;
        }
        pthread_mutex_unlock(&current_encoding_frame_num_lock);
    }

    // printf("[all_in_one]: Finished encoding frame %d\n", md->frame_id);

    // Free the frame
    if (image_pixels) {
        free(image_pixels);
    }

    if (processed_pixels_p) {
        free(processed_pixels_p);
    }

    // printf("[all_in_one]: Going to start freeing frame %d\n", md->frame_id);
    free_frame_4_proc(processing_frame_info);
    // printf("[all_in_one]: Finished freeing frame %d\n", md->frame_id);
    free_metadata(md);
    // printf("[all_in_one]: Finished freeing metadata of frame %d\n", md->frame_id);
}

typedef struct
{
    uint8_t *buffer;
    ssize_t size;
} INPUT_BUFFER;

static int read_callback(int64_t offset, void *buffer, size_t size, void *token)
{
    INPUT_BUFFER *buf = (INPUT_BUFFER*)token;
    size_t to_copy = MINIMP4_MIN(size, buf->size - offset - size);
    memcpy(buffer, buf->buffer + offset, to_copy);
    return to_copy != size;
}

static ssize_t get_nal_size(uint8_t *buf, ssize_t size)
{
    ssize_t pos = 3;
    while ((size - pos) > 3)
    {
        if (buf[pos] == 0 && buf[pos + 1] == 0 && buf[pos + 2] == 1)
            return pos;
        if (buf[pos] == 0 && buf[pos + 1] == 0 && buf[pos + 2] == 0 && buf[pos + 3] == 1)
            return pos;
        pos++;
    }
    return size;
}

int expand_allocation_space_if_necessary(void** pointer_to_check, size_t *size_of_data, size_t current_used_size, size_t size_to_write, size_t size_to_expand) 
{
	// Return 0 for success, otherwise fail

	while ((*size_of_data - current_used_size) < size_to_write) {
		// printf("[decoder:TestEnclave]: expand_allocation_space_if_necessary: Going to expand to %d\n", *size_of_data + size_to_expand);
		*pointer_to_check = realloc(*pointer_to_check, *size_of_data + size_to_expand);
		// printf("[decoder:TestEnclave]: expand_allocation_space_if_necessary: Expanded to %d\n", *size_of_data + size_to_expand);
		if (*pointer_to_check == NULL) {
			printf("[decoder:TestEnclave]: expand_allocation_space_if_necessary is failed when trying to resize from %d to %d...\n", *size_of_data, current_used_size);
			return 1;
		}
		*size_of_data += size_to_expand;
	}
	// printf("[decoder:TestEnclave]: After expand_allocation_space_if_necessary, size_of_data is now expanded to: %d\n", *size_of_data);
	return 0;
}

int adjust_allocation_space_as_needed(void** pointer_to_check, size_t *size_of_data, size_t current_used_size)
{
	// Return 0 for success, otherwise fail
	if (*size_of_data < current_used_size) {
		printf("[decoder:TestEnclave]: adjust_allocation_space_as_needed is failed when trying to resize from %d to %d...\n", *size_of_data, current_used_size);
		return 1;
	} else if (*size_of_data > current_used_size) {
		*pointer_to_check = realloc(*pointer_to_check, current_used_size);
		if (*pointer_to_check == NULL) {
			printf("[decoder:TestEnclave]: adjust_allocation_space_as_needed is failed when trying to resize from %d to %d...\n", *size_of_data, current_used_size);
			return 1;
		}
		*size_of_data = current_used_size;
	}
	return 0;
}

static int write_callback(int64_t offset, const void *buffer, size_t size, void *token)
{
	// Return 0 for success, otherwise fail

    // FILE *f = (FILE*)token;
    // fseek(f, offset, SEEK_SET);
    // return fwrite(buffer, 1, size, f) != size;

    // Don't forget to play the trick: passing **token into the *token argument...(since otherwise have to modify the whole minimp4.h)
    // Also, we are assuming token is the mp4_strm

    // printf("[EncoderEnclave]: mux: write_callback is called...\n");
    if (expand_allocation_space_if_necessary((void**) token, &sizeof_current_mp4_strm, sizeof_used_mp4_strm, size, standard_block_size) != 0) {
        return 1;
    }
    // printf("[EncoderEnclave]: mux: write_callback is called 1...\n");

    memcpy((*(void**)token) + offset, buffer, size);
    // printf("[EncoderEnclave]: mux: write_callback is called 2...\n");
    sizeof_used_mp4_strm += size;
    return 0;
}

int mux(metadata* video_meta,
        uint8_t* video_strm, size_t video_strm_size,
        uint8_t* audio_dsi_strm, size_t audio_dsi_strm_size,
        uint8_t* audio_strm, size_t audio_strm_size,
        uint8_t** mp4_buffer, size_t* mp4_buffer_size) {
    // Return 0 for success, otherwise fail
    // Note that mp4_buffer will be newly allocated here, so make sure you free it

    // printf("[EncoderEnclave]: mux: checkpoint 1...\n");

    int is_hevc = 0;    // TO-DO: Consider supporting HEVC
    int sequential_mode = 0;    // TO-DO: Consider supporting sequential_mode
    int fragmentation_mode = 0; // TO-DO: Consider supporting fragmentation_mode
    
    // printf("[EncoderEnclave]: mux: checkpoint 2...\n");

    // Init mp4_buffer
    sizeof_current_mp4_strm = standard_block_size;
    *mp4_buffer = (uint8_t*) malloc(sizeof_current_mp4_strm);

    // printf("[EncoderEnclave]: mux: checkpoint 3...\n");

    MP4E_mux_t *mux;
    mp4_h26x_writer_t mp4wr;
    mux = MP4E_open(sequential_mode, fragmentation_mode, mp4_buffer, write_callback);

    if (mux == 0) {
        printf("[EncoderEnclave]: MP4E_open failed...\n");
        return 1;
    }
    
    // printf("[EncoderEnclave]: mux: checkpoint 4...\n");

    if (MP4E_STATUS_OK != mp4_h26x_write_init(&mp4wr, mux, 352, 288, is_hevc))
    {
        printf("[EncoderEnclave]: error: mp4_h26x_write_init failed\n");
        return 1;
    }
    
    // printf("[EncoderEnclave]: mux: checkpoint 5...\n");

    // Start of audio part
    uint8_t *audio_dsi_strm_temp = audio_dsi_strm;
    // Get sample rate and timescale
    unsigned int sample_rate = 0, timescale = 0;
    memcpy(&sample_rate, audio_dsi_strm_temp, sizeof(unsigned int));
    audio_dsi_strm_temp += sizeof(unsigned int);
    memcpy(&timescale, audio_dsi_strm_temp, sizeof(unsigned int));
    audio_dsi_strm_temp += sizeof(unsigned int);
    
    // printf("[EncoderEnclave]: mux: checkpoint 6...\n");

    // Set track data
    MP4E_track_t tr;
    tr.track_media_kind = e_audio;
    tr.language[0] = 'u';
    tr.language[1] = 'n';
    tr.language[2] = 'd';
    tr.language[3] = 0;
    tr.object_type_indication = MP4_OBJECT_TYPE_AUDIO_ISO_IEC_14496_3;
    tr.time_scale = timescale;
    tr.default_duration = 0;
    tr.u.a.channelcount = 2;
    tr.u.a.samplerate_hz = sample_rate;
    int audio_track_id = MP4E_add_track(mux, &tr);
    
    // printf("[EncoderEnclave]: mux: checkpoint 7...\n");

    // Set DSI
    unsigned int dsi_bytes = 0;
    memcpy(&dsi_bytes, audio_dsi_strm_temp, sizeof(unsigned int));
    audio_dsi_strm_temp += sizeof(unsigned int);
    MP4E_set_dsi(mux, audio_track_id, audio_dsi_strm_temp, dsi_bytes);
    // End of audio part
    
    // printf("[EncoderEnclave]: mux: checkpoint 8...\n");

    int counter = 0;
    uint8_t *buf_h264_audio_temp = audio_strm;
    uint8_t *video_strm_temp = video_strm;
    
    // printf("[EncoderEnclave]: mux: checkpoint 9...video_strm_size: %d\n", video_strm_size);

    while (video_strm_size > 0)
    {
        // printf("[EncoderEnclave]: mux: checkpoint 9.1...\n");

        ssize_t nal_size = get_nal_size(video_strm_temp, video_strm_size);

        // printf("[EncoderEnclave]: mux: checkpoint 9.2...nal_size: %d\n", nal_size);

        if (nal_size < 4)
        {
            video_strm_temp  += 1;
            video_strm_size -= 1;
            continue;
        }

        // printf("[EncoderEnclave]: mux: checkpoint 9.3...video_meta->frame_rate: %d\n", video_meta->frame_rate);

        if (MP4E_STATUS_OK != mp4_h26x_write_nal(&mp4wr, video_strm_temp, nal_size, 90000/video_meta->frame_rate))
        {
            printf("[EncoderEnclave]: error: mp4_h26x_write_nal failed\n");
            return 1;
        }

        // printf("[EncoderEnclave]: mux: checkpoint 9.4...\n");

        video_strm_temp  += nal_size;
        video_strm_size -= nal_size;
        
        // printf("[EncoderEnclave]: mux: checkpoint 9.5...\n");

        if (fragmentation_mode && !mux->fragments_count)
            continue; /* make sure mp4_h26x_write_nal writes sps/pps, because in fragmentation mode first MP4E_put_sample writes moov with track information and dsi.
                         all tracks dsi must be set (MP4E_set_dsi) before first MP4E_put_sample. */
        ++counter;

        // printf("[EncoderEnclave]: mux: checkpoint 9.6...\n");
    }

    // printf("[EncoderEnclave]: mux: checkpoint 10...\n");

    // Put audio data to container
    unsigned int sample_count = 0;

    // printf("[EncoderEnclave]: mux: checkpoint 11...\n");

    memcpy(&sample_count, buf_h264_audio_temp, sizeof(unsigned int));

    // printf("[EncoderEnclave]: mux: checkpoint 12...\n");

    // printf("[EncoderEnclave]: read sample_count: %u\n", sample_count);
    buf_h264_audio_temp += sizeof(unsigned int);

    // printf("[EncoderEnclave]: mux: checkpoint 13...\n");

    for (int i = 0; i < sample_count; ++i){
        unsigned frame_bytes = 0;
        memcpy(&frame_bytes, buf_h264_audio_temp, sizeof(unsigned));
        // if (i == 3) printf("[EncoderEnclave]: read frame_bytes: %u\n", frame_bytes);
        buf_h264_audio_temp += sizeof(unsigned);
        if (MP4E_STATUS_OK != MP4E_put_sample(mux, audio_track_id, buf_h264_audio_temp, frame_bytes, 1024, MP4E_SAMPLE_RANDOM_ACCESS))
        {
            printf("error: MP4E_put_sample failed\n");
            exit(1);
        }
        buf_h264_audio_temp += frame_bytes;
    }
    // End of audio part

    // printf("[EncoderEnclave]: mux: checkpoint 14...\n");

    MP4E_close(mux);
    mp4_h26x_write_close(&mp4wr);
    
    // Muxing finished!
    if (adjust_allocation_space_as_needed((void**) mp4_buffer, &sizeof_current_mp4_strm, sizeof_used_mp4_strm) != 0) {
		return 1;
	}
    *mp4_buffer_size = sizeof_used_mp4_strm;

    printf("[EncoderEnclave]: mux: mp4_buffer_size: %d\n", *mp4_buffer_size);

    return 0;
}

int demux(uint8_t *input_buf, size_t input_size, 
	uint8_t **video_out, size_t *size_of_video_out,
	uint8_t **audio_out, size_t *size_of_audio_out,
	uint8_t **audio_meta_out, size_t *size_of_audio_meta_out,
	int ntrack)
{
	// Return 0 on success, otherwise fail

	// This will allocate space for video_out, audio_out, audio_meta_out, remember to clean them
	// Sizes will be stored accordingly in size_of_video_out, size_of_audio_out, size_of_audio_meta_out

    int /*ntrack, */i, spspps_bytes;
    const void *spspps;
    INPUT_BUFFER buf = { input_buf, input_size };
    MP4D_demux_t mp4 = { 0, };
    MP4D_open(&mp4, read_callback, &buf, input_size);

	size_t standard_block_size = 1000000;	// For controlling how video_out, audio_out, audio_meta_out grow

	size_t current_size_of_video_out = standard_block_size;
	size_t current_used_size_of_video_out = 0;
	size_t current_size_of_audio_out = standard_block_size;
	size_t current_used_size_of_audio_out = 0;
	size_t current_size_of_audio_meta_out = standard_block_size;
	size_t current_used_size_of_audio_meta_out = 0;

	*video_out = (uint8_t*) malloc(current_size_of_video_out);
	*audio_out = (uint8_t*) malloc(current_size_of_audio_out);
	*audio_meta_out = (uint8_t*) malloc(current_size_of_audio_meta_out);

    // printf("[decoder:TestEnclave]: There are a total of %d tracks in this mp4 container...\n", mp4.track_count);

    for (ntrack = 0; ntrack < mp4.track_count; ntrack++)
    {
        // printf("[decoder:TestEnclave]: Dealing with track %d now...\n", ntrack);
        MP4D_track_t *tr = mp4.track + ntrack;
        unsigned sum_duration = 0;
        i = 0;
        if (tr->handler_type == MP4D_HANDLER_TYPE_VIDE)
        {   // assume h264
#define USE_SHORT_SYNC 0
            char sync[4] = { 0, 0, 0, 1 };
            while (spspps = MP4D_read_sps(&mp4, ntrack, i, &spspps_bytes))
            {
				if (expand_allocation_space_if_necessary((void**) video_out, &current_size_of_video_out, current_used_size_of_video_out, 4 - USE_SHORT_SYNC + spspps_bytes, standard_block_size) != 0) {
					return 1;
				}
				memcpy(*video_out + current_used_size_of_video_out, sync + USE_SHORT_SYNC, 4 - USE_SHORT_SYNC);
				current_used_size_of_video_out += 4 - USE_SHORT_SYNC;
				memcpy(*video_out + current_used_size_of_video_out, spspps, spspps_bytes);
				current_used_size_of_video_out += spspps_bytes;
                // fwrite(sync + USE_SHORT_SYNC, 1, 4 - USE_SHORT_SYNC, fout);
                // fwrite(spspps, 1, spspps_bytes, fout);
                i++;
            }
            i = 0;
            while (spspps = MP4D_read_pps(&mp4, ntrack, i, &spspps_bytes))
            {
				if (expand_allocation_space_if_necessary((void**) video_out, &current_size_of_video_out, current_used_size_of_video_out, 4 - USE_SHORT_SYNC + spspps_bytes, standard_block_size) != 0) {
					return 1;
				}
				memcpy(*video_out + current_used_size_of_video_out, sync + USE_SHORT_SYNC, 4 - USE_SHORT_SYNC);
				current_used_size_of_video_out += 4 - USE_SHORT_SYNC;
				memcpy(*video_out + current_used_size_of_video_out, spspps, spspps_bytes);
				current_used_size_of_video_out += spspps_bytes;
                // fwrite(sync + USE_SHORT_SYNC, 1, 4 - USE_SHORT_SYNC, fout);
                // fwrite(spspps, 1, spspps_bytes, fout);
                i++;
            }
            // printf("[decoder:TestEnclave]: There are a total of %d samples in the video track...\n", mp4.track[ntrack].sample_count);
            for (i = 0; i < mp4.track[ntrack].sample_count; i++)
            {
                unsigned frame_bytes, timestamp, duration;
                MP4D_file_offset_t ofs = MP4D_frame_offset(&mp4, ntrack, i, &frame_bytes, &timestamp, &duration);
                uint8_t *mem = input_buf + ofs;
                sum_duration += duration;
                // printf("frame_bytes in video is: %d\n", frame_bytes);
                while (frame_bytes)
                {
                    uint32_t size = ((uint32_t)mem[0] << 24) | ((uint32_t)mem[1] << 16) | ((uint32_t)mem[2] << 8) | mem[3];
                    // printf("size in video is: %d\n", size);
                    size += 4;
                    mem[0] = 0; mem[1] = 0; mem[2] = 0; mem[3] = 1;
					if (expand_allocation_space_if_necessary((void**) video_out, &current_size_of_video_out, current_used_size_of_video_out, size - USE_SHORT_SYNC, standard_block_size) != 0) {
						return 1;
					}
					memcpy(*video_out + current_used_size_of_video_out, mem + USE_SHORT_SYNC, size - USE_SHORT_SYNC);
					current_used_size_of_video_out += size - USE_SHORT_SYNC;
                    // fwrite(mem + USE_SHORT_SYNC, 1, size - USE_SHORT_SYNC, fout);
                    if (frame_bytes < size)
                    {
                        printf("[decoder:TestEnclave]: error: demux sample failed\n");
                        return 1;
                    }
                    frame_bytes -= size;
                    mem += size;
                }
            }
        } else if (tr->handler_type == MP4D_HANDLER_TYPE_SOUN)
        { 
            // The following codes are for storing both audio dsi and audio raw data(AAC)...
            // printf("[decoder:TestEnclave]: Audio track detected...with sample_count: %d, channel_count: %d, sample_rate: %d, dsi_bytes: %d, and language: {%s}, timescale: %i\n", 
            //     mp4.track[ntrack].sample_count, (tr->SampleDescription).audio.channelcount, (tr->SampleDescription).audio.samplerate_hz, tr->dsi_bytes, tr->language, tr->timescale);
            // printf("[decoder:TestEnclave]: Audio has type: %x, compared with default_output_audio_type: %x\n", tr->object_type_indication, MP4_OBJECT_TYPE_AUDIO_ISO_IEC_14496_3);

            // Write audio-related metadata.
            // Samplerate in Hz.
			if (expand_allocation_space_if_necessary((void**) audio_meta_out, &current_size_of_audio_meta_out, current_used_size_of_audio_meta_out, sizeof(unsigned int) * 3 + tr->dsi_bytes, standard_block_size) != 0) {
				return 1;
			}
			memcpy(*audio_meta_out + current_used_size_of_audio_meta_out, &(tr->SampleDescription).audio.samplerate_hz, sizeof(unsigned int));
			current_used_size_of_audio_meta_out += sizeof(unsigned int);
            // fwrite(&(tr->SampleDescription).audio.samplerate_hz, 1, sizeof(unsigned int), f_audio_meta_out);
            // timescale
			memcpy(*audio_meta_out + current_used_size_of_audio_meta_out, &tr->timescale, sizeof(unsigned int));
			current_used_size_of_audio_meta_out += sizeof(unsigned int);
            // fwrite(&tr->timescale, 1, sizeof(unsigned int), f_audio_meta_out);
            // DSI
			memcpy(*audio_meta_out + current_used_size_of_audio_meta_out, &tr->dsi_bytes, sizeof(unsigned int));
			current_used_size_of_audio_meta_out += sizeof(unsigned int);
			memcpy(*audio_meta_out + current_used_size_of_audio_meta_out, tr->dsi, tr->dsi_bytes);
			current_used_size_of_audio_meta_out += tr->dsi_bytes;
            // fwrite(&tr->dsi_bytes, 1, sizeof(unsigned int), f_audio_meta_out);
            // fwrite(tr->dsi, 1, tr->dsi_bytes, f_audio_meta_out);

            // Write audio data
			if (expand_allocation_space_if_necessary((void**) audio_out, &current_size_of_audio_out, current_used_size_of_audio_out, sizeof(unsigned int), standard_block_size) != 0) {
				return 1;
			}
			memcpy(*audio_out + current_used_size_of_audio_out, &(mp4.track[ntrack].sample_count), sizeof(unsigned int));
			current_used_size_of_audio_out += sizeof(unsigned int);
            // fwrite(&(mp4.track[ntrack].sample_count), 1, sizeof(unsigned int), f_audio_out);
            for (i = 0; i < mp4.track[ntrack].sample_count; i++)
            {
                // printf("Dealing with audio sample_count: %d, where the total sample count is: %d\n", i, mp4.track[ntrack].sample_count);
                unsigned frame_bytes, timestamp, duration;
                MP4D_file_offset_t ofs = MP4D_frame_offset(&mp4, ntrack, i, &frame_bytes, &timestamp, &duration);
				if (expand_allocation_space_if_necessary((void**)audio_out, &current_size_of_audio_out, current_used_size_of_audio_out, sizeof(unsigned) + frame_bytes, standard_block_size) != 0) {
					return 1;
				}
				memcpy(*audio_out + current_used_size_of_audio_out, &frame_bytes, sizeof(unsigned));
				current_used_size_of_audio_out += sizeof(unsigned);
                // fwrite(&frame_bytes, 1, sizeof(unsigned), f_audio_out);
                if (ofs > input_size) {
                    // printf("[decoder:TestEnclave]: Abandoning audio from sample_count: %d, where the total sample_count is: %d\n", i, mp4.track[ntrack].sample_count);
                    break;
                }
				memcpy(*audio_out + current_used_size_of_audio_out, input_buf + ofs, frame_bytes);
				current_used_size_of_audio_out += frame_bytes;
                // fwrite(input_buf + ofs, 1, frame_bytes, f_audio_out);
                // printf("sample_count: %d, ofs=%d frame_bytes=%d timestamp=%d duration=%d\n", i, (unsigned)ofs, frame_bytes, timestamp, duration);
            }
            // printf("Audio track is done...\n");
        }
    }

    MP4D_close(&mp4);

	if (adjust_allocation_space_as_needed((void**) video_out, &current_size_of_video_out, current_used_size_of_video_out) != 0) {
		return 1;
	}
	if (adjust_allocation_space_as_needed((void**) audio_meta_out, &current_size_of_audio_meta_out, current_used_size_of_audio_meta_out) != 0) {
		return 1;
	}
	if (adjust_allocation_space_as_needed((void**) audio_out, &current_size_of_audio_out, current_used_size_of_audio_out) != 0) {
		return 1;
	}

	*size_of_video_out = current_used_size_of_video_out;
	*size_of_audio_meta_out = current_used_size_of_audio_meta_out;
	*size_of_audio_out = current_used_size_of_audio_out;

    // if (input_buf)
    //     free(input_buf);
    return 0;
}

// int is_test_2_printed = 0;

static void yuv_save(unsigned char *buf[], int wrap[], int xsize,int ysize, unsigned char *target_buffer)
{
	int i;
	unsigned char* temp_target = target_buffer;	
	for (i = 0; i < ysize; i++) {
		// fwrite(buf[0] + i * wrap[0], 1, xsize, f);
		memcpy(temp_target, buf[0] + i * wrap[0], xsize);
		// if (!is_test_2_printed) {
		// 	printf("real first five chars: {%d} {%d} {%d} {%d} {%d}\n", *(buf[0] + i * wrap[0]), *(buf[0] + i * wrap[0] + 1), *(buf[0] + i * wrap[0] + 2), *(buf[0] + i * wrap[0] + 3), *(buf[0] + i * wrap[0] + 4));
		// 	printf("copied first five chars: {%d} {%d} {%d} {%d} {%d}\n", target_buffer[0], target_buffer[1], target_buffer[2], target_buffer[3], target_buffer[4]);
		// 	is_test_2_printed = 1;
		// }
		temp_target += xsize;
	}
	for (i = 0; i < ysize / 2; i++) {
		// fwrite(buf[1] + i * wrap[1], 1, xsize/2, f);
		memcpy(temp_target, buf[1] + i * wrap[1], xsize/2);
		temp_target += xsize/2;
	}
	for (i = 0; i < ysize / 2; i++) {
		// fwrite(buf[2] + i * wrap[2], 1, xsize/2, f);
		memcpy(temp_target, buf[2] + i * wrap[2], xsize/2);
		temp_target += xsize/2;
	}
}

// int is_test_printed = 0;

static int decode_write_frame(unsigned char *target_buffer, AVCodecContext *avctx,
							  AVFrame *frame, int *frame_index, AVPacket *pkt, int flush, int *is_frame_decoded)
{
	int got_frame = 0;
	do {
		int len = avcodec_decode_video2(avctx, frame, &got_frame, pkt);
		if (len < 0) {
			// fprintf(stderr, "Error while decoding frame %d\n", *frame_index);
			printf("[decoder:TestEnclave]: Error while decoding frame %d\n", *frame_index);
			return len;
		}
		if (got_frame) {
			// printf("Got frame %d\n", *frame_index);
			if (target_buffer) {
				size_t size_of_temp_yuv_data = sizeof(unsigned char) * frame->width * frame->height * 3 / 2;
				unsigned char *temp_yuv_data = (unsigned char*)malloc(size_of_temp_yuv_data);
				memset(temp_yuv_data, 0, size_of_temp_yuv_data);
				yuv_save(frame->data, frame->linesize, frame->width, frame->height, temp_yuv_data);
				// if (!is_test_printed) {
				// 	printf("first five chars: {%d} {%d} {%d} {%d} {%d}\n", temp_yuv_data[0], temp_yuv_data[1], temp_yuv_data[2], temp_yuv_data[3], temp_yuv_data[4]);
				// 	int total_size = sizeof(unsigned char) * frame->width * frame->height * 3 / 2;
				// 	printf("last five chars: {%d} {%d} {%d} {%d} {%d}\n", temp_yuv_data[total_size - 1], temp_yuv_data[total_size - 2], temp_yuv_data[total_size - 3], temp_yuv_data[total_size - 4], temp_yuv_data[total_size - 5]);
				// 	is_test_printed = 1;
				// }
				yuv420_prog_planar_to_rgb_packed(temp_yuv_data, target_buffer, frame->width, frame->height);
				free(temp_yuv_data);
			}
			(*frame_index)++;
		}
	} while (flush && got_frame);
	*is_frame_decoded = got_frame;
	return 0;
}

// int prepare_decoder(
// 	void* input_content_buffer, long size_of_input_content_buffer, 
// 	void* md_json, long md_json_len) {
// 	// Return 1 on success, return 0 on fail, return -1 on error, return -2 on already verified

// 	// Prepare Decoder
// 	status = h264bsdInit(&storage, HANTRO_FALSE);

// 	if (status != HANTRO_OK) {
// 		// fprintf(stderr, "h264bsdInit failed\n");
// 		printf("h264bsdInit failed\n");
// 		return 0;
// 	}

// 	len = size_of_input_content_buffer;
// 	byteStrm = (u8*)malloc(len);
// 	memset(byteStrm, 0, len);
// 	memcpy(byteStrm, input_content_buffer, len);

// 	s_md_json_len = md_json_len;
// 	s_md_json = (char*)malloc(s_md_json_len);
// 	memset(s_md_json, 0, s_md_json_len);
// 	memcpy(s_md_json, md_json, s_md_json_len);

// 	return 1;
// }

int prepare_decoder(
	void* input_content_buffer, long size_of_input_content_buffer, 
	void* md_json, long md_json_len,
	int is_safetynet_presented) {
	// Return 1 on success, return 0 on fail, return -1 on error

	// printf("[decoder:TestEnclave]: now inside t_sgxver_prepare_decoder...\n");

    int res = 1;

	// Extra parsing metadata for Safetynet
	// This might be potentially a vulnerbility as attacker can use this check to bypass our check for certificate
	// One solution is to seperate SafetyNet based server from the original Vronicle server
    metadata* original_md = json_2_metadata((char*)md_json, md_json_len);

	// printf("[decoder:TestEnclave]: is_source_video_verified: %d\n", is_source_video_verified);

    // Prepare Decoder
    // status = h264bsdInit(&dec, HANTRO_FALSE);

    // if (status != HANTRO_OK) {
    // 	// fprintf(stderr, "h264bsdInit failed\n");
    // 	printf("h264bsdInit failed\n");
    // 	return 0;
    // }
    avcodec_register(&ff_h264_decoder);
    av_register_codec_parser(&ff_h264_parser);
    
    codec = avcodec_find_decoder(AV_CODEC_ID_H264);
    if (!codec) {
        // fprintf(stderr, "Codec not found\n");
        printf("[decoder:TestEnclave]: Codec not found\n");
        return 0;
    }

    codec_ctx = avcodec_alloc_context3(codec);
    if (!codec_ctx) {
        // fprintf(stderr, "Could not allocate video codec context\n");
        printf("[decoder:TestEnclave]: Could not allocate video codec context\n");
        return 0;
    }
    
    if (avcodec_open2(codec_ctx, codec, NULL) < 0) {
        // fprintf(stderr, "Could not open codec\n");
        printf("[decoder:TestEnclave]: Could not open codec\n");
        return 0;
    }
    
    parser = av_parser_init(AV_CODEC_ID_H264);
    if(!parser) {
        // fprintf(stderr, "Could not create H264 parser\n");
        printf("[decoder:TestEnclave]: Could not create H264 parser\n");
        return 0;
    }

    frame = av_frame_alloc();
    if (!frame) {
        // fprintf(stderr, "Could not allocate video frame\n");
        printf("[decoder:TestEnclave]: Could not allocate video frame\n");
        return 0;
    }

    int demux_result = demux((uint8_t*)input_content_buffer, size_of_input_content_buffer, &byteStrm, &len, &audio_strm, &size_of_audio_strm, &audio_meta_strm, &size_of_audio_meta_strm, 0);

    // printf("[decoder:TestEnclave]: demux result is: %d...\n", demux_result);

    if (demux_result != 0) {
        printf("[decoder:TestEnclave]: demux is failed...\n");
        return 0;
    }

    // if (byteStrm) {
    // 	printf("[decoder:TestEnclave]: byteStrm does exist...\n");
    // }

    // len = size_of_input_content_buffer;
    // byteStrm = (u8*)malloc(len);
    // memset(byteStrm, 0, len);
    // memcpy(byteStrm, input_content_buffer, len);

    // For the following decoding frame process
    tempByteStrm = byteStrm;

    // printf("[decoder:TestEnclave]: Going to try to access address of byteStrm...\n");
    // printf("[decoder:TestEnclave]: After demuxing, the first five characters: 1: {%d}, 2: {%d}, 3: {%d}, 4: {%d}, 5: {%d}\n", byteStrm[0], byteStrm[1], byteStrm[2], byteStrm[3], byteStrm[4]);
    // printf("[decoder:TestEnclave]: After demuxing, the last five characters: 5: {%d}, 4: {%d}, 3: {%d}, 2: {%d}, 1: {%d}\n", byteStrm[len - 1], byteStrm[len - 2], byteStrm[len - 3], byteStrm[len - 4], byteStrm[len - 5]);

    if (original_md->is_safetynet_presented) {
        metadata *temp_md = json_2_metadata((char*)md_json, md_json_len);
        for (int i = 0; i < temp_md->num_of_safetynet_jws; ++i) {
            free(temp_md->safetynet_jws[i]);
        }
        free(temp_md->safetynet_jws);
        temp_md->num_of_safetynet_jws = 0;
        temp_md->is_safetynet_presented = 0;
        md_json = metadata_2_json_without_frame_id(temp_md);
        md_json_len = strlen((char*)md_json);
        free_metadata(temp_md);
    }

    s_md_json_len = md_json_len;
    s_md_json = (char*)malloc(s_md_json_len);
    memset(s_md_json, 0, s_md_json_len);
    memcpy(s_md_json, md_json, s_md_json_len);

    if (original_md->is_safetynet_presented) {
        free(md_json);
    }

	if (original_md) {
		free_metadata(original_md);
	}

	return res;
}


// int decode_single_frame(
// 	void* decoded_frame, long size_of_decoded_frame, 
// 	void* output_md_json, long size_of_output_json) {
	
// 	// Return 0 on success; return -1 on finish all decoding; otherwise fail...

// 	if(is_decoding_finished){
// 		printf("[decoder]: decoding is already finished...\n");
// 		return 1;
// 	}

// 	u8* decoded_frame_temp = (u8*)decoded_frame;
// 	memset(decoded_frame_temp, 0, size_of_decoded_frame);
// 	char* output_md_json_temp = (char*)output_md_json;
// 	memset(output_md_json_temp, 0, size_of_output_json);

// 	int is_single_frame_successfully_decoded = 0;

// 	// For some temp variables
// 	size_t real_size_of_output_md_json = 0;
// 	int res = -1;
// 	char* output_json_n = NULL;
// 	u8* pic_rgb = NULL;
//     const char* dummy_mrenclave = "11111111111111111111111111111111111111111111";

// 	while (len > 0 && !is_single_frame_successfully_decoded) {
// 		u32 result = h264bsdDecode(&storage, byteStrm, len, 0, &readBytes);
// 		// printf("[decoder]: readBytes: [%d], frame_size: [%d]\n", readBytes, frame_size_in_rgb);
// 		len -= readBytes;
// 		byteStrm += readBytes;

// 		switch (result) {
// 			case H264BSD_PIC_RDY:
// 				// Extract frame
// 				pic = h264bsdNextOutputPicture(&storage, &picId, &isIdrPic, &numErrMbs);
// 				++numPics;
// 				if(!frame_size_in_rgb){
// 					printf("No valid video header detected, exiting...\n");
// 					exit(1);
// 				}

// 				// Convert frame to RGB packed format
// 				yuv420_prog_planar_to_rgb_packed(pic, decoded_frame_temp, width, height);

// 				// Generate metadata
// 				tmp = json_2_metadata((char*)s_md_json, s_md_json_len);
// 				if (!tmp) {
// 					printf("Failed to parse metadata\n");
// 					exit(1);
// 				}
// 				tmp->frame_id = numPics - 1;
// 				tmp_total_digests = tmp->total_digests;
// 				tmp->total_digests = tmp_total_digests + 1;
// 				tmp->digests = (char**)malloc(sizeof(char*) * 1);
// 				tmp->digests[0] = (char*)malloc(45);
// 				memset(tmp->digests[0], 0, 45);
// 				memcpy(tmp->digests[0], dummy_mrenclave, 45);
// 				output_json_n = metadata_2_json(tmp);
// 				// printf("[decode:TestEnclave]: We now have output_json_n[%ld]: {%s}\n", strlen(output_json_n), output_json_n);

// 				// Check size of md_json
// 				real_size_of_output_md_json = strlen(output_json_n);
// 				if(real_size_of_output_md_json != (size_t)size_of_output_json){
// 					printf("[decode:TestEnclave]: Incorrect md_json size...real_size_of_output_md_json: [%ld]; size_of_output_json: [%ld]\n", real_size_of_output_md_json, size_of_output_json);
// 					return 1;
// 				}
// 				memcpy(output_md_json_temp, output_json_n, real_size_of_output_md_json);
// 				// printf("[decode:TestEnclave]: We now have output_json_n[%d]: {%s}\n", real_size_of_output_md_json, output_md_json_temp);

// 				// Clean up
// 				free_metadata(tmp);
// 				free(output_json_n);
// 				free(data_buf);

// 				is_single_frame_successfully_decoded = 1;

// 				break;
// 			case H264BSD_HDRS_RDY:
// 				// printf("[decoder]: in H264BSD_HDRS_RDY ...\n");
// 				// Obtain frame parameters
// 				h264bsdCroppingParams(&storage, &croppingFlag, &leftOffset, &width, &topOffset, &height);
// 				if (!croppingFlag) {
// 				width = h264bsdPicWidth(&storage) * 16;
// 				height = h264bsdPicHeight(&storage) * 16;
// 				}
// 				// Allocate memory for frame
// 				if(!frame_size_in_rgb){
// 					frame_size_in_rgb = width * height * 3;
// 					if(size_of_decoded_frame != frame_size_in_rgb){
// 						printf("[decoder]: Incorrect size...size_of_decoded_frame: [%ld]; frame_size_in_rgb: [%ld]...\n", size_of_decoded_frame, frame_size_in_rgb);
// 						return 1;
// 					}
// 					InitConvt(width, height);
// 				}
// 				break;
// 			case H264BSD_RDY:
// 				break;
// 			case H264BSD_ERROR:
// 				printf("Error\n");
// 				return 1;
// 			case H264BSD_PARAM_SET_ERROR:
// 				printf("Param set error\n");
// 				return 1;
// 		}
// 	}

// 	if(len <= 0){
// 		h264bsdShutdown(&storage);
// 		is_decoding_finished = 1;
// 		return -1;
// 	}
	
// 	return 0;
// }

int decode_single_frame(
	void* decoded_frame, long size_of_decoded_frame, 
	void* output_md_json, long size_of_output_json) {
	
	// Return 0 on success; return -1 on finish all decoding; otherwise fail...

    const char* dummy_mrenclave = "11111111111111111111111111111111111111111111";

	if(is_decoding_finished){
		printf("[decoder:TestEnclave]: decoding is already finished...\n");
		return 1;
	}

	u8* decoded_frame_temp = (u8*)decoded_frame;
	memset(decoded_frame_temp, 0, size_of_decoded_frame);
	char* output_md_json_temp = (char*)output_md_json;
	memset(output_md_json_temp, 0, size_of_output_json);

	int is_single_frame_successfully_decoded = 0;

	// For some temp variables
	size_t real_size_of_output_md_json = 0;
	int res = -1;
	char* output_json_n = NULL;
	u8* pic_rgb = NULL;

	// printf("[decoder:TestEnclave]: Currently in t_sgxver_decode_single_frame, with remaining len: %d\n", len);

	while (len > 0 && !is_single_frame_successfully_decoded) {
		// u32 result = h264bsdDecode(&dec, byteStrm, len, 0, &readBytes);
		uint8_t* data = NULL;
  		int size = 0;
		// printf("[decoder:TestEnclave]: Going to call av_parser_parse2\n");
		readBytes = av_parser_parse2(parser, codec_ctx, &data, &size, tempByteStrm, len, 0, 0, AV_NOPTS_VALUE);
		// printf("[decoder:TestEnclave]: readBytes: [%d], frame_size: [%d]\n", readBytes, frame_size_in_rgb);

		if (readBytes > 0) {
			// Set up some parameters for the first time
			if(!frame_size_in_rgb){
				width = parser->width;
				height = parser->height;
				frame_size_in_rgb = width * height * 3;
				if(size_of_decoded_frame != frame_size_in_rgb){
					printf("[decoder:TestEnclave]: Incorrect size...size_of_decoded_frame: [%d]; frame_size_in_rgb: [%d]...\n", size_of_decoded_frame, frame_size_in_rgb);
					return 1;
				}
				InitConvt(width, height);
			}

			av_init_packet(&packet);
			packet.data = data;
			packet.size = size;
			int got_frame = 0;
			int ret = decode_write_frame(decoded_frame_temp, codec_ctx, frame, &frame_index, &packet, 0, &got_frame);
			if (ret < 0) {
				printf("Decode or write frame error\n");
				exit(1);
			}

			if (got_frame) {
				// Generate metadata
				// printf("[decode:TestEnclave]: The s_md_json(%d): {%s}\n", s_md_json_len, s_md_json);
				tmp = json_2_metadata((char*)s_md_json, s_md_json_len);
				// printf("[decode:TestEnclave]: First check of is_safetynet_presented: %d\n", tmp->is_safetynet_presented);
				if (!tmp) {
					printf("Failed to parse metadata\n");
					exit(1);
				}
				tmp->frame_id = frame_index - 1;
				// printf("[decode:TestEnclave]: Got frame %d\n", tmp->frame_id);
				tmp_total_digests = tmp->total_digests;
				tmp->total_digests = tmp_total_digests + 1;
				tmp->digests = (char**)malloc(sizeof(char*) * 1);
				tmp->digests[0] = (char*)malloc(45);
				memset(tmp->digests[0], 0, 45);
				memcpy(tmp->digests[0], dummy_mrenclave, 45);
				// printf("[decode:TestEnclave]: Second check of is_safetynet_presented: %d\n", tmp->is_safetynet_presented);
				output_json_n = metadata_2_json(tmp);
				// printf("[decode:TestEnclave]: We now have output_json_n[%d]: {%s}\n", strlen(output_json_n), output_json_n);

				// Check size of decoded_rgb_frame
				if (frame_size_in_rgb != (size_t)size_of_decoded_frame) {
					printf("[decode:TestEnclave]: Incorrect decoded_frame size...frame_size_in_rgb: [%d]; size_of_decoded_frame: [%ld]\n", frame_size_in_rgb, size_of_decoded_frame);
					return 1;
				}

				// Check size of md_json
				real_size_of_output_md_json = strlen(output_json_n);
				if(real_size_of_output_md_json + 1 != (size_t)size_of_output_json){
					printf("[decode:TestEnclave]: Incorrect md_json size...real_size_of_output_md_json: [%d]; size_of_output_json: [%ld]\n", real_size_of_output_md_json, size_of_output_json);
					return 1;
				}
				memcpy(output_md_json_temp, output_json_n, real_size_of_output_md_json);
				// printf("[decode:TestEnclave]: We now have output_json_n[%d]: {%s}\n", real_size_of_output_md_json, output_md_json_temp);

				
				// printf("[decode:TestEnclave]: Cleaning for frame %d\n", tmp->frame_id);

				// Clean up
				free_metadata(tmp);
				free(output_json_n);

				// printf("[decode:TestEnclave]: Finished cleaning for frame %d\n", tmp->frame_id);

				is_single_frame_successfully_decoded = 1;
			}

			len -= readBytes;
			tempByteStrm += readBytes;
		}

	}

	if(len <= 0){
		// printf("[decode:TestEnclave]: Decoding should be finished...going to clean...\n");
		// h264bsdShutdown(&dec);
		// Flush the decoder
		packet.data = NULL;
		packet.size = 0;
		// TO-DO: Check if possible that there is still one last frame when program gets here...
		avcodec_close(codec_ctx);
		av_free(codec_ctx);
		av_parser_close(parser);
		av_frame_free(&frame);
		is_decoding_finished = 1;

		// printf("[decode:TestEnclave]: Decoding should be finished...going to actually clean byteStrm...\n");
		if (byteStrm) {
			free(byteStrm);
		}
		// The cleaning of audio_strm and audio_meta_strm is performed when they are being copied out in a seperate function
		// printf("[decode:TestEnclave]: Decoding should be finished...going to actually clean audio_strm...\n");
		// if (audio_strm) {
		// 	free(audio_strm);
		// }
		// printf("[decode:TestEnclave]: Decoding should be finished...going to actually clean audio_meta_strm...\n");
		// if (audio_meta_strm) {
		// 	free(audio_meta_strm);
		// }
		
		printf("[decode:TestEnclave]: Decoding should be finished...cleaning also finished...\n");

		return -1;
	}
	
	return 0;
}

void do_decoding(
    int argc,
    char** argv)
{
    // printf("[decoder]: incoming port: %s, outgoing address: %s, outgoing port: %s\n", argv[1], argv[2], argv[3]);

    // Register signal handlers
    std::signal(SIGINT, close_app);
	std::signal(SIGPIPE, sigpipe_handler);

    // Init evaluation
    auto start = high_resolution_clock::now();
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(end - start);

    // declaring argument of time() 

    // ctime() used to give the present time 

    // Prepare buf for sending message
    msg_buf_for_rec = (char*) malloc(size_of_msg_buf_for_rec);

    // Prepare tcp client
    // printf("[decoder]: Setting up tcp client...\n");
    int time_to_try = 10;
    int is_successfully_connected = 0;

    while (time_to_try && !is_successfully_connected) {
        bool result_of_connection_setup = tcp_client_rec.setup("127.0.0.1", incoming_port);
        if(!result_of_connection_setup){
            tcp_client_rec = TCPClient();
            --time_to_try;
            usleep(50000);
        } else {
            is_successfully_connected = 1;
        }
    }

    if(!is_successfully_connected){
        printf("[decoder:TestApp]: Connection cannot be established...\n");
        close_app(0);
    }

    // Determine if the current scheduler is in main mode or in helper mode
    // If in helper mode, be ready to change tcp_client for connecting the main scheduler
    // printf("Going to do check_and_change_to_main_scheduler...\n");
    check_and_change_to_main_scheduler();
    // printf("check_and_change_to_main_scheduler finished...\n");

    time_t my_time = time(NULL); 
    // printf("[decoder]: Receiving started at: %s", ctime(&my_time));
    
    memset(msg_buf_for_rec, 0, size_of_msg_buf_for_rec);
    memcpy(msg_buf_for_rec, "ready", 5);
    tcp_client_rec.Send(msg_buf_for_rec, REPLYMSGSIZE);
    // printf("[decoder]: reply is sent...\n");

    start = high_resolution_clock::now();

    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    alt_eval_file << duration.count() << ", ";

    // Start receiving other data
    while(num_of_times_received != TARGET_NUM_TIMES_RECEIVED){
        // printf("[decoder]: Start receiving data...\n");
        string name_of_current_file = tcp_client_rec.receive_name();
        // printf("[decoder]: Got new data: {%s}\n", name_of_current_file.c_str());
        void* current_writting_location;
        long current_writting_location_size;
        // printf("[decoder]: Got new file name: %s\n", name_of_current_file.c_str());
        memset(msg_buf_for_rec, 0, size_of_msg_buf_for_rec);
        memcpy(msg_buf_for_rec, "ready", 5);
        // printf("[decoder]: Going to send reply message...\n");
        tcp_client_rec.Send(msg_buf_for_rec, size_of_msg_buf_for_rec);
        // printf("[decoder]: Reply to scheduler is sent...\n");
        if (name_of_current_file == "vid"){

            contentSize = tcp_client_rec.receive_size_of_data();
            
            contentBuffer = (unsigned char*) malloc(contentSize);
            current_writting_location_size = contentSize;
            current_writting_location = contentBuffer;

        } else if (name_of_current_file == "meta"){
            // printf("[decoder]: Going to receive size of data...\n");
            md_json_len = tcp_client_rec.receive_size_of_data();
            
            // printf("[decoder]: size of data received(%ld)...\n", md_json_len);
            
            md_json = (char*) malloc(md_json_len);
            current_writting_location_size = md_json_len;
            current_writting_location = md_json;

        } else {
            printf("[decoder]: Received invalid file name: [%s]\n", name_of_current_file.c_str());
            return;
        }

        memset(msg_buf_for_rec, 0, size_of_msg_buf_for_rec);
        memcpy(msg_buf_for_rec, "ready", 5);
        tcp_client_rec.Send(msg_buf_for_rec, size_of_msg_buf_for_rec);

        // printf("[decoder]: Going to try receive data for size: %ld\n", current_writting_location_size);
        try_receive_something(current_writting_location, current_writting_location_size);
        ++num_of_times_received;
    }

    // Free
    free(msg_buf_for_rec);

    start = high_resolution_clock::now();

    // Parse metadata
    // printf("md_json(%ld): %s\n", md_json_len, md_json);
    if (md_json[md_json_len - 1] == '\0') md_json_len--;
    if (md_json[md_json_len - 1] == '\0') md_json_len--;
    metadata* md = json_2_metadata(md_json, md_json_len);
    if (!md) {
        printf("[decoder]: Failed to parse metadata\n");
        return;
    }

    // Extra parsing for Safetynet
    metadata *original_md = md;
    original_md_json = md_json;
    original_md_json_len = md_json_len;
    if (original_md->is_safetynet_presented) {
        md = json_2_metadata((char*)md_json, md_json_len);
        for (int i = 0; i < md->num_of_safetynet_jws; ++i) {
            free(md->safetynet_jws[i]);
        }
        free(md->safetynet_jws);
        md->num_of_safetynet_jws = 0;
        md->is_safetynet_presented = 0;
        md_json = metadata_2_json_without_frame_id(md);
        md_json_len = strlen((char*)md_json);
    }

    // Set up parameters for the case where output is multi
    int max_frames = 999; // Assume there are at most 999 frames
    int max_frame_digits = num_digits(max_frames);
    size_t md_size = md_json_len + 17 + 46 + 1;

    // Parameters to be acquired from enclave
    // u32* frame_width = (u32*)malloc(sizeof(u32)); 
    // u32* frame_height = (u32*)malloc(sizeof(u32));
    // int* num_of_frames = (int*)malloc(sizeof(int));
    int num_of_frames = md->total_frames;
    int frame_size = sizeof(u8) * md->width * md->height * 3;

    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    alt_eval_file << duration.count() << ", ";

    int res = 0;

    // Prepare decoder
    start = high_resolution_clock::now();
    res = prepare_decoder(contentBuffer, contentSize, 
                          original_md_json, original_md_json_len, md->is_safetynet_presented);

    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    alt_eval_file << duration.count() << ", ";

    auto start_s = high_resolution_clock::now();

    pthread_mutex_init(&current_encoding_frame_num_lock, NULL);
    pthread_mutex_init(&current_num_of_threads_proc_lock, NULL);

    if (res != 1) {
        printf("[decoder]: Failed to prepare decoding video with error code: [%d]\n", res);
        close_app(0);
    }

    // printf("[decoder]: After decoding, we know the frame width: %d, frame height: %d, and there are a total of %d frames.\n", 
    //     *frame_width, *frame_height, *num_of_frames);

    // Clean signle frame info each time before getting something new...

    // printf("Going to prepare all tcp clients...\n");

    // // Prepare all tcp clients
    // if(set_num_of_pair_of_output() != 0){
    //     printf("[all_in_one]: Failed to do set_num_of_pair_of_output\n");
    //     return;
    // }
    // // printf("[all_in_one]: After receiving, we have num_of_pair_of_output: [%d]\n", num_of_pair_of_output);
    // if(setup_tcp_clients_auto() != 0){
    //     printf("[all_in_one]: Failed to do setup_tcp_clients_auto\n");
    //     return;
    // }

    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start_s);
    alt_eval_file << duration.count() << ", ";

    // Start processing frames 
    for(int i = 0; i < num_of_frames; ++i){

        // printf("[all_in_one]: Processing frame: %d\n", i);

        // Init for single frame info
        u8* single_frame_buf = (u8*)malloc(frame_size);
        char* single_frame_md_json = (char*)malloc(md_size);

        // Clean signle frame info each time before getting something new...
        memset(single_frame_buf, 0, frame_size);
        memset(single_frame_md_json, 0, md_size);

        res = decode_single_frame(single_frame_buf, frame_size,
                                    single_frame_md_json, md_size);

        if(res == -1 && i + 1 < num_of_frames){
            printf("[all_in_one]: Finished decoding video on incorrect frame: [%d], where total frame is: [%d]...\n", i, num_of_frames);
            close_app(0);
        } else if(res != 0 && res != -1){
            printf("[all_in_one]: Failed to decode video on frame: [%d]\n", i);
            close_app(0);
        }

        frame_4_proc* f_proc_info = (frame_4_proc*) malloc(sizeof(frame_4_proc));
        memset(f_proc_info, 0, sizeof(frame_4_proc));
        f_proc_info->frame_id = i;
        f_proc_info->total_frames = md->total_frames;
        f_proc_info->original_frame_buf = single_frame_buf;
        f_proc_info->original_frame_md_json = single_frame_md_json;
        f_proc_info->original_frame_size = frame_size;
        f_proc_info->original_md_size = md_size;

        int is_frame_started_proc = 0;
        while(!is_frame_started_proc){
            pthread_mutex_lock(&current_num_of_threads_proc_lock);
            if(current_num_of_threads_proc < MAX_NUM_OF_THREADS_FOR_PROCESSING){
                if(pthread_create(&last_proc_thread, NULL, apply_filters_and_encode, f_proc_info) != 0){
                    printf("[all_in_one]: pthread for apply_filters_and_encode created failed...quiting...\n");
                    close_app(0);
                }
                ++current_num_of_threads_proc;
                is_frame_started_proc = 1;
            }
            pthread_mutex_unlock(&current_num_of_threads_proc_lock);
            // pthread_join(last_proc_thread, NULL);
            // if(!is_frame_started_proc){
            //     usleep(100);
            // }
        }
    }

    pthread_join(last_proc_thread, NULL);
    
    pthread_mutex_destroy(&current_encoding_frame_num_lock);
    pthread_mutex_destroy(&current_num_of_threads_proc_lock);

    if (total_coded_data_size == 0) {
        printf("[all_in_one]: no video is coded yet...\n");
        close_app(0);
    }

    if (size_of_audio_strm == 0) {
        printf("[all_in_one]: audio_strm is not ready...\n");
        close_app(0);
    }

    int res_of_mux = mux(in_md, total_coded_data, total_coded_data_size, (uint8_t*)audio_meta_strm, size_of_audio_meta_strm, (uint8_t*)audio_strm, size_of_audio_strm, &mp4_strm, &sizeof_mp4_strm);
    if (res_of_mux != 0) {
        printf("[all_in_one]: Mux is failed...\n");
        close_app(0);
    }

    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start_s);
    alt_eval_file << duration.count();

    fprintf(stderr, "[Evaluation]: Processing ended at: %ld\n", high_resolution_clock::now());

    vector<int> opts = { SO_REUSEPORT, SO_REUSEADDR };
    printf("[all_in_one]: port_for_viewer is going to be set at: %d\n", port_for_viewer);
    if( tcp_server_for_viewer.setup(port_for_viewer,opts) == 0) {
        printf("[all_in_one]: Ready for viewer to connect...\n");
        tcp_server_for_viewer.accepted();
        // cerr << "Accepted viewer" << endl;
        fprintf(stderr, "[Evaluation]: Sending started at: %ld\n", high_resolution_clock::now());
    }
    else
        cerr << "Errore apertura socket" << endl;

    // Init msg_buf
    string msg_reply_from_viewer;
    size_t size_of_msg_buf = SIZEOFPACKAGEFORNAME;
    char* msg_buf = (char*) malloc(size_of_msg_buf);

    // Send encoded video
    memset(msg_buf, 0, size_of_msg_buf);
    memcpy(msg_buf, "vid", 3);
    tcp_server_for_viewer.send_to_last_connected_client(msg_buf, size_of_msg_buf);
    msg_reply_from_viewer = tcp_server_for_viewer.receive_name();
    if(msg_reply_from_viewer != "ready"){
        printf("No ready received from viewer but: %s\n", msg_reply_from_viewer.c_str());
        close_app(0);
    }

    // send_buffer_to_viewer(total_coded_data, total_coded_data_size);
    send_buffer_to_viewer(mp4_strm, sizeof_mp4_strm);

    delete total_coded_data;

    start = high_resolution_clock::now();

    // Send metadata
    if (cl->stats)
    {
        printf ("[all_in_one]: out_metadata: %s\n", md_json);
    }

    // printf("[all_in_one]: Going to send metadata(%d): [%s]\n", potential_out_md_json_len, out_md_json);

    memset(msg_buf, 0, size_of_msg_buf);
    memcpy(msg_buf, "meta", 4);
    tcp_server_for_viewer.send_to_last_connected_client(msg_buf, size_of_msg_buf);
    msg_reply_from_viewer = tcp_server_for_viewer.receive_name();
    if(msg_reply_from_viewer != "ready"){
        printf("[all_in_one]: No ready received from viewer but: %s\n", msg_reply_from_viewer.c_str());
        close_app(0);
    }

    // printf("[all_in_one]: Going to send metadata(%d): [%s]\n", potential_out_md_json_len, out_md_json);
    const char* dummy_mrenclave = "11111111111111111111111111111111111111111111";
    int tmp_total_digests = in_md->total_digests;
	in_md->total_digests = tmp_total_digests + 1;
	in_md->digests = (char**)realloc(in_md->digests, sizeof(char*) * in_md->total_digests);
	in_md->digests[tmp_total_digests] = (char*)malloc(45);
	memset(in_md->digests[tmp_total_digests], 0, 45);
	memcpy(in_md->digests[tmp_total_digests], dummy_mrenclave, 45);

    // Merge original metadata's safetynet info to in_md
    // metadata *original_md = json_2_metadata(original_md_json, original_md_json_len);
    if (original_md->is_safetynet_presented) {
        // printf("[all_in_one]: safetynet_jws_report_1_size in original_md: %d, safetynet_jws_report_2_size in original_md: %d.\n", strlen(original_md->safetynet_jws[0]), strlen(original_md->safetynet_jws[1]));
        in_md->is_safetynet_presented = original_md->is_safetynet_presented;
        in_md->num_of_safetynet_jws = original_md->num_of_safetynet_jws;
        in_md->safetynet_jws = (char**)malloc(sizeof(char*) * in_md->num_of_safetynet_jws);
        for (int i = 0; i < in_md->num_of_safetynet_jws; ++i) {
            size_t size_of_current_jws = strlen(original_md->safetynet_jws[i]);
            in_md->safetynet_jws[i] = (char*)malloc(sizeof(char) * size_of_current_jws + sizeof(char));
            memcpy(in_md->safetynet_jws[i], original_md->safetynet_jws[i], sizeof(char) * size_of_current_jws);
            in_md->safetynet_jws[i][size_of_current_jws] = '\0';
        }
    }

	char* output_json = metadata_2_json_without_frame_id(in_md);
    send_buffer_to_viewer(output_json, strlen(output_json));

    if (original_md->is_safetynet_presented) {
        // printf("[all_in_one]: safetynet_jws_report_1_size in out_md: %d, safetynet_jws_report_2_size in out_md: %d.\n", strlen(out_md->safetynet_jws[0]), strlen(out_md->safetynet_jws[1]));
        // printf("[all_in_one]: output_json: {%s}\n", output_json);
        printf("[all_in_one]: After safetynet related data is presented in metadata, the final size of output_json will be: %d\n", strlen(output_json));
    }

    fprintf(stderr, "[Evaluation]: Sending ended at: %ld\n", high_resolution_clock::now());
    printf("[all_in_one]: All files sent successfully...going to quit...\n");

    free(output_json);

    if (cl->psnr)
        psnr_print(psnr_get());

    // Free everything
    // printf("[decoder]: Going to call free at the end of decoder...\n");
    // if(frame_width)
    //     free(frame_width);
    // if(frame_height)
    //     free(frame_height);
    // if(num_of_frames)
    //     free(num_of_frames);
    if(original_md->is_safetynet_presented){
        free_metadata(original_md);
        free(original_md_json);
    }
    if(contentBuffer)
        free(contentBuffer);
    if(md_json)
        free(md_json);
    if(md)
        free_metadata(md);
    if(in_md)
        free_metadata(in_md);
    
    for(int i = 0; i < num_of_pair_of_output; ++i){
        tcp_clients[i]->exit();
        delete tcp_clients[i];
    }
    free(tcp_clients);

    tcp_server_for_viewer.closed();

    // if(!ret){
    //     system("cd ../../../filter_blur/sgx/filter_enclave/run_enclave/; ./client 127.0.0.1 60");
    // }

    return;
}

void wait_wrapper(int s)
{
	wait(&s);
}

/* Application entry */
int main(int argc, char *argv[], char **env)
{

    if (!read_cmdline_options(argc, argv))
        return 1;

    // Check if incoming_port and port_for_viewer are set correctly
    if(incoming_port <= 0 || port_for_viewer <= 0){
        printf("[all_in_one]: Incoming port: %d or Port for viewer %d is invalid\n", incoming_port, port_for_viewer);
    }
    // printf("[all_in_one]: Incoming port: %d; Port for viewer %d\n", incoming_port, port_for_viewer);

    // num_of_pair_of_output += (argc - 4) / 2;

    // Open file to store evaluation results
    mkdir("../evaluation/eval_result", 0777);
    eval_file.open("../evaluation/eval_result/eval_all_in_one.csv");
    if (!eval_file.is_open()) {
        printf("[all_in_one]: Could not open eval file.\n");
        return 1;
    }

    alt_eval_file.open("../evaluation/eval_result/eval_all_in_one_one_time.csv");
    if (!alt_eval_file.is_open()) {
        printf("[all_in_one]: Could not open alt_eval_file file.\n");
        return 1;
    }

    // For time of initializing sgx enclave and doing RA
    auto start = high_resolution_clock::now();

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(end - start);
    alt_eval_file << duration.count() << ", "; 

    start = high_resolution_clock::now();
    
    end = high_resolution_clock::now();
    duration = duration_cast<microseconds>(end - start);
    alt_eval_file << duration.count() << ", "; 

	/* create the server waiting for the verification request from the client */
	int s;
	signal(SIGCHLD,wait_wrapper);
    do_decoding(argc, argv);

    // Close eval file
    eval_file.close();
    alt_eval_file.close();

	return 0;
}
