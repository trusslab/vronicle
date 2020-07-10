#include <errno.h>
#include <fcntl.h>
#include <linux/videodev2.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <time.h>

uint8_t *buffer;

clock_t start, end;
double cpu_time_used;

static int xioctl(int fd, int request, void *arg)
{
        int r;

        do r = ioctl (fd, request, arg);
        while (-1 == r && EINTR == errno);

        return r;
}

int print_caps(int fd)
{
        struct v4l2_capability caps = {0};
        if (-1 == xioctl(fd, VIDIOC_QUERYCAP, &caps))
        {
                perror("Querying Capabilities");
                return 1;
        }

        printf( "Driver Caps:\n"
                "  Driver: \"%s\"\n"
                "  Card: \"%s\"\n"
                "  Bus: \"%s\"\n"
                "  Version: %d.%d\n"
                "  Capabilities: %08x\n",
                caps.driver,
                caps.card,
                caps.bus_info,
                (caps.version>>16)&&0xff,
                (caps.version>>24)&&0xff,
                caps.capabilities);


        struct v4l2_cropcap cropcap = {0};
        cropcap.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        if (-1 == xioctl (fd, VIDIOC_CROPCAP, &cropcap))
        {
                perror("Querying Cropping Capabilities");
                return 1;
        }

        printf( "Camera Cropping:\n"
                "  Bounds: %dx%d+%d+%d\n"
                "  Default: %dx%d+%d+%d\n"
                "  Aspect: %d/%d\n",
                cropcap.bounds.width, cropcap.bounds.height, cropcap.bounds.left, cropcap.bounds.top,
                cropcap.defrect.width, cropcap.defrect.height, cropcap.defrect.left, cropcap.defrect.top,
                cropcap.pixelaspect.numerator, cropcap.pixelaspect.denominator);

        int support_grbg10 = 0;

        struct v4l2_fmtdesc fmtdesc = {0};
        fmtdesc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        char fourcc[5] = {0};
        char c, e;
        printf("  FMT : CE Desc\n--------------------\n");
        while (0 == xioctl(fd, VIDIOC_ENUM_FMT, &fmtdesc))
        {
                strncpy(fourcc, (char *)&fmtdesc.pixelformat, 4);
                if (fmtdesc.pixelformat == V4L2_PIX_FMT_YUYV)
                    support_grbg10 = 1;
                c = fmtdesc.flags & 1? 'C' : ' ';
                e = fmtdesc.flags & 2? 'E' : ' ';
                printf("  %s: %c%c %s\n", fourcc, c, e, fmtdesc.description);
                fmtdesc.index++;
        }

        if (!support_grbg10)
        {
            printf("Doesn't support YUYV.\n");
            return 1;
        }

        struct v4l2_format fmt = {0};
        fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        fmt.fmt.pix.width = 1280;
        fmt.fmt.pix.height = 720;
        fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_YUYV;
        fmt.fmt.pix.field = V4L2_FIELD_NONE;

        if (-1 == xioctl(fd, VIDIOC_S_FMT, &fmt))
        {
            perror("Setting Pixel Format");
            return 1;
        }

        strncpy(fourcc, (char *)&fmt.fmt.pix.pixelformat, 4);
        printf( "Selected Camera Mode:\n"
                "  Width: %d\n"
                "  Height: %d\n"
                "  PixFmt: %s\n"
                "  Field: %d\n",
                fmt.fmt.pix.width,
                fmt.fmt.pix.height,
                fourcc,
                fmt.fmt.pix.field);
        return 0;
}

int init_mmap(int fd)
{
    struct v4l2_requestbuffers req = {0};
    req.count = 1;
    req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;

    if (-1 == xioctl(fd, VIDIOC_REQBUFS, &req))
    {
        perror("Requesting Buffer");
        return 1;
    }

    struct v4l2_buffer buf = {0};
    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP;
    buf.index = 0;
    if(-1 == xioctl(fd, VIDIOC_QUERYBUF, &buf))
    {
        perror("Querying Buffer");
        return 1;
    }

    buffer = mmap (NULL, buf.length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, buf.m.offset);
    printf("Length: %d\nAddress: %p\n", buf.length, buffer);
    printf("Frame Length: %d\n", buf.bytesused);

    return 0;
}

int capture_frames(int fd, const char* fileName, int num_of_frames)
{

    int outfd = open(fileName, O_RDWR | O_CREAT);

    for(int i = 0; i < num_of_frames; ++i){
        struct v4l2_buffer buf = {0};
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index = 0;
        if(-1 == xioctl(fd, VIDIOC_QBUF, &buf))
        {
            perror("Query Buffer");
            return 1;
        }

        if(-1 == xioctl(fd, VIDIOC_STREAMON, &buf.type))
        {
            perror("Start Capture");
            return 1;
        }

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        struct timeval tv = {0};
        tv.tv_sec = 2;
        int r = select(fd+1, &fds, NULL, NULL, &tv);
        if(-1 == r)
        {
            perror("Waiting for Frame");
            return 1;
        }

        if(-1 == xioctl(fd, VIDIOC_DQBUF, &buf))
        {
            perror("Retrieving Frame");
            return 1;
        }

        // printf("Image Length (After taken image): %d\n", buf.bytesused);
        write(outfd, buffer, buf.bytesused);
    }
    
    close(outfd);

    return 0;
}

int main(int argc, char *argv[])
{
    if(argc != 3){
        printf("Usage: [num_of_frames_to_take] [save_file_name]");
        return 1;
    }

    int num_of_frames = atoi(argv[1]);

    int fd;
    char buf[25];

    fd = open("/dev/video0", O_RDWR);
    if (fd == -1)
    {
            perror("Opening video device");
            return 1;
    }

    if(print_caps(fd))
        return 1;

    start = clock();

    if(init_mmap(fd))
        return 1;

    // for(int i = 0; i < num_of_frames; ++i){
    //     snprintf(buf, 25, "./out_raw_jpg/out_%d.jpg", i);
    //     if(capture_image(fd, buf))
    //         return 1;
    // }
    
    if(capture_frames(fd, argv[2], num_of_frames))
        return 1;
    
    end = clock();

    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;

    printf("take_photo took %f seconds to execute \n", cpu_time_used);

    close(fd);
    return 0;
}