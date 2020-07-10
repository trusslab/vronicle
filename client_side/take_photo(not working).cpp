// This doesn't work
// Looks like there is a dead loop somewhere


#include <iostream>
#include <fstream>
#include <fcntl.h>    /* For O_RDWR */
#include <unistd.h>   /* For open(), creat() */
#include <sys/ioctl.h>
#include <linux/videodev2.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdint.h>
using namespace std;

static int xioctl(int fd, int request, void *arg)
{
    int r;
        do r = ioctl (fd, request, arg);
        while (-1 == r && EINTR == errno);
        return r;
}

int main(){
    // Try find device
    int fd;
    fd = open("/dev/video0", O_RDWR);
    if (fd == -1)
    {
        // couldn't find capture device
        perror("Opening Video device");
        return 1;
    } else {
        cout << "Found Video device" << endl;
    }

    // Check v4l2 compatibility
    struct v4l2_capability caps = {0};
    if (-1 == xioctl(fd, VIDIOC_QUERYCAP, &caps))
    {
        perror("Querying Capabilites");
        return 1;
    } else {
        cout << "Device is supported by v4l2" << endl;
    }

    // Set image format
    struct v4l2_format fmt = {0};
    fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    fmt.fmt.pix.width = 1280;
    fmt.fmt.pix.height = 720;
    fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_MJPEG;
    fmt.fmt.pix.field = V4L2_FIELD_NONE;

    if (-1 == xioctl(fd, VIDIOC_S_FMT, &fmt))
    {
        perror("Setting Pixel Format");
        return 1;
    } else {
        cout << "Image format set" << endl;
    }

    // Request buffer
    struct v4l2_requestbuffers req = {0};
    req.count = 1;
    req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;

    if (-1 == xioctl(fd, VIDIOC_REQBUFS, &req))
    {
        perror("Requesting Buffer");
        return 1;
    } else {
        cout << "Got buffer" << endl;
    }

    // Query buffer
    struct v4l2_buffer buf = {0};
    buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buf.memory = V4L2_MEMORY_MMAP;
    buf.index = 0;
    if(-1 == xioctl(fd, VIDIOC_QUERYBUF, &buf))
    {
        perror("Querying Buffer");
        return 1;
    } else {
        cout << "buffer queried, bytesused: " << buf.bytesused << endl;
    }
    uint8_t *buffer = (uint8_t *)mmap (NULL, buf.length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, buf.m.offset);

    // Capture image
    if(-1 == xioctl(fd, VIDIOC_STREAMON, &buf.type))
    {
        perror("Start Capture");
        return 1;
    } else {
        cout << "Caputre started" << endl;
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
    } else {
        cout << "Wait for frame" << endl;
    }

    if(-1 == xioctl(fd, VIDIOC_DQBUF, &buf))
    {
        perror("Retrieving Frame");
        return 1;
    } else {
        cout << "Image captured" << endl;
    }

    int outfd = open("out.img", O_RDWR);
    write(outfd, buffer, buf.bytesused);
    close(outfd);

}