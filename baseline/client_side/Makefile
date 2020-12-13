CC=gcc
CFLAGS=-L/usr/lib/x86_64-linux-gnu -ljpeg

all: video_capture/take_yuyv_frames.c
	$(CC) -o video_capture/take_yuyv_frames video_capture/take_yuyv_frames.c
	cd encoder;	sh build_x86.sh;
	cd tcp_client; make;

clean:
	rm video_capture/take_yuyv_frames encoder/h264enc_x64
	cd tcp_client; make clean;
