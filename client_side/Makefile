CC=gcc
CFLAGS=-L/usr/lib/x86_64-linux-gnu -ljpeg

all: signer/rsa_sign.cpp video_capture/take_yuyv_frames.c
	$(CC) -o video_capture/take_yuyv_frames video_capture/take_yuyv_frames.c
	cd encoder;	sh build_x86.sh;

clean:
	rm video_capture/take_yuyv_frames encoder/h264enc_x64
