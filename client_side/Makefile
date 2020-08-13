CC=gcc
CPP=g++
CFLAGS=-L/usr/lib/x86_64-linux-gnu -ljpeg
CFLAGSSSL=-lssl -lcrypto

all: signer/rsa_sign.cpp video_capture/take_yuyv_frames.c
	$(CC) -o video_capture/take_yuyv_frames video_capture/take_yuyv_frames.c
	$(CPP) -o signer/rsa_sign signer/rsa_sign.cpp $(CFLAGSSSL)

clean:
	rm signer/rsa_sign video_capture/take_yuyv_frames
