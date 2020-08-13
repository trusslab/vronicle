CC=gcc
CPP=g++
CFLAGS=-L/usr/lib/x86_64-linux-gnu -ljpeg
CFLAGSSSL=-lssl -lcrypto

all: rsa_sign.cpp take_yuyv_frames.c
	$(CC) -o take_yuyv_frames take_yuyv_frames.c
	$(CPP) -o rsa_sign rsa_sign.cpp $(CFLAGSSSL)
	# $(CPP) -o make_certificate make_certificate.cpp $(CFLAGSSSL)

clean:
	rm rsa_sign take_yuyv_frames
