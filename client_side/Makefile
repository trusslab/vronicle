CC=gcc
CPP=g++
CFLAGS=-L/usr/lib/x86_64-linux-gnu -ljpeg
CFLAGSSSL=-lssl -lcrypto

all: jpeg_to_raw.c raw_to_jpeg.c take_photo.c generate_new_key_pair.cpp filter_framework.cpp rsa_sign.cpp
	$(CC) -o take_yuyv_frames take_yuyv_frames.c
	$(CPP) -o rsa_sign rsa_sign.cpp $(CFLAGSSSL)
	# $(CPP) -o make_certificate make_certificate.cpp $(CFLAGSSSL)

clean:
	rm rsa_sign take_yuyv_frames
