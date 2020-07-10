CC=gcc
CPP=g++
CFLAGS=-L/usr/lib/x86_64-linux-gnu -ljpeg
CFLAGSSSL=-lssl -lcrypto

all: jpeg_to_raw.c raw_to_jpeg.c take_photo.c generate_new_key_pair.cpp filter_framework.cpp rsa_sign.cpp
	$(CC) -o jpeg_to_raw jpeg_to_raw.c $(CFLAGS)
	$(CC) -o raw_to_jpeg raw_to_jpeg.c $(CFLAGS)
	$(CC) -o take_photo take_photo.c
	$(CC) -o take_yuyv_frames take_yuyv_frames.c
	$(CPP) -o generate_new_key_pair generate_new_key_pair.cpp $(CFLAGSSSL)
	$(CPP) -o filter_framework filter_framework.cpp $(CFLAGSSSL)
	$(CPP) -o rsa_sign rsa_sign.cpp $(CFLAGSSSL)
	$(CPP) -o make_certificate make_certificate.cpp $(CFLAGSSSL)

clean:
	rm jpeg_to_raw raw_to_jpeg take_photo generate_new_key_pair filter_framework rsa_sign
