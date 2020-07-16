#!/bin/bash

make clean
make

echo "Verifying signature"
./sig_verify ../encoder/out.264 ../encoder/out.sig ../encoder/data/encoder_pub

echo "Displaying video"
vlc ../encoder/out.264
