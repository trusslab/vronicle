#!/bin/bash

make clean
make

ENCODER_PATH="../encoder/tee/sgx/encoder_ra"

echo "Verifying signature"
./sig_verify $ENCODER_PATH/output.h264 $ENCODER_PATH/output.sig $ENCODER_PATH/encoder_cert.der $ENCODER_PATH/metadata.json

echo "Displaying video"
vlc $ENCODER_PATH/output.h264
