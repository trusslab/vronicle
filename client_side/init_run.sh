# Clean and make
make clean
make

# Setup v4l2 cam
v4l2-ctl -d /dev/video0 -c exposure_auto=1
v4l2-ctl -d /dev/video0 -c brightness=100
v4l2-ctl -d /dev/video0 -c exposure_absolute=664

# Set variables
NUM_OF_FRAMES="30"

# run
./take_photo $NUM_OF_FRAMES
./generate_new_key_pair camera_vendor_pub camera_vendor_pri
./generate_new_key_pair camera_pub camera_pri
./make_certificate camera_vendor_pri campera_pub camera_cert
./jpeg_to_raw $NUM_OF_FRAMES
./rsa_sign camera_pri $NUM_OF_FRAMES