# Do not use this as we do not apply filter on client side
# clean and make
make clean
make

# Setup v4l2 cam
v4l2-ctl -d /dev/video0 -c exposure_auto=1
v4l2-ctl -d /dev/video0 -c brightness=100
v4l2-ctl -d /dev/video0 -c exposure_absolute=664

# run
./take_photo
./generate_new_key_pair camera_pub camera_pri
./jpeg_to_raw out.jpeg
./rsa_sign raw_for_input camera_pri camera_sign 30
./filter_framework raw_for_input camera_sign camera_pub filter1_pub filter1_pri filter1_out1_sign filter1_out1
./raw_to_jpeg filter1_out1