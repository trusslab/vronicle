# Clean and make
make clean
make

# Setup v4l2 cam (Suppose your webcam is video0)
v4l2-ctl -d /dev/video0 -c exposure_auto=1
v4l2-ctl -d /dev/video0 -c brightness=100
v4l2-ctl -d /dev/video0 -c exposure_absolute=664

# Set variables
NUM_OF_FRAMES="60"
SAVE_FILE_NAME="./out_raw_yuv_frames/out.cif"

# run
./take_yuyv_frames $NUM_OF_FRAMES $SAVE_FILE_NAME