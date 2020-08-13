# Clean and make
make clean
make

# Make Encoder
cd encoder
./build_x86.sh
cd ..

# Setup v4l2 cam (Suppose your webcam is video0)
v4l2-ctl -d /dev/video0 -c exposure_auto=1
v4l2-ctl -d /dev/video0 -c brightness=100
v4l2-ctl -d /dev/video0 -c exposure_absolute=664

# Create directory to save output
mkdir -p output

# Set variables
NUM_OF_FRAMES="60"
VIDEO_FILE_NAME="./output/out.720p"
ENC_VIDEO_FILE_NAME="./output/out.h264"
SIG_FILE_NAME="./output/out.sig"
PRIVKEY_FILE_NAME="./signer/camera_pri"

# run
./video_capture/take_yuyv_frames $NUM_OF_FRAMES $VIDEO_FILE_NAME

# encode
./encoder/h264enc_x64 -is_yuyv -fps10 $VIDEO_FILE_NAME $ENC_VIDEO_FILE_NAME $SIG_FILE_NAME $PRIVKEY_FILE_NAME

# sign encoded video

chmod -x,+r $VIDEO_FILE_NAME