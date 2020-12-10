if [ $# -lt 1 ]
then
    echo "Usage: ./make_server.sh <path_to_project_directory> <enable_dcap: default=0>"
    exit 1
fi

if [ "$1" != "" ]
then
    HOME_DIR=$1
else
    echo "Provide path to project directory"
    exit 1
fi

ENABLE_DCAP=0
if [ "$2" != "" ]
then
    ENABLE_DCAP=$2
fi

cd $HOME_DIR/decoder/sgx/decoder_enclave/; make ENABLE_DCAP=$ENABLE_DCAP

cd $HOME_DIR/filter_blur/sgx/filter_enclave/; make ENABLE_DCAP=$ENABLE_DCAP
cd $HOME_DIR/filter_gray/sgx/filter_enclave/; make ENABLE_DCAP=$ENABLE_DCAP
cd $HOME_DIR/filter_white_balance/sgx/filter_enclave/; make ENABLE_DCAP=$ENABLE_DCAP
cd $HOME_DIR/filter_brightness/sgx/filter_enclave/; make ENABLE_DCAP=$ENABLE_DCAP
cd $HOME_DIR/filter_sharpen/sgx/filter_enclave/; make ENABLE_DCAP=$ENABLE_DCAP
cd $HOME_DIR/filter_denoise_easy/sgx/filter_enclave/; make ENABLE_DCAP=$ENABLE_DCAP
cd $HOME_DIR/filter_test_bundle_sharpen_and_blur/sgx/filter_enclave/; make ENABLE_DCAP=$ENABLE_DCAP

cd $HOME_DIR/encoder/tee/sgx/encoder_ra/; make ENABLE_DCAP=$ENABLE_DCAP
