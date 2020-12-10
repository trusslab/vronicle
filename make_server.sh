HOME_DIR="/var/www/truesign.doc/video_provenance/video_provenance"

cd $HOME_DIR/decoder/sgx/decoder_enclave/; make

cd $HOME_DIR/filter_blur/sgx/filter_enclave/; make
cd $HOME_DIR/filter_gray/sgx/filter_enclave/; make
cd $HOME_DIR/filter_white_balance/sgx/filter_enclave/; make
cd $HOME_DIR/filter_brightness/sgx/filter_enclave/; make
cd $HOME_DIR/filter_sharpen/sgx/filter_enclave/; make
cd $HOME_DIR/filter_denoise_easy/sgx/filter_enclave/; make
cd $HOME_DIR/filter_test_bundle_sharpen_and_blur/sgx/filter_enclave/; make

cd $HOME_DIR/encoder/tee/sgx/encoder_ra/; make