cd ../decoder/sgx/decoder_enclave; ./TestApp 10113 &
cd ../../../scheduler;
cd ../filter_blur/sgx/filter_enclave; ./TestApp 10114 127.0.0.1 10115 0 &
cd ../../../scheduler;
cd ../filter_sharpen/sgx/filter_enclave; ./TestApp 10115 127.0.0.1 10116 0 &
cd ../../../scheduler;
cd ../filter_white_balance/sgx/filter_enclave; ./TestApp 10116 127.0.0.1 10117 0 &
cd ../../../scheduler;
cd ../filter_denoise_easy/sgx/filter_enclave; ./TestApp 10117 127.0.0.1 10118 0 &
cd ../../../scheduler;
cd ../filter_blur/sgx/filter_enclave; ./TestApp 10121 127.0.0.1 10122 0 &
cd ../../../scheduler;
cd ../filter_gray/sgx/filter_enclave; ./TestApp 10119 127.0.0.1 10120 1 &
cd ../../../scheduler;
cd ../filter_sharpen/sgx/filter_enclave; ./TestApp 10122 127.0.0.1 10123 0 &
cd ../../../scheduler;
cd ../filter_white_balance/sgx/filter_enclave; ./TestApp 10123 127.0.0.1 10124 0 &
cd ../../../scheduler;
cd ../filter_denoise_easy/sgx/filter_enclave; ./TestApp 10124 127.0.0.1 10125 0 &
cd ../../../scheduler;
cd ../filter_brightness/sgx/filter_enclave; ./TestApp 10118 127.0.0.1 10119 0 &
cd ../../../scheduler;
cd ../filter_brightness/sgx/filter_enclave; ./TestApp 10125 127.0.0.1 10126 0 &
cd ../../../scheduler;
cd ../encoder/tee/sgx/encoder_ra; ./EncoderApp 10120 41231 41236  -fps10 -is_rgb -multi_in3 &
cd ../../../../scheduler;
cd ../filter_gray/sgx/filter_enclave; ./TestApp 10132 127.0.0.1 10120 1 &
cd ../../../scheduler;
cd ../filter_sharpen/sgx/filter_enclave; ./TestApp 10128 127.0.0.1 10129 0 &
cd ../../../scheduler;
cd ../filter_denoise_easy/sgx/filter_enclave; ./TestApp 10130 127.0.0.1 10131 0 &
cd ../../../scheduler;
cd ../filter_brightness/sgx/filter_enclave; ./TestApp 10131 127.0.0.1 10132 0 &
cd ../../../scheduler;
cd ../filter_gray/sgx/filter_enclave; ./TestApp 10126 127.0.0.1 10120 1 &
cd ../../../scheduler;
cd ../filter_blur/sgx/filter_enclave; ./TestApp 10127 127.0.0.1 10128 0 &
cd ../../../scheduler;
cd ../filter_white_balance/sgx/filter_enclave; ./TestApp 10129 127.0.0.1 10130 0 &
cd ../../../scheduler;