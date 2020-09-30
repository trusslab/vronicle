# start tcp server
./server 10111 &

# start filter enclave
cd ../filter_blur/sgx/filter_enclave/; sudo ./TestApp ../../../decoder/sgx/video_data/decoder_cert.der ../../../video_data/raw_for_process_sig/sig ../../../video_data/raw_for_process/raw_for_process ../../../video_data/raw_for_process_metadata/meta ../../../video_data/processed_raw_md/meta

# cd ../filter_blur/sgx/filter_enclave/; sudo ./TestApp ../../../decoder/sgx/video_data/decoder_cert.der ../../../video_data/raw_for_process_sig/sig ../../../video_data/raw_for_process/raw_for_process ../../../video_data/raw_for_process_metadata/meta ../../../video_data/processed_raw_md/meta &
