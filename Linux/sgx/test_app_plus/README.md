# Building: 
```
sudo make
```

# Cleaning:
``` 
sudo make clean
```

# How to Run: 
You will have to first start the Host Application, which will initialize the enclave and wait for information coming in. After that, you need to run a client application to pass the information to the Host Application.

# How to run Host Application: 
```
sudo ./TestApp data/camera_pub data/filter1_pri &
```

# How to run Client Application:
```
./run_enclave/client 127.0.0.1 8
```
If you want to change the num of frames to be passed and rendered to 4 or other num:
```
./run_enclave/client 127.0.0.1 4
```
(You know how to change it now, right? :) )

# Info about input data:
data/camera_pri: Camera's private key (not used)
data/camera_pub: Camera's public key (TO-DO: should be changed to certificate signed by camera vendor)
data/filter1_pri: filter's private key (TO-DO: should not be saved on disk, but generate a new one each time the enclave is created and get certificate by doing RA)
data/filter1_pub: filter's public key (TO-DO: similar as above)
data/out_raw: folder that contains all input raw frames
data/out_raw_sign: folder that contains all input raw frames' signatures

# Info about output data:
data/processed_raw: All processed frames will be stored here
data/processed_raw_sign: All processed frames' signatures will be stored here