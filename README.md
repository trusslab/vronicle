# Vronicle: Verifiable Provenance for Videos from Mobile Devices

Authors: Yuxin (Myles) Liu, Yoshimichi Nakatsuka, and Ardalan Amiri Sani, UC Irvine; Sharad Agarwal, Microsoft; Gene Tsudik, UC Irvine.

## Vronicle's demo

(Please note that our project name at submission time of MobiSys 2022 was VideoProv)

<iframe width="560" height="315" src="https://www.youtube.com/watch?v=gD0AehHKyCE" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

## Vronicle

Vronicle is a system platform that enables videos to be shoot, processed, and viewed in a trusted and verifiable manner. 

It is composed by three parts: camera client, server, and viewer. The camera client is an Android application; the server has two variants, where one is SGX-based, and the other one is TrustZone-based; the viewer is a linux GUI for verifying and playing the video.

In our current implementation, the SGX-based server is used along with Android camera client and Linux GUI player, where the TrustZone-based server is solely used for evaluation purpose. In the following document, we show how to build each part of Vronicle and run a simple demo of the whole system flow. Please refer to our paper for technical details: (TBA).

## Vronicle Android Camera

The following steps are tested on a Windows 11 desktop (12-core, 32GB RAM) and a Galaxy S20 Plus (Android 12).

First follow this tutorial (https://developer.android.com/studio/install) to set up Android Studio on your machine.

Import ``<vronicle_project_directory>/FilterTestWithNativeC`` into Android Studio as a project. Wait for gradle to sync and build. Now you can run it on either a physical Android phone or an emulator.

## Vronicle SGX-based Server

The following steps are tested on an Azure Confidential VM (8-core, 32GB RAM).

First use this repo (https://github.com/ayeks/SGX-hardware) to see if SGX is presented in your server.

Use the following commands to install some libraries:

```
sudo apt install gcc cmake openssl dkms libssl-dev curl libcurl4-openssl-dev libprotobuf-dev
```

Use the following commands to install Intel SGX Driver and SDK in ``$INTEL_SGX_DIR``:

```
cd $INTEL_SGX_DIR
wget https://download.01.org/intel-sgx/sgx-linux/2.16/distro/ubuntu18.04-server/sgx_linux_x64_driver_1.41.bin
wget https://download.01.org/intel-sgx/sgx-linux/2.16/distro/ubuntu18.04-server/sgx_linux_x64_driver_2.11.054c9c4c.bin
wget https://download.01.org/intel-sgx/sgx-linux/2.16/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.16.100.4.bin
chmod +x sgx_linux_*
./sgx_linux_x64_driver_1.41.bin
./sgx_linux_x64_driver_2.11.054c9c4c.bin
./sgx_linux_x64_sdk_2.16.100.4.bin
```

When you install ``sgx_linux_x64_sdk_2.16.100.4.bin``, you will be prompted to select a location to install SGX SDK, let's suppose you assign ``$INTEL_SGX_SDK`` as the directory. Also, after installation, you should be prompted to use a ``source`` command to set up the SGX SDK environment.

Use the following commands to install some Intel SGX plugins:

```
cd $INTEL_SGX_DIR
mkdir sgx_plugins
cd sgx_plugins
wget https://download.01.org/intel-sgx/sgx-linux/2.16/distro/ubuntu18.04-server/debian_pkgs/devel/libsgx-enclave-common-dev/libsgx-enclave-common-dev_2.16.100.4-bionic1_amd64.deb
wget https://download.01.org/intel-sgx/sgx-linux/2.16/distro/ubuntu18.04-server/debian_pkgs/devel/libsgx-epid-dev/libsgx-epid-dev_2.16.100.4-bionic1_amd64.deb
wget https://download.01.org/intel-sgx/sgx-linux/2.16/distro/ubuntu18.04-server/debian_pkgs/devel/libsgx-headers/libsgx-headers_2.16.100.4-bionic1_amd64.deb
wget https://download.01.org/intel-sgx/sgx-linux/2.16/distro/ubuntu18.04-server/debian_pkgs/devel/libsgx-launch-dev/libsgx-launch-dev_2.16.100.4-bionic1_amd64.deb
wget https://download.01.org/intel-sgx/sgx-linux/2.16/distro/ubuntu18.04-server/debian_pkgs/devel/libsgx-quote-ex-dev/libsgx-quote-ex-dev_2.16.100.4-bionic1_amd64.deb
wget https://download.01.org/intel-sgx/sgx-linux/2.16/distro/ubuntu18.04-server/debian_pkgs/devel/libsgx-ra-network-dev/libsgx-ra-network-dev_1.13.100.4-bionic1_amd64.deb
wget https://download.01.org/intel-sgx/sgx-linux/2.16/distro/ubuntu18.04-server/debian_pkgs/devel/libsgx-ra-uefi-dev/libsgx-ra-uefi-dev_1.13.100.4-bionic1_amd64.deb
wget https://download.01.org/intel-sgx/sgx-linux/2.16/distro/ubuntu18.04-server/debian_pkgs/libs/libsgx-ra-network/libsgx-ra-network_1.13.100.4-bionic1_amd64.deb
wget https://download.01.org/intel-sgx/sgx-linux/2.16/distro/ubuntu18.04-server/debian_pkgs/libs/libsgx-ra-uefi/libsgx-ra-uefi_1.13.100.4-bionic1_amd64.deb
sudo dpkg -i libsgx-headers_2.16.100.4-bionic1_amd64.deb
sudo dpkg -i libsgx-enclave-common-dev_2.16.100.4-bionic1_amd64.deb
sudo dpkg -i libsgx-epid-dev_2.16.100.4-bionic1_amd64.deb
sudo dpkg -i libsgx-launch-dev_2.16.100.4-bionic1_amd64.deb
sudo dpkg -i libsgx-quote-ex-dev_2.16.100.4-bionic1_amd64.deb
sudo dpkg -i libsgx-ra-network_1.13.100.4-bionic1_amd64.deb
sudo dpkg -i libsgx-ra-network-dev_1.13.100.4-bionic1_amd64.deb
sudo dpkg -i libsgx-ra-uefi_1.13.100.4-bionic1_amd64.deb
sudo dpkg -i libsgx-ra-uefi-dev_1.13.100.4-bionic1_amd64.deb
```

Assume the root directory of the project is ``$vronicle``, use the following commands to compile the SGX-based server.

```
cd $vronicle
./make_server.sh ~/vronicle/vronicle/
cd $vronicle/scheduler
make
```

To run the server, use the following commands to start the scheduler.

```
cd $vronicle/scheduler
sudo ./scheduler 10112
```

``sudo ./scheduler 10112`` will start the scheduler and let it listen at port 10112. (Note that the server should have the corresponding ports opened)

When each request comes in, different enclave server will be started, which is shown in the log. The log also shows the port used by the corresponding enclave server, including the one used by the encoding server, which will be used later in the viewer for it to download the processed video.

## Vronicle TrustZone-based Server

The following steps are tested on a Ubuntu 20.04 desktop (4-core; 16GB RAM) and a Hikey 620 LeMaker 8GB (2GB RAM) board. 

First, download all files from another repo: https://github.com/trusslab/vronicle_trustzone. We would assume a folder ``<vronicle_trustzone_based_server_directory>`` is used.

We use AOSP with OP-TEE for our TrustZone-based server. To build it, we assume the folder ``$trustzone_server`` is used. The following commands will build the TrustZone-based evaluation server with modified amount of memory. (See https://github.com/OP-TEE/optee_os/issues/2597 for details)

```
cd $trustzone_server
git clone https://github.com/linaro-swg/optee_android_manifest [-b <release_tag>]
cd optee_android_manifest
./sync-p.sh
cp -r <vronicle_trustzone_based_server_directory>/optee_examples $trustzone_server/external/
cp -r <vronicle_trustzone_based_server_directory>/plat-hikey $trustzone_server/optee/optee_os/core/arch/arm/
./build-p.sh
```

As compiling AOSP with OP-TEE can be challenging, we also provide pre-built binary files in  ``<vronicle_trustzone_based_server_directory>/hikey``.

For flashing the image to your Hikey board, please follow the tutorial in this link: https://optee.readthedocs.io/en/latest/building/aosp/aosp.html#flashing-the-image.

Now you should be able to run filter evaluations on the Hikey board. After it boots up, the following command can be invoked to do filter evaluations. Further instructions are shown when calling the command.

```
optee_examples_hello_world
```

## Vronicle Linux Viewer

The following steps are tested on a Ubuntu 20.04 desktop (4-core; 16GB RAM). The libraries setup is similar to the one mentioned in SGX-based Server, which is therefore omitted here.

Assume the root directory of the project is ``$vronicle``, use the following command to compile the viewer.

```
cd $vronicle/viewer
./build_viewer.sh
```

Assume the Encoder Enclave server has IP: ``<encoder_ip>`` and port: ``<encoder_port>``, first modify the script ``$vronicle/viewer/run_viewer.sh`` at line 10, which sets the encoder IP and port, and then use the following commands to run the viewer.

```
cd $vronicle/viewer
./run_viewer.sh
```

