#!/bin/sh

HOME_DIR=$PWD

cd $HOME_DIR/client_side; make clean;
cd $HOME_DIR/scheduler; make clean;
cd $HOME_DIR/decoder; make clean;
cd $HOME_DIR/filter_blur; make clean;
cd $HOME_DIR/filter_brightness; make clean;
cd $HOME_DIR/filter_denoise_easy; make clean;
cd $HOME_DIR/filter_gray; make clean;
cd $HOME_DIR/filter_sharpen; make clean;
cd $HOME_DIR/filter_white_balance; make clean;
cd $HOME_DIR/encoder; make clean;

cd $HOME_DIR/client_side; make;
cd $HOME_DIR/scheduler; make;
cd $HOME_DIR/decoder; make;
cd $HOME_DIR/filter_blur; make;
cd $HOME_DIR/filter_brightness; make;
cd $HOME_DIR/filter_denoise_easy; make;
cd $HOME_DIR/filter_gray; make;
cd $HOME_DIR/filter_sharpen; make;
cd $HOME_DIR/filter_white_balance; make;
cd $HOME_DIR/encoder; make;
