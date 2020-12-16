#!/bin/sh

HOME_DIR=$PWD

cd $HOME_DIR/client_side; make clean; make;
cd $HOME_DIR/scheduler; make clean; make;
cd $HOME_DIR/decoder; make clean; make;
cd $HOME_DIR/filter_blur; make clean; make;
cd $HOME_DIR/filter_brightness; make clean; make;
cd $HOME_DIR/filter_denoise_easy; make clean; make;
cd $HOME_DIR/filter_gray; make clean; make;
cd $HOME_DIR/filter_sharpen; make clean; make;
cd $HOME_DIR/filter_white_balance; make clean; make;
cd $HOME_DIR/encoder; make clean; make;
