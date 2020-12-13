#!/bin/sh

HOME_DIR=$PWD

cd $HOME_DIR/client_side; make;
cd $HOME_DIR/scheduler; make;
cd $HOME_DIR/decoder; make;
cd $HOME_DIR/filter_blur; make;
cd $HOME_DIR/encoder; make;
