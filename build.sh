#!/bin/bash
echo Build C Libs
git submodule update --init
cd libs
echo "Working Directory:" `pwd`

# echo Build LuaJIT 
# cd LuaJIT
# make && sudo make install
# sudo ln -sf luajit-2.1.0-beta3 /usr/local/bin/luajit
# cd ..

# echo Build Brotli
# cd brotli
# ./bootstrap && ./configure -static
# make && sudo make install
# cd ..

cd ..
git submodule deinit --all -f
echo Complete!
pwd

# echo Notice: You need to make sure that you have installed luajit in the running environment.

# go generate
go build -a -ldflags "-X 'main.buildstamp=`date -u --rfc-3339=seconds`' -X 'main.gitver=`git describe --long --dirty --tags`'"