#!/bin/sh
rm -r out/
mkdir out/
pushd out
cmake ..
cp compile_commands.json ..
popd

