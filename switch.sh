#!/bin/bash

rm build
rm plugins/protocol-plugin/build
ln -s cmake-build-$1 build
ln -s cmake-build-$1 plugins/protocol-plugin/build
ls -la build
ls -la plugins/protocol-plugin/build
