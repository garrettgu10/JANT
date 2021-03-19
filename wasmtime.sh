#!/bin/bash

export WASMTIME_PATH=~/wasmtime/target/aarch64-unknown-linux-gnu/debug/wasmtime

qemu-aarch64 -L /usr/aarch64-linux-gnu/ $WASMTIME_PATH $@