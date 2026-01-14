#!/bin/bash
set -e

echo "Building lwIP shared library..."

cd "$(dirname "$0")/../py-lwip"

# Initialize submodules if not already done
if [ ! -f "lwip/README" ]; then
    echo "Initializing lwIP submodule..."
    git submodule update --init --recursive
fi

# Build the library using py-lwip's Makefile
echo "Compiling lwIP..."
make lwip-lib

echo "lwIP library built successfully!"
echo "Library location: py-lwip/lwip_lib/build/liblwip.so"
