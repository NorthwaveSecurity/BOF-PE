#!/usr/bin/env bash
ARCH=${ARCH:-x86_64}
TOOLCHAIN_ARCH=${ARCH}
if [ "$ARCH" = "x86" ]; then
    TOOLCHAIN_ARCH=i386
elif [ "$ARCH" = "x64" ]; then
    TOOLCHAIN_ARCH=x86_64
fi
mkdir -p build && \
cd build && \
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=/opt/toolchain/${TOOLCHAIN_ARCH}-pc-windows-msvc.cmake -DCMAKE_INSTALL_PREFIX=./dist -D DEBUG=${DEBUG} -D ARCH=${ARCH} .. && \
cmake --build . && \
cmake --install .
