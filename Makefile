arch:=x86_64
DEBUG:=0
container:=ccob/windows-llvm-cross-msvc

.PHONY: all

all:
	docker run --rm -t -i -v "$$PWD:/data" ${container} /bin/bash -c '\
		cd /data && \
		mkdir -p build && \
		cd build && \
		cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=/opt/toolchain/${arch}-pc-windows-msvc.cmake -DCMAKE_INSTALL_PREFIX=./dist -D DEBUG=${DEBUG} .. && \
		cmake --build . && \
		cmake --install .'
