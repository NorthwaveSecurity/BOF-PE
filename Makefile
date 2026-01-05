export DEBUG:=1
container:=ccob/windows-llvm-cross-msvc

define build
	docker run --rm -t -i -v "$$PWD:/data" -w /data -e DEBUG=${DEBUG} -e ARCH=${ARCH} ${container} ./build.sh
endef

.PHONY: all
.EXPORT_ALL_VARIABLES:

x64: ARCH = x64
x64: ; $(build)

x86: ARCH = x86
x86: ; $(build)

