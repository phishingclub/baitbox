.PHONY: build build-arm

# build a single, self contained production binary with docker -> build/baitbox
# no host go toolchain is needed. override the version with: make build VERSION=1.2.3
build:
	VERSION=$(VERSION) BIN_ARCH=amd64 ./build_scripts/build.sh

# same as build but for linux arm64 (needs qemu locally)
build-arm:
	VERSION=$(VERSION) BIN_ARCH=arm64 ./build_scripts/build.sh
