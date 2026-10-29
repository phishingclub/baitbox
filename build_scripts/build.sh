#!/bin/sh
set -e

# build a single, self contained baitbox binary.
# uses docker only, no host go toolchain is needed. output is build/baitbox.
#
# this mirrors the sibling projects: same pinned golang image and the same musl
# static cgo build, so the local binary matches the released one. the sqlite
# driver is cgo, hence gcc and musl-dev and the static link.
#
# the build omits the dev build tag on purpose: the dev tag selects the local
# pebble ACME issuer, the default selects Let's Encrypt production. a binary
# built here is a production binary, run it with config.prod.json.
#
# defaults to linux amd64, override with:
#   BIN_ARCH=arm64 ./build_scripts/build.sh   (needs qemu locally)
#   VERSION=1.2.3 ./build_scripts/build.sh

# pinned images, keep in sync with the sibling projects and .github/workflows/test-build.yml
GO_IMAGE_AMD64="golang@sha256:bff16a94c0b4b6d9642581e2a3aa81beb3edb940b2f5a3aac1d22c6a68cb7747" # golang:1.27.3-alpine linux/amd64
GO_IMAGE_ARM64="golang@sha256:ee0dcdc452cb73890363fbef65fc333aeb0da7c24ba52f2c6428a37b0e7f4f1c" # golang:1.27.3-alpine linux/arm64

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
cd "$REPO_ROOT"

USER_ID=$(id -u)
GROUP_ID=$(id -g)
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
BIN_ARCH=${BIN_ARCH:-amd64}

case "$BIN_ARCH" in
	amd64) GO_IMAGE="$GO_IMAGE_AMD64"; PLATFORM="" ;;
	arm64) GO_IMAGE="$GO_IMAGE_ARM64"; PLATFORM="--platform linux/arm64" ;;
	*) echo "unsupported BIN_ARCH=$BIN_ARCH (use amd64 or arm64)"; exit 1 ;;
esac

echo "### Building admin SPA into frontend/build (embedded by the Go build)"
# only the frontend directory is mounted, and npm ci installs exactly what
# package-lock.json pins with install scripts off. esbuild needs no install
# script: it finds its binary through its optional platform package. the vite
# build empties build/, so the tracked placeholder is put back after it.
sudo docker run --rm \
	-v "$REPO_ROOT/frontend":/app \
	-w /app \
	node@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3 `# node:22-slim` \
	sh -c "npm ci --ignore-scripts --no-audit --no-fund && npm run build && touch build/.gitkeep"

echo "### Building baitbox for linux/$BIN_ARCH (version $VERSION)"
mkdir -p build

# cgo build statically linked against musl, matches the released binary
sudo docker run --rm $PLATFORM \
	-v "$REPO_ROOT":/app \
	-w /app \
	"$GO_IMAGE" \
	sh -c "apk add --no-cache gcc=15.2.0-r5 musl-dev=1.2.6-r3 && go build -trimpath -mod vendor \
		-ldflags='-X main.version=$VERSION -linkmode=external -extldflags=-static' \
		-o /app/build/baitbox ."

sudo chown -R "$USER_ID:$GROUP_ID" build

echo "### Done"
ls -lh "$REPO_ROOT/build/baitbox"
