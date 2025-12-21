#!/usr/bin/env bash

export CGO_ENABLED=0 GOOS=windows

build() {
    local output="dnsr-$1"
    
    echo ">>> Building $1..."
    env GOARCH=$1 $2 go build -ldflags '-s -w' -trimpath -o "$output" && \
    upx --best --lzma "$output" >> /dev/null
}

build amd64
build 386
build arm
build arm64
build ppc64
build ppc64le

build mips   GOMIPS=softfloat
build mipsle GOMIPS=softfloat
# build mips64le GOMIPS=softfloat
# build riscv64
