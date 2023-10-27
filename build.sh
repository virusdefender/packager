#! /bin/bash

DATETIME=$(date '+%Y-%m-%d')
GITCOMMIT=$(git rev-parse --short=8 HEAD 2>/dev/null || echo "__unknown__")
GITTAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "0.0.0")

buildinfo="github.com/virusdefender/goutils/buildinfo"
function build() {
  set -x
  go build -o build/packager_${GOOS}_${GOARCH}${Ext} -ldflags \
      "-s -w -X ${buildinfo}.GitCommit=${GITCOMMIT} -X ${buildinfo}.Version=${GITTAG}" cli/main.go
}

GOOS=linux GOARCH=amd64 build
GOOS=linux GOARCH=arm64 build
GOOS=windows GOARCH=amd64 Ext=.exe build
GOOS=windows GOARCH=386 Ext=.exe build
GOOS=darwin GOARCH=amd64 build
GOOS=darwin GOARCH=arm64 build