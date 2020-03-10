#!/bin/sh
for module in "$GOPATH"/pkg/mod/github.com/iovisor/*/elf/module.go; do
  patch -f --verbose "${module}" \
    "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/centos-fix.patch"
done
