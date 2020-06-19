#!/bin/bash
set -e # exit on non-zero exit code

# shellcheck disable=SC2016
cd workspace/pkg/ebpf ||
    (
        echo "ERROR: run inside bpfink folder with following flag to docker:" &&
            echo 'ERROR: -v $(pwd):/workspace' &&
            exit 1
    )

# this command returns non-zero error code, which we want to ignore
source scl_source enable devtoolset-7 llvm-toolset-7 || true

KERNELS=$(rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}.%{ARCH}\n' | grep kernel-devel | cut -d ' ' -f 2)
KERNELS_SHORT=$(rpm -qa --qf '%{NAME} %{VERSION}\n' | grep kernel-devel | cut -d ' ' -f 2 | cut -d '.' -f -2)

for kernel in 3.10 4.9 4.14 4.18 4.19; do
    make -r -C "." -e KERNEL_RELEASE="$(echo "$KERNELS" | grep $kernel)"
    mv -f vfs.o "vfs-$(echo "$KERNELS_SHORT" | grep $kernel)".o
done
