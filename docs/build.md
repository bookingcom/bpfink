## Building

right now building bpfink with eBPF is a multi step process. 

Run the following commands to package eBPF for each kernel major.minor version
in the future we may support JIT similar to how BCC works. 

### Dependencies
* LLVM
* clang
* kernel-devel

Generally speaking if you install bcc and bcc works you should be able to compile bpflink
[See how to install bcc](https://github.com/iovisor/bcc/blob/master/INSTALL.md)

In the future we may add a build pipeline to build a different version of the BPF program. 

```bash
cd bpfink

cd /workspace/pkg/ebpf

make -r -C "." -e KERNEL_RELEASE=<kernel_version>
```
The list of supported kernel versions can be found by running the following command inside the container.

`ls /lib/modules/`

add the updated ELF files to the repo, and push to your branch.

