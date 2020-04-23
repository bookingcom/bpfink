BPF
=======

### How we run BPF 
bpfink is using BPF to trace file events in the kernels space. While most users of BPF rely on [BCC](https://github.com/iovisor/bcc). Which does JIT compilation of BPF programs. This introduces a hard requires every host to have llvm, and c-lang to be installed. We decided, it is much simpler to pre-compile the BPF program into an ELF file and load this in at runtime. We build out multiple ELF files per Kernel `Major.Minor` versions. Right now we build packages per Kernel `Major.Minor` version. 

The current plan is to build out all Kernel `Major.Minor` versions of the ELF file, and give bpfink the ability to pick the correct version at runtime. 

### BPF program overview
Right now the BPF program has two probes `vfs_write` and `vfs_rename`. The `vfs_write` probe covers most traditional file write events. When the probe is triggered, we read in `inode number` from the event. Using a hash map build out of inodes from files we want to monitor, we check to see if the inode number exists in the hashmap. If it does, we send an event to user space with a ring buffer map. 

Some programs like passwd, want to write files atomically. One way to approach this is to write to a different file, and using the rename syscall. This allows for the temp file to become the real file in one atomic function call. In order to catch these types of events. The probe `vfs_rename` looks for old inode numbers in our hashmap. If the inode exists, we send an event to userspace via the ring buffer. Where the user space program reload the file into the hashmap. So that future changes can be monitored. 


### Future plans
There has been some research into monitoring mmap on files, so that events can be sent to user space. This will likely be achieved by coupling multiple probes together: 
* `vma_link`
* `sys_msync`
* `fd_install`
* `vfs_unlink`
* `vfs_open`
* `vfs_rmdir`
* `done_path_create`


There are other linux system function calls that will need to have probes implemented as well. 