bpfink (BPF based FIM solution)
==========================================

This program aim to track select files in order to detect changes and log the
difference between the old and new version. The creation of this program is
motivated by the desire to have near real time file monitoring on linux systems.

Documentation
-------------

- [BPF](./bpf.md) 
- [Building](./build.md)

Technical overview
------------------

__Main dependencies:__
- [eBPF](https://github.com/iovisor/gobpf/) to handle kernel write events.
- [boltdb](https://github.com/etcd-io/bbolt) for state persistence.
- [graphite](https://graphiteapp.org/) optional to tracking installation, and number of events processed


```text
                   +--------------------+
                   |                    |
                   |    File System     |
                   |                    |
                   +---------+----------+
                             |
                             v
                      +------+-------+
                      |              |
                      |     eBPF     |
                      |              |
                      +------+-------+
                             |
                +------------+-------------+
                |                          |
                v                          v
     +----------+---------+     +----------+---------+
     |                    |     |                    |
     |       Consumer     |     |      Consumer      |
     |                    |     |                    |
     | /etc/access.conf   |     |   /etc/password    |
     |                    |     |   /etc/shadow      |
     |                    |     |                    |
     +----------+---------+     +----------+---------+
                |                          |
                v                          v
+---------------+-----------+ +------------+--------------+
|                           | |                           |
|           parser          | |          parser           |
|                           | |                           |
+--------------+------------+ +--------------+------------+
               |                             |
               +-------------+---------------+
                             |
       +--------------+      |    +---------------------+
       |              |      |    |                     |
       |    BoltDB    +<-----+--->+        STDOUT       |
       |              |           |                     |
       +--------------+           +---------------------+
```

bpfink Is a set of consumers connected to file system watcher. We are currently using eBPF to watch vfs_write syscalls in the kernel.
When an event is fired the associated consumer is called, we have currently two
different consumers for three different use cases:

- User consumer, watch for the __/passwd__, __/shadow__ file to detect password changes
(password hash is not logged to avoid offline brute force on leaked logs),
it also watches for user home directory to detect ssh key injection.
- Access consumer, just watch __/access.conf__

All consumers hold their own states to keep track of changes and diffing. If
a difference is spotted, the diff is logged to our stdout in json format.
In parallel consumers are persisting their state in a key value store (currently BoltDB).

Current status
--------------

This project is actively being developed, and is currently in a beta status. It is functional but things
will be changing. We will be working on coming up with tasks, so that other can contribute to the project.

Right now, dynamic file/dir watching is actively being worked on, and will be the next major milestone. Once this is complete, the code should ideally go for a refactor to improve memory usage, and improve code readability. 
