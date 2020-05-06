bpfink (BPF based FIM solution)
==========================================

This program aim to track select files in order to detect changes and log the
difference between the old and new version. The creation of this program is
motivated by the desire to have near real time file monitoring on linux systems.

Documentation
-------------

Most of the documentation can be found in the [docs](./docs) directory.

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
                +------------+-------------+--------------------------+
                |                          |                          |
                v                          v                          v
     +----------+---------+     +----------+---------+     +----------+---------+
     |                    |     |                    |     |                    |
     |       Consumer     |     |      Consumer      |     |     Consumer       |
     |                    |     |                    |     |                    |
     | /etc/access.conf   |     |   /etc/password    |     |      Generic       |
     |                    |     |   /etc/shadow      |     |      any file      |
     |                    |     |                    |     |      or dir        |
     +----------+---------+     +----------+---------+     +----------+---------+
                |                          |                          |
                v                          v                          v
+---------------+-----------+ +------------+--------------+ +---------+------------+
|                           | |                           | |                      |
|           parser          | |          parser           | |        parser        |
|                           | |                           | |                      |
+--------------+------------+ +--------------+------------+ +--------------+-------+
               |                             |                             |
               +-----------------------------+-----------------------------+
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
it also watch for user home directory to detect ssh key injection.
- Access consumer, just watch __/access.conf__
- Generic consumer, watches for any existing or new files/directories for any given parent directory

All consumers hold their own states to keep track of changes and diffing. If
a difference is spotted, the diff is logged to our stdout in json format.
In parallel consumers are persisting their state in a key value store (currently BoltDB).

Current status
--------------

This project is activily being developed, and is currently in a beta status. It is functional but things
will be changing. We will be working on coming up with tasks, so that other can contrubute to the project.


Contributions
-------------
We welcome all contributions, and hope to build a great product with a community of backers. Please read our [Contributions guide](./CONTRIBUTING.md) for expectations when contributing to this repo. 


ACKNOWLEDGMENT
--------------

This software was originally developed at Booking.com. With approval from Booking.com,
this software was released as open source, for which the authors would like to express 
their gratitude.

