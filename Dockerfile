FROM centos:7

# install bpf build dependancies
RUN yum install -y epel-release && \
    yum update -y && \
    yum groupinstall -y "Development tools" && \
    yum install -y elfutils-libelf-devel cmake3 git bison flex ncurses-devel && \
    yum install -y luajit luajit-devel  # for Lua support

# build and install bcc
RUN yum install -y centos-release-scl && \
    yum-config-manager --enable rhel-server-rhscl-7-rpms && \
    yum install -y devtoolset-7 llvm-toolset-7 llvm-toolset-7-llvm-devel llvm-toolset-7-llvm-static llvm-toolset-7-clang-devel && \
    source scl_source enable devtoolset-7 llvm-toolset-7 && \
    mkdir -p /workspace/code/src/github.com && \
    cd /workspace/code/src/github.com && \
    git clone https://github.com/iovisor/bcc.git && \
    mkdir bcc/build && \
    cd bcc/build && \
    cmake3 .. && \
    make && \
    make install

# enable GCC and Clang permanently for logged in user
RUN echo "source scl_source enable devtoolset-7 llvm-toolset-7" >> ~/.bashrc

# install kernel-devel for 3.10
RUN yum install -y kernel-devel

# install kernel-devel for 4.9
RUN yum install -y http://dl.central.org/dl/linuxdev/fedora25/x86_64/kernel-devel-4.9.3-200.fc25.x86_64.rpm

# install kernel-devel for 4.14
RUN yum install -y http://dl.central.org/dl/linuxdev/fedora27/x86_64/kernel-devel-4.14.3-300.fc27.x86_64.rpm

# install kernel-devel for 4.18
RUN yum install -y http://mirror.centos.org/centos/8/BaseOS/x86_64/os/Packages/kernel-devel-4.18.0-193.6.3.el8_2.x86_64.rpm

# install kernel-devel for 4.19
RUN yum install -y http://dl.central.org/dl/linuxdev/fedora29/x86_64/kernel-devel-4.19.2-300.fc29.x86_64.rpm

# set up build script
COPY scripts/build.sh .
CMD ["./build.sh"]
