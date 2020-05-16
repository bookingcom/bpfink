FROM centos:7

# install Go 
RUN Run wget https://dl.google.com/go/go1.13.3.linux-amd64.tar.gz && \
    tar -xzf go1.13.3.linux-amd64.tar.gz && \
    mv go /usr/local

# install bpf build dependancies
RUN yum install -y epel-release && \
    yum update -y && \
    yum groupinstall -y "Development tools" && \
    yum install -y elfutils-libelf-devel cmake3 git bison flex ncurses-devel && \
    yum install -y luajit luajit-devel  # for Lua support && \
    yum install -y centos-release-scl && \
    yum-config-manager --enable rhel-server-rhscl-7-rpms && \
    yum install -y devtoolset-7 llvm-toolset-7 llvm-toolset-7-llvm-devel llvm-toolset-7-llvm-static llvm-toolset-7-clang-devel && \
    source scl_source enable devtoolset-7 llvm-toolset-7

RUN mkdir -p /workspace/code/src/github.com && \
    cd /workspace/code/src/github && \
    git clone https://github.com/iovisor/bcc.git && \
    mkdir bcc/build; cd bcc/build && \
    cmake3 .. && \
    make && \
    sudo make install