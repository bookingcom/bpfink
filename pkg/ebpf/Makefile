KERNEL_RELEASE ?= $(shell uname -r)

INCLUDE_DIR = include

INCLUDES =  -I $(INCLUDE_DIR)
INCLUDES += -I /lib/modules/$(KERNEL_RELEASE)/build/arch/x86/include
INCLUDES += -I /lib/modules/$(KERNEL_RELEASE)/build/arch/x86/include/generated
INCLUDES += -I /lib/modules/$(KERNEL_RELEASE)/build/include
INCLUDES += -I /lib/modules/$(KERNEL_RELEASE)/build/include/generated/uapi
INCLUDES += -I /lib/modules/$(KERNEL_RELEASE)/build/arch/x86/include/uapi
INCLUDES += -I /lib/modules/$(KERNEL_RELEASE)/build/include/uapi
INCLUDES += -I /lib/modules/$(KERNEL_RELEASE)/build/arch/x86/include/asm/asm.h

MAKEFLAGS += -r
CC = clang
LLC = llc
LLCFLAGS += -march=bpf -filetype=obj
LDFLAGS ?= -w -s -X main.BuildDate=$(shell date +%F)
CFLAGS ?= -O2
CFLAGS += -emit-llvm -fno-stack-protector -D__KERNEL__ -D__BPF_TRACING__  

PREFIX ?= /usr
NAME = bpfink
VERSION ?=
LIBRARIES = vfs$(VERSION).o

build: $(LIBRARIES)
install: $(foreach library,$(LIBRARIES), $(PREFIX)/lib/$(NAME)/$(library))

$(PREFIX)/lib/$(NAME)/%.o: %.o
	install -p -D -m 0644 $< $@

%.ll: %.c $(wildcard $(INCLUDE_DIR)/*)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@

%.o: %.ll
	$(LLC) $(LLCFLAGS) -o $@ $<

.PHONY: clean
clean:
	rm -vf $(LIBRARIES)
