BINARY = bpfink
LD_FLAGS ?= -w -s -X main.BuildDate=$(shell date +%F) -X main.Version=$(BINARY_VERSION)
PREFIX ?= /usr
BINARY_VERSION ?=

all: build
build: $(BINARY)
install: $(PREFIX)/bin/$(BINARY)

.PHONY: $(BINARY)
$(BINARY):
	$(MAKE) -r -C pkg/ebpf
	CGO_CPPFLAGS="-D SO_ATTACH_BPF=SO_ATTACH_FILTER -D SO_DETACH_BPF=SO_DETACH_FILTER" go build -ldflags '$(LD_FLAGS)' -o $@ cmd/*.go

$(PREFIX)/bin/$(BINARY): $(BINARY)
	install -p -D -m 0755 $< $@
	$(MAKE) -r -C pkg/ebpf install

.PHONY: e2etests
e2etests: $(BINARY)
	@sudo -E go test -tags e2e -race ./e2etests --bpfink-bin '$(PWD)/$(BINARY)' --ebpf-obj '$(PWD)/pkg/ebpf/vfs.o'

.PHONY: clean
clean:
	@rm -vf $(BINARY)
	@$(MAKE) -C pkg/ebpf clean

.PHONY: cover
cover:
	@bash -c "go tool cover -func <(go test -v -cover -coverprofile >(tee) ./... > /dev/null)"

.PHONY: vet
vet:
	@go vet ./cmd ./pkg

.PHONY: fmt
fmt:
	@bash -c "diff -u <(echo -n) <(gofmt -d ./)"

.PHONY: test
test: cover vet fmt

.PHONY: test-unit
test-unit:
	go test -race -v ./pkg/...
