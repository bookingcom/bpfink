BINARY = bpfink
LD_FLAGS ?= -w -s -X main.BuildDate=$(shell date +%F)
PREFIX ?= /usr

all: build
build: $(BINARY)
install: $(PREFIX)/bin/$(BINARY)

$(BINARY):
	$(MAKE) -C pkg/ebpf
	go build -ldflags '$(LD_FLAGS)' -o $@ cmd/*.go

$(PREFIX)/bin/$(BINARY): $(BINARY)
	install -p -D -m 0755 $< $@
	$(MAKE) -r -C pkg/ebpf install

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
