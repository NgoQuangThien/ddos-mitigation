go mod init examples/ebpf-test
go mod tidy

go get github.com/cilium/ebpf/cmd/bpf2go

go generate

go build && sudo ./ebpf-test

go generate && go build && sudo ./ebpf-test
