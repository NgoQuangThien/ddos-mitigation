```
go mod init main/ebpf
```

```
go mod tidy
```

```
go get github.com/cilium/ebpf/cmd/bpf2go
```

```
go generate && go build
```

```
sudo ./ebpf ens37
```
