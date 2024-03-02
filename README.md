# ddos-mitigation
## This program depends on bpf_link, available in Linux kernel version 5.7 or newer.

## LLVM 
Ubuntu clang version 18.1.0 (++20240221023121+bba39443eb91-1~exp1~20240221023233.52)
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/bin

```
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh <version number>
```

```
sudo ln -s /usr/bin/clang-18 /usr/local/bin/clang
sudo ln -s /usr/bin/llvm-strip-18 /usr/local/bin/llvm-strip
```

## libbpf headers 
```
sudo apt install libbpf-dev
```

## Linux kernel headers 3
```
sudo ln -sf /usr/include/asm-generic/ /usr/include/asm
```

## Go compiler version supported by ebpf-go's Go module
```
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```
