wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 18
rm -rf llvm.sh

sudo ln -s /usr/bin/clang-18 /usr/local/bin/clang
sudo ln -s /usr/bin/llvm-strip-18 /usr/local/bin/llvm-strip

wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
