wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 18

sudo ln -s /usr/bin/clang-18 /usr/local/bin/clang
sudo ln -s /usr/bin/llvm-strip-18 /usr/local/bin/llvm-strip

