# cmake-cross-compile

### dependency package
> sudo apt-get install -y crossbuild-essential-arm64 gcc-aarch64-linux-gnu g++-aarch64-linux-gnu

### Create a build folder
```
$ mkdir build
$ tree
.
├── CMakeLists.txt
├── README.md
├── build
├── clean_build.sh
└── arp_req.c
```

### compile packet capture and run for x86
```
cd build
COMPILE_TARGET=x86 cmake ../
make
./parp_req.c
```

### compile packet capture and run for arm
```
cd build
COMPILE_TARGET=arm cmake ../
make
# scp binary to target server
scp ./arp_req.c <armserver>@<ip addr>
armserver$./arp_req.c
```


### Clean cmake build target
```
./clean_build.sh
```
