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
└── packet_capture.c
```

### compile packet capture and run for x86
```
cd build
COMPILE_TARGET=x86 cmake ../
make
./packet_capture
```

### compile packet capture and run for arm
```
cd build
COMPILE_TARGET=arm cmake ../
make
# scp compiled library and binary to target server
scp /usr/local/lib/libpcap.so.1.9.1 <armserver>@<ip addr>
scp ./packet_capture <armserver>@<ip addr>
armserver$./packet_capture
```


### Clean cmake build target
```
./clean_build.sh
```