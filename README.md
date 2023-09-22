# cmake-cross-compile

### dependency package
> sudo apt-get install -y crossbuild-essential-arm64 gcc-aarch64-linux-gnu g++-aarch64-linux-gnu

### compile hello and run for x86
> $ cd build
> $ COMPILE_TARGET=x86 cmake ../
> $ make
> $ ./hello_world

### compile hello and run for arm
> cd build
> COMPILE_TARGET=x86 cmake ../
> make
> scp ./hello_world <armserver>@<IP ADDR>
> armserver$./hello_world


### Clean cmake build target
> $ ./clean_build.sh