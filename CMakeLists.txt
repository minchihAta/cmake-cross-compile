
cmake_minimum_required(VERSION 3.10)
set(CMAKE_C_COMPILER_NAMES clang-11 clang-10 clang-9 gcc-10 gcc-9 cc)

#
# CMake Toolchain file for crosscompiling on ARM.
#
# Target operating system name.

if ("$ENV{COMPILE_TARGET}" STREQUAL "arm")
  link_libraries(/usr/local/lib/libpcap.so.1.9.1)
  set(CMAKE_SYSTEM_NAME Linux)
  set(CMAKE_SYSTEM_PROCESSOR aarch64)
  set(CMAKE_CROSSCOMPILING TRUE)

  # Name of C compiler.
  set(CMAKE_C_COMPILER "/usr/bin/aarch64-linux-gnu-gcc")
  set(CMAKE_CXX_COMPILER "/usr/bin/aarch64-linux-gnu-g++")

  # Where to look for the target environment. (More paths can be added here)
  set(CMAKE_FIND_ROOT_PATH /usr/aarch64-linux-gnu)
  set(CMAKE_INCLUDE_PATH  /usr/include/aarch64-linux-gnu)
  set(CMAKE_LIBRARY_PATH  /usr/lib/aarch64-linux-gnu)
  set(CMAKE_PROGRAM_PATH  /usr/bin/aarch64-linux-gnu)

  # Adjust the default behavior of the FIND_XXX() commands:
  # search programs in the host environment only.
  set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

  # Search headers and libraries in the target environment only.
  set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
  set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
  set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
endif()

project(packet_capture)
add_executable(packet_capture packet_capture.c)
target_link_libraries(packet_capture ${PCAP_LIBRARY})