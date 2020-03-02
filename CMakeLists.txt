cmake_minimum_required(VERSION 3.15)
project(krbC C)

set(CMAKE_C_STANDARD 99)

add_executable(krbC main.c)
# Make sure the library is there
target_link_libraries(krbC LINK_PUBLIC /usr/lib/x86_64-linux-gnu/libgssapi.so.3)