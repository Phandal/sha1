cmake_minimum_required(VERSION 3.16..4.0)

project(libsha1)

add_library(sha1 STATIC lib/sha1.c lib/sha1.h)

add_executable(hash src/main.c)
target_link_libraries(hash sha1)
target_include_directories(hash PRIVATE lib)
