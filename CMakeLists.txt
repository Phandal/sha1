cmake_minimum_required(VERSION 3.16..4.0)

project(libsha1)
option(BUILD_BINARY "build the 'hash' binary" OFF)
option(BUILD_TEST_DRIVER "build the test driver" OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(sha1 STATIC lib/sha1.c lib/sha1.h)
add_library(sha256 STATIC lib/sha256.c lib/sha256.h)

if(BUILD_TEST_DRIVER)
  add_executable(test_libsha src/test_driver.c)
  target_link_libraries(test_libsha sha1)
  target_link_libraries(test_libsha sha256)
  target_include_directories(test_libsha PRIVATE lib)
endif(BUILD_TEST_DRIVER)

if(BUILD_BINARY)
  add_executable(hash src/main.c)
  target_link_libraries(hash sha1)
  target_link_libraries(hash sha256)
  target_include_directories(hash PRIVATE lib)
endif(BUILD_BINARY)
