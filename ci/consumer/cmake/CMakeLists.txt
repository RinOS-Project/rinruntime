cmake_minimum_required(VERSION 3.16)
project(RinRuntimeInstalledConsumer LANGUAGES C CXX)

find_package(RinRuntime 1 CONFIG REQUIRED)

add_executable(rinruntime-consumer-c ../consumer.c)
target_include_directories(rinruntime-consumer-c PRIVATE ..)
target_link_libraries(rinruntime-consumer-c PRIVATE RinRuntime::RinRuntime)

add_executable(rinruntime-consumer-cxx ../consumer.cpp)
target_include_directories(rinruntime-consumer-cxx PRIVATE ..)
target_link_libraries(rinruntime-consumer-cxx PRIVATE RinRuntime::RinRuntime)
