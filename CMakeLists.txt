cmake_minimum_required(VERSION 3.16)
project(RinRuntime VERSION 1.0.0 LANGUAGES C CXX)

option(RINRUNTIME_BUILD_TESTS "Build RinRuntime host tests" ON)
add_library(RinRuntime STATIC src/portal.c)
add_library(RinRuntime::RinRuntime ALIAS RinRuntime)
target_compile_features(RinRuntime PUBLIC c_std_11)
target_include_directories(RinRuntime PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
if(NOT MSVC)
    target_compile_options(RinRuntime PRIVATE -Wall -Wextra -Wpedantic)
endif()

include(GNUInstallDirs)
install(TARGETS RinRuntime EXPORT RinRuntimeTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT RinRuntimeTargets
        FILE RinRuntimeTargets.cmake
        NAMESPACE RinRuntime::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/RinRuntime)

configure_file(rinruntime.pc.in rinruntime.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/rinruntime.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

if(RINRUNTIME_BUILD_TESTS)
    enable_testing()
    add_executable(rinruntime-model-test tests/runtime_model_test.cpp)
    target_link_libraries(rinruntime-model-test PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-model-test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(rinruntime-model-test PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-model COMMAND rinruntime-model-test)
    add_executable(rinruntime-portal-test tests/portal_contract_test.c)
    target_link_libraries(rinruntime-portal-test PRIVATE RinRuntime::RinRuntime)
    add_test(NAME rinruntime-portal COMMAND rinruntime-portal-test)
endif()
