cmake_minimum_required(VERSION 3.16)
project(RinRuntime VERSION 1.0.0 LANGUAGES C CXX)

option(RINRUNTIME_BUILD_TESTS "Build RinRuntime host tests" ON)
option(RINRUNTIME_BUILD_SHARED "Build RinRuntime as a shared library" OFF)
option(RINRUNTIME_BUILD_EXAMPLES "Build RinRuntime host examples" ON)
set(RINRUNTIME_LIBRARY_TYPE STATIC)
if(RINRUNTIME_BUILD_SHARED)
    set(RINRUNTIME_LIBRARY_TYPE SHARED)
endif()
set(RINRUNTIME_SOURCES
    src/portal.c
    src/crash.c
    src/backup_restore.c
    src/known_folders.c
    src/file_operation.c
    src/safe_save.c
    src/safe_save_posix.c
    src/session_recovery.c
    src/crash_service.c)
# crashd is a RinOS local-socket service.  The host Windows build has no
# RinOS AF_UNIX/poll ABI; keep that transport out of the host library rather
# than substituting a success path.  RinOS/Unix builds include the real client.
if(NOT WIN32)
    list(APPEND RINRUNTIME_SOURCES src/crash_service_client.c)
endif()
add_library(RinRuntime ${RINRUNTIME_LIBRARY_TYPE}
    ${RINRUNTIME_SOURCES})
add_library(RinRuntime::RinRuntime ALIAS RinRuntime)
target_compile_features(RinRuntime PUBLIC c_std_11)
target_include_directories(RinRuntime PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../RinOS-SDK/include>
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
    add_executable(rinruntime-policy-test tests/policy_contract_test.c)
    target_link_libraries(rinruntime-policy-test PRIVATE RinRuntime::RinRuntime)
    add_test(NAME rinruntime-policy COMMAND rinruntime-policy-test)
    add_executable(rinruntime-crash-service-test tests/crash_service_contract_test.c)
    target_link_libraries(rinruntime-crash-service-test PRIVATE RinRuntime::RinRuntime)
    add_test(NAME rinruntime-crash-service COMMAND rinruntime-crash-service-test)
endif()

if(RINRUNTIME_BUILD_EXAMPLES)
    foreach(example_name IN ITEMS basic_widgets layout accessibility
            application_data document_app printing crash_reporter)
        add_executable(rinruntime-example-${example_name}
                       examples/${example_name}.cpp)
        target_link_libraries(rinruntime-example-${example_name}
                              PRIVATE RinRuntime::RinRuntime)
        target_include_directories(rinruntime-example-${example_name}
                                   PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
        set_target_properties(rinruntime-example-${example_name}
                              PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    endforeach()
endif()
