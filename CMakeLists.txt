cmake_minimum_required(VERSION 3.16)
project(RinRuntime VERSION 1.0.0 LANGUAGES C CXX)

option(RINRUNTIME_BUILD_TESTS "Build RinRuntime host tests" ON)
option(RINRUNTIME_BUILD_SHARED "Build RinRuntime as a shared library" OFF)
option(RINRUNTIME_BUILD_EXAMPLES "Build RinRuntime host examples" ON)
set(RINRUNTIME_GUI_DEFAULT ON)
if(WIN32)
    set(RINRUNTIME_GUI_DEFAULT OFF)
endif()
option(RINRUNTIME_BUILD_GUI
       "Build the public compositor-backed native window API" ${RINRUNTIME_GUI_DEFAULT})
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
    src/crash_service.c
    src/path.c
    src/serial_portal_protocol.c)
# crashd is a RinOS local-socket service.  The host Windows build has no
# RinOS AF_UNIX/poll ABI; keep that transport out of the host library rather
# than substituting a success path.  RinOS/Unix builds include the real client.
if(NOT WIN32)
    list(APPEND RINRUNTIME_SOURCES src/crash_service_client.c)
    list(APPEND RINRUNTIME_SOURCES
        src/file_portal.c
        src/durable_file_portal.c
        src/file_chooser_portal.c
        src/file_operation_service_client.c
        src/accessibility_service_client.c
        src/audio/rin_audio_service_client.c)
endif()
if(RINRUNTIME_BUILD_GUI)
    if(WIN32)
        message(FATAL_ERROR
                "RINRUNTIME_BUILD_GUI requires the RinOS Unix compositor transport")
    endif()
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../aquamarine
                     ${CMAKE_CURRENT_BINARY_DIR}/aquamarine EXCLUDE_FROM_ALL)
    list(APPEND RINRUNTIME_SOURCES
         src/compositor_gui.c
         src/render.c
         src/render_context.cpp)
endif()
add_library(RinRuntime ${RINRUNTIME_LIBRARY_TYPE}
    ${RINRUNTIME_SOURCES})
add_library(RinRuntime::RinRuntime ALIAS RinRuntime)
target_compile_features(RinRuntime PUBLIC c_std_11)
if(RINRUNTIME_BUILD_GUI)
    target_compile_features(RinRuntime PUBLIC cxx_std_17)
    target_link_libraries(RinRuntime PUBLIC Aquamarine::Aquamarine)
endif()
target_include_directories(RinRuntime PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../RinOS-SDK/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../aquamarine>
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
    add_executable(rinruntime-file-portal-abi-test tests/file_portal_abi_compile_test.c)
    target_link_libraries(rinruntime-file-portal-abi-test PRIVATE RinRuntime::RinRuntime)
    add_test(NAME rinruntime-file-portal-abi COMMAND rinruntime-file-portal-abi-test)
    if(RINRUNTIME_BUILD_GUI)
        add_executable(rinruntime-window-abi-test tests/window_abi_compile_test.c)
        target_link_libraries(rinruntime-window-abi-test PRIVATE RinRuntime::RinRuntime)
        add_test(NAME rinruntime-window-abi COMMAND rinruntime-window-abi-test)
        add_library(rinruntime-render-context-abi-test OBJECT
                    tests/render_context_abi_compile_test.cpp)
        target_link_libraries(rinruntime-render-context-abi-test
                              PRIVATE RinRuntime::RinRuntime)
        set_target_properties(rinruntime-render-context-abi-test
                              PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    endif()
    add_executable(rinruntime-accessibility-client-abi-test
                   tests/accessibility_client_abi_compile_test.c)
    target_link_libraries(rinruntime-accessibility-client-abi-test PRIVATE RinRuntime::RinRuntime)
    add_test(NAME rinruntime-accessibility-client-abi
             COMMAND rinruntime-accessibility-client-abi-test)
    add_executable(rinruntime-serial-portal-test
                   tests/serial_portal_contract_test.c)
    target_link_libraries(rinruntime-serial-portal-test PRIVATE RinRuntime::RinRuntime)
    add_test(NAME rinruntime-serial-portal COMMAND rinruntime-serial-portal-test)
    if(NOT WIN32)
        add_executable(rinruntime-audio-ring-test
                       tests/audio/rin_audio_service_client_ring_test.c)
        target_link_libraries(rinruntime-audio-ring-test PRIVATE RinRuntime::RinRuntime)
        add_test(NAME rinruntime-audio-ring COMMAND rinruntime-audio-ring-test)
    endif()
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
    if(RINRUNTIME_BUILD_GUI)
        foreach(gui_example IN ITEMS hello-window aquamarine-drawing resize input clipping)
            add_library(rinruntime-example-${gui_example} OBJECT
                        examples/${gui_example}/main.cpp)
            target_link_libraries(rinruntime-example-${gui_example}
                                  PRIVATE RinRuntime::RinRuntime)
            set_target_properties(rinruntime-example-${gui_example}
                                  PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
        endforeach()
        add_library(rinruntime-example-c-window OBJECT examples/c-window/main.c)
        target_link_libraries(rinruntime-example-c-window PRIVATE RinRuntime::RinRuntime)
    endif()
endif()
