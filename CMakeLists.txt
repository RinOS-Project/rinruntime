cmake_minimum_required(VERSION 3.16)
project(RinRuntime VERSION 1.0.0 LANGUAGES C CXX)

option(RINRUNTIME_BUILD_TESTS "Build RinRuntime host tests" ON)
option(RINRUNTIME_BUILD_SHARED "Build RinRuntime as a shared library" OFF)
option(RINRUNTIME_BUILD_EXAMPLES "Build RinRuntime host examples" ON)
option(RINRUNTIME_BUILD_RLL
       "Expose the signed RinCompiler/rld RinRuntime .rll target route" OFF)
set(RINRUNTIME_RLL_RCC "" CACHE FILEPATH
    "RinCompiler rcc executable used by the target .rll route")
set(RINRUNTIME_RLL_RLD "" CACHE FILEPATH
    "RinCompiler rld executable used by the target .rll route")
set(RINRUNTIME_RLL_RINSIGN "" CACHE FILEPATH
    "rinsign executable used by the target .rll route")
set(RINRUNTIME_RLL_SIGN_KEY "" CACHE FILEPATH
    "signing private key used by the target .rll route")
set(RINRUNTIME_RLL_PUBLIC_KEY "" CACHE FILEPATH
    "signing public key used by the target .rll route")
set(RINRUNTIME_RLL_TARGET "x86_64-unknown-rinos" CACHE STRING
    "RinCompiler target triple used by the target .rll route")
set(RINRUNTIME_RLL_SIGN_PROFILE "release" CACHE STRING
    "RinCompiler signing profile used by the target .rll route")
set(RINRUNTIME_RLL_SOURCES
    "src/portal.c;src/crash.c;src/rin_crash_record.c;src/rin_crash_summary.c;src/rin_crash_consent.c;src/backup_restore.c;src/known_folders.c;src/file_operation.c;src/safe_save.c;src/safe_save_posix.c;src/session_recovery.c;src/crash_service.c;src/frame_copy.c;src/serial_portal_protocol.c;src/unicode_grapheme.c;src/unicode.c;src/platform.c;src/service.c;src/clipboard.c;src/crash_service_client.c;src/file_portal.c;src/file_portal_startup.c;src/durable_file_portal.c;src/file_chooser_portal.c;src/file_operation_service_client.c;src/accessibility_service_client.c;src/audio/rin_audio_service_client.c;src/firewall/rule_engine.c;src/firewall/namespace_policy.c;src/firewall/profile.c;src/firewall/application.c;src/firewall/conntrack_query.c"
    CACHE STRING "semicolon-separated RinRuntime sources for the target .rll route")
set(RINRUNTIME_RLL_DEPENDENCIES "" CACHE STRING
    "semicolon-separated dependency .rll images for the target .rll route")
set(RINRUNTIME_GUI_DEFAULT ON)
if(WIN32)
    set(RINRUNTIME_GUI_DEFAULT OFF)
endif()
option(RINRUNTIME_BUILD_GUI
       "Build the public compositor-backed native window API" ${RINRUNTIME_GUI_DEFAULT})
find_package(Python3 3.10 COMPONENTS Interpreter REQUIRED)
set(RINRUNTIME_DEPENDENCY_NAMES
    rinpath libunicode libc libcxx libi18n rinresource rinjson rinos-sdk rinuri
    rinhttp rinwire aquamarine ringpu)
set(RINRUNTIME_DEPENDENCY_COMMAND
    ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/scripts/resolve_dependencies.py
    --source-root ${CMAKE_CURRENT_SOURCE_DIR}
    --build-root ${CMAKE_CURRENT_BINARY_DIR})
foreach(dependency_name IN LISTS RINRUNTIME_DEPENDENCY_NAMES)
    list(APPEND RINRUNTIME_DEPENDENCY_COMMAND --dependency ${dependency_name})
endforeach()
execute_process(
    COMMAND ${RINRUNTIME_DEPENDENCY_COMMAND}
    RESULT_VARIABLE RINRUNTIME_DEPENDENCY_RESULT
    OUTPUT_VARIABLE RINRUNTIME_DEPENDENCY_PATHS
    ERROR_VARIABLE RINRUNTIME_DEPENDENCY_ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT RINRUNTIME_DEPENDENCY_RESULT EQUAL 0)
    message(FATAL_ERROR "RinRuntime dependency resolution failed: ${RINRUNTIME_DEPENDENCY_ERROR}")
endif()
string(REPLACE "\r\n" "\n" RINRUNTIME_DEPENDENCY_PATHS "${RINRUNTIME_DEPENDENCY_PATHS}")
string(REPLACE "\n" ";" RINRUNTIME_DEPENDENCY_PATHS "${RINRUNTIME_DEPENDENCY_PATHS}")
list(LENGTH RINRUNTIME_DEPENDENCY_PATHS RINRUNTIME_RESOLVED_DEPENDENCY_COUNT)
list(LENGTH RINRUNTIME_DEPENDENCY_NAMES RINRUNTIME_EXPECTED_DEPENDENCY_COUNT)
if(NOT RINRUNTIME_RESOLVED_DEPENDENCY_COUNT EQUAL RINRUNTIME_EXPECTED_DEPENDENCY_COUNT)
    message(FATAL_ERROR "RinRuntime dependency resolver returned an incomplete path list")
endif()
list(GET RINRUNTIME_DEPENDENCY_PATHS 0 RINRUNTIME_RINPATH_ROOT)
list(GET RINRUNTIME_DEPENDENCY_PATHS 1 RINRUNTIME_LIBUNICODE_ROOT)
list(GET RINRUNTIME_DEPENDENCY_PATHS 2 RINRUNTIME_LIBC_ROOT)
list(GET RINRUNTIME_DEPENDENCY_PATHS 3 RINRUNTIME_LIBCXX_ROOT)
list(GET RINRUNTIME_DEPENDENCY_PATHS 4 RINRUNTIME_LIBI18N_ROOT)
list(GET RINRUNTIME_DEPENDENCY_PATHS 5 RINRUNTIME_RINRESOURCE_ROOT)
list(GET RINRUNTIME_DEPENDENCY_PATHS 6 RINRUNTIME_RINJSON_ROOT)
list(GET RINRUNTIME_DEPENDENCY_PATHS 7 RINRUNTIME_SDK_ROOT)
list(GET RINRUNTIME_DEPENDENCY_PATHS 8 RINRUNTIME_RINURI_ROOT)
list(GET RINRUNTIME_DEPENDENCY_PATHS 9 RINRUNTIME_RINHTTP_ROOT)
list(GET RINRUNTIME_DEPENDENCY_PATHS 10 RINRUNTIME_RINWIRE_ROOT)
list(GET RINRUNTIME_DEPENDENCY_PATHS 11 RINRUNTIME_AQUAMARINE_ROOT)
list(GET RINRUNTIME_DEPENDENCY_PATHS 12 RINRUNTIME_RINGPU_ROOT)
list(REMOVE_ITEM RINRUNTIME_RLL_SOURCES
     ../rinpath/path.c ../libunicode/core.c ../libunicode/locale_adapter.c
     ../libi18n/rin_i18n.c ../rinjson/src/json.cpp)
list(APPEND RINRUNTIME_RLL_SOURCES
     ${RINRUNTIME_RINPATH_ROOT}/path.c
     ${RINRUNTIME_LIBUNICODE_ROOT}/core.c
     ${RINRUNTIME_LIBUNICODE_ROOT}/locale_adapter.c
     ${RINRUNTIME_LIBI18N_ROOT}/rin_i18n.c
     ${RINRUNTIME_RINJSON_ROOT}/src/json.cpp)
set(RINRUNTIME_GENERATED_INCLUDE
    ${CMAKE_CURRENT_BINARY_DIR})
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
             ${CMAKE_CURRENT_SOURCE_DIR}/dependencies.lock.json
             ${CMAKE_CURRENT_SOURCE_DIR}/scripts/resolve_dependencies.py
             ${CMAKE_CURRENT_SOURCE_DIR}/scripts/prepare_i18n_header.py
             ${RINRUNTIME_LIBI18N_ROOT}/rin_i18n.h)
set(RINRUNTIME_LIBRARY_TYPE STATIC)
if(RINRUNTIME_BUILD_SHARED)
    set(RINRUNTIME_LIBRARY_TYPE SHARED)
endif()
set(RINRUNTIME_SOURCES
    src/portal.c
    src/crash.c
    src/rin_crash_record.c
    src/rin_crash_summary.c
    src/rin_crash_consent.c
    src/backup_restore.c
    src/known_folders.c
    src/file_operation.c
    src/safe_save.c
    src/safe_save_posix.c
    src/session_recovery.c
    src/crash_service.c
    src/frame_copy.c
    ${RINRUNTIME_RINPATH_ROOT}/path.c
    src/serial_portal_protocol.c
    src/file_chooser_portal.c
    src/unicode_grapheme.c
    src/unicode.c
    ${RINRUNTIME_LIBUNICODE_ROOT}/core.c
    ${RINRUNTIME_LIBUNICODE_ROOT}/locale_adapter.c
    ${RINRUNTIME_LIBI18N_ROOT}/rin_i18n.c
    ${RINRUNTIME_RINJSON_ROOT}/src/json.cpp
    src/firewall/rule_engine.c
    src/firewall/namespace_policy.c
    src/firewall/profile.c
    src/firewall/application.c
    src/firewall/conntrack_query.c)
# crashd is a RinOS local-socket service.  The host Windows build has no
# RinOS AF_UNIX/poll ABI; keep that transport out of the host library rather
# than substituting a success path.  RinOS/Unix builds include the real client.
if(NOT WIN32)
    list(APPEND RINRUNTIME_SOURCES src/backup_payload.c)
    list(APPEND RINRUNTIME_RLL_SOURCES src/backup_payload.c)
    list(APPEND RINRUNTIME_SOURCES src/platform.c)
    list(APPEND RINRUNTIME_SOURCES src/poll_wait.c)
    list(APPEND RINRUNTIME_SOURCES src/service.c)
    list(APPEND RINRUNTIME_SOURCES src/clipboard.c)
    list(APPEND RINRUNTIME_SOURCES src/rin_keyring_client.c)
    list(APPEND RINRUNTIME_RLL_SOURCES src/rin_keyring_client.c)
    list(APPEND RINRUNTIME_RLL_SOURCES src/poll_wait.c)
    list(APPEND RINRUNTIME_SOURCES src/crash_service_client.c)
    list(APPEND RINRUNTIME_SOURCES
        src/file_portal.c
        src/file_portal_startup.c
        src/durable_file_portal.c
        src/file_operation_service_client.c
        src/accessibility_service_client.c
        src/audio/rin_audio_service_client.c)
endif()
if(RINRUNTIME_BUILD_GUI)
    if(WIN32)
        message(FATAL_ERROR
                "RINRUNTIME_BUILD_GUI requires the RinOS Unix compositor transport")
    endif()
    list(APPEND RINRUNTIME_SOURCES
         ${RINRUNTIME_AQUAMARINE_ROOT}/aq_blend.c
         ${RINRUNTIME_AQUAMARINE_ROOT}/aq_color.c
         ${RINRUNTIME_AQUAMARINE_ROOT}/aq_draw.c
         ${RINRUNTIME_AQUAMARINE_ROOT}/aq_gradient.c
         ${RINRUNTIME_AQUAMARINE_ROOT}/aq_path.c
         ${RINRUNTIME_AQUAMARINE_ROOT}/aq_render3d.c
         ${RINRUNTIME_AQUAMARINE_ROOT}/aq_surface.c
         ${RINRUNTIME_AQUAMARINE_ROOT}/aq_text.c
         ${RINRUNTIME_AQUAMARINE_ROOT}/aq_transform.c
         src/compositor_gui.c
         src/compositor_gpu_bridge.c
         src/render.c
         src/media_render.c
         src/render_context.cpp)
endif()
add_library(RinRuntime ${RINRUNTIME_LIBRARY_TYPE}
    ${RINRUNTIME_SOURCES})
add_library(RinRuntime::RinRuntime ALIAS RinRuntime)
target_compile_features(RinRuntime PUBLIC c_std_11)
target_include_directories(RinRuntime PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${RINRUNTIME_GENERATED_INCLUDE}>
    $<BUILD_INTERFACE:${RINRUNTIME_SDK_ROOT}/include>
    $<BUILD_INTERFACE:${RINRUNTIME_LIBC_ROOT}/..>
    $<BUILD_INTERFACE:${RINRUNTIME_LIBCXX_ROOT}/..>
    $<BUILD_INTERFACE:${RINRUNTIME_RINJSON_ROOT}/include>
    $<BUILD_INTERFACE:${RINRUNTIME_RINPATH_ROOT}/include>
    $<BUILD_INTERFACE:${RINRUNTIME_RINRESOURCE_ROOT}/include>
    $<BUILD_INTERFACE:${RINRUNTIME_RINURI_ROOT}/include>
    $<BUILD_INTERFACE:${RINRUNTIME_RINHTTP_ROOT}/include>
    $<BUILD_INTERFACE:${RINRUNTIME_RINWIRE_ROOT}/include>
    $<BUILD_INTERFACE:${RINRUNTIME_RINGPU_ROOT}/include>
    $<BUILD_INTERFACE:${RINRUNTIME_AQUAMARINE_ROOT}/..>
    $<BUILD_INTERFACE:${RINRUNTIME_LIBUNICODE_ROOT}>
    $<INSTALL_INTERFACE:include>)
target_compile_features(RinRuntime PUBLIC cxx_std_17)
if(RINRUNTIME_BUILD_GUI)
    target_include_directories(RinRuntime PUBLIC
        $<BUILD_INTERFACE:${RINRUNTIME_AQUAMARINE_ROOT}>)
endif()
if(NOT MSVC)
    target_compile_options(RinRuntime PRIVATE -Wall -Wextra -Wpedantic)
endif()

include(GNUInstallDirs)
install(TARGETS RinRuntime EXPORT RinRuntimeTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/rinruntime/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/rinruntime
        PATTERN "crypt" EXCLUDE)
install(DIRECTORY include/rincompression/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/rincompression)
install(DIRECTORY ${RINRUNTIME_RINPATH_ROOT}/include/rinpath/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/rinpath)
install(DIRECTORY ${RINRUNTIME_RINJSON_ROOT}/include/rinjson/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/rinjson)
install(DIRECTORY ${RINRUNTIME_RINRESOURCE_ROOT}/include/rinresource/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/rinresource)
install(DIRECTORY ${RINRUNTIME_SDK_ROOT}/include/rin/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/rin)
install(DIRECTORY ${RINRUNTIME_RINURI_ROOT}/include/rinuri/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/rinuri)
install(DIRECTORY ${RINRUNTIME_RINHTTP_ROOT}/include/rinhttp/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/rinhttp)
install(DIRECTORY ${RINRUNTIME_RINWIRE_ROOT}/include/rinwire/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/rinwire)
install(DIRECTORY ${RINRUNTIME_RINGPU_ROOT}/include/ringpu/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ringpu)
install(DIRECTORY ${RINRUNTIME_LIBC_ROOT}/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/libc
        FILES_MATCHING
        PATTERN ".git" EXCLUDE
        PATTERN ".github" EXCLUDE
        PATTERN "*.h" PATTERN "*.hh" PATTERN "*.hpp"
                        PATTERN "*.hxx" PATTERN "*.inc")
install(DIRECTORY ${RINRUNTIME_LIBCXX_ROOT}/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/libcxx
        FILES_MATCHING
        PATTERN ".git" EXCLUDE
        PATTERN ".github" EXCLUDE
        PATTERN "*.h" PATTERN "*.hh" PATTERN "*.hpp"
                        PATTERN "*.hxx" PATTERN "*.inc")
install(FILES ${RINRUNTIME_AQUAMARINE_ROOT}/aq_types.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/aquamarine)
install(FILES ${RINRUNTIME_GENERATED_INCLUDE}/rin_i18n.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/rini18n/v1)
install(EXPORT RinRuntimeTargets
        FILE RinRuntimeTargets.cmake
        NAMESPACE RinRuntime::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/RinRuntime)
include(CMakePackageConfigHelpers)
configure_package_config_file(
    cmake/RinRuntimeConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/RinRuntimeConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/RinRuntime)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/RinRuntimeConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)
install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/RinRuntimeConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/RinRuntimeConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/RinRuntime)

configure_file(rinruntime.pc.in rinruntime.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/rinruntime.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

if(RINRUNTIME_BUILD_RLL)
    if(NOT RINRUNTIME_RLL_RCC OR NOT RINRUNTIME_RLL_RLD OR
       NOT RINRUNTIME_RLL_RINSIGN OR NOT RINRUNTIME_RLL_SIGN_KEY OR
       NOT RINRUNTIME_RLL_PUBLIC_KEY)
        message(FATAL_ERROR
                "RINRUNTIME_BUILD_RLL requires rcc, rld, rinsign, sign key, and public key")
    endif()
    if(NOT RINRUNTIME_RLL_SIGN_PROFILE STREQUAL "debug" AND
       NOT RINRUNTIME_RLL_SIGN_PROFILE STREQUAL "release")
        message(FATAL_ERROR
                "RINRUNTIME_RLL_SIGN_PROFILE must be debug or release")
    endif()
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    set(RINRUNTIME_RLL_SCRIPT
        ${CMAKE_CURRENT_SOURCE_DIR}/scripts/build_rll.py)
    set(RINRUNTIME_RLL_COMMAND
        ${Python3_EXECUTABLE} ${RINRUNTIME_RLL_SCRIPT}
        --rcc ${RINRUNTIME_RLL_RCC}
        --rld ${RINRUNTIME_RLL_RLD}
        --rinsign ${RINRUNTIME_RLL_RINSIGN}
        --sign-key ${RINRUNTIME_RLL_SIGN_KEY}
        --public-key ${RINRUNTIME_RLL_PUBLIC_KEY}
        --sign-profile ${RINRUNTIME_RLL_SIGN_PROFILE}
        --target ${RINRUNTIME_RLL_TARGET}
        --source-root ${CMAKE_CURRENT_SOURCE_DIR}
        --output ${CMAKE_CURRENT_BINARY_DIR}/RinRuntime.rll
        --include ${CMAKE_CURRENT_SOURCE_DIR}/include
        --include ${RINRUNTIME_GENERATED_INCLUDE}
        --include ${RINRUNTIME_RINPATH_ROOT}/include
        --include ${RINRUNTIME_SDK_ROOT}/include
        --include ${RINRUNTIME_LIBC_ROOT}/..
        --include ${RINRUNTIME_LIBCXX_ROOT}/..
        --include ${RINRUNTIME_LIBUNICODE_ROOT}
        --include ${RINRUNTIME_LIBI18N_ROOT}
        --include ${RINRUNTIME_RINRESOURCE_ROOT}/include
        --include ${RINRUNTIME_RINJSON_ROOT}/include)
    foreach(dependency_root IN LISTS RINRUNTIME_DEPENDENCY_PATHS)
        list(APPEND RINRUNTIME_RLL_COMMAND --dependency-root ${dependency_root})
    endforeach()
    foreach(rll_source IN LISTS RINRUNTIME_RLL_SOURCES)
        list(APPEND RINRUNTIME_RLL_COMMAND --source ${rll_source})
    endforeach()
    foreach(rll_dependency IN LISTS RINRUNTIME_RLL_DEPENDENCIES)
        list(APPEND RINRUNTIME_RLL_COMMAND --dependency ${rll_dependency})
    endforeach()
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/RinRuntime.rll
        COMMAND ${RINRUNTIME_RLL_COMMAND}
        DEPENDS ${RINRUNTIME_RLL_SCRIPT} ${RINRUNTIME_RLL_SOURCES}
                ${RINRUNTIME_RLL_DEPENDENCIES}
        VERBATIM)
    add_custom_target(rinruntime-rll
                      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/RinRuntime.rll)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/RinRuntime.rll
            DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()

if(RINRUNTIME_BUILD_TESTS)
    enable_testing()
    add_executable(rinruntime-frame-copy-test
                   tests/frame_copy_contract_test.c)
    target_link_libraries(rinruntime-frame-copy-test
                          PRIVATE RinRuntime::RinRuntime)
    add_test(NAME rinruntime-frame-copy COMMAND rinruntime-frame-copy-test)
    add_executable(rinruntime-domain-headers-test
                   tests/domain_headers_compile_test.cpp
                   tests/domain_header_core_test.cpp
                   tests/domain_header_ui_test.cpp
                   tests/domain_header_media_test.cpp
                   tests/domain_header_storage_test.cpp
                   tests/domain_header_system_test.cpp
                   tests/domain_header_legacy_test.cpp)
    target_link_libraries(rinruntime-domain-headers-test
                          PRIVATE RinRuntime::RinRuntime)
    set_target_properties(rinruntime-domain-headers-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-domain-headers
             COMMAND rinruntime-domain-headers-test)
    add_executable(rinruntime-model-test tests/runtime_model_test.cpp)
    target_link_libraries(rinruntime-model-test PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-model-test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(rinruntime-model-test PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-model COMMAND rinruntime-model-test)
    add_executable(rinruntime-abi-feature-manifest-test
                   tests/abi_feature_manifest_test.cpp)
    target_link_libraries(rinruntime-abi-feature-manifest-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-abi-feature-manifest-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(rinruntime-abi-feature-manifest-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-abi-feature-manifest
             COMMAND rinruntime-abi-feature-manifest-test)
    add_executable(rinruntime-application-metadata-test
                   tests/application_metadata_test.cpp)
    target_link_libraries(rinruntime-application-metadata-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-application-metadata-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(rinruntime-application-metadata-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-application-metadata
             COMMAND rinruntime-application-metadata-test)
    add_executable(rinruntime-package-metadata-test
                   tests/package_metadata_test.cpp)
    target_link_libraries(rinruntime-package-metadata-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-package-metadata-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(rinruntime-package-metadata-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-package-metadata
             COMMAND rinruntime-package-metadata-test)
    add_executable(rinruntime-service-configuration-test
                   tests/service_configuration_test.cpp)
    target_link_libraries(rinruntime-service-configuration-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-service-configuration-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(rinruntime-service-configuration-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-service-configuration
             COMMAND rinruntime-service-configuration-test)
    add_executable(rinruntime-update-metadata-test
                   tests/update_metadata_test.cpp)
    target_link_libraries(rinruntime-update-metadata-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-update-metadata-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(rinruntime-update-metadata-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-update-metadata
             COMMAND rinruntime-update-metadata-test)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    add_test(NAME rinruntime-public-io-retry-boundary
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/tests/public_io_retry_boundary_test.py)
    add_test(NAME rinruntime-crash-service-request-identity-boundary
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/tests/crash_service_request_identity_boundary_test.py)
    add_test(NAME rinruntime-file-operation-service-request-identity-boundary
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/tests/file_operation_service_request_identity_boundary_test.py)
    add_test(NAME rinruntime-accessibility-service-request-identity-boundary
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/tests/accessibility_service_request_identity_boundary_test.py)
    add_test(NAME rinruntime-compositor-request-identity-boundary
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/tests/compositor_request_identity_boundary_test.py)
    add_test(NAME rinruntime-audio-service-request-identity-boundary
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/tests/audio_service_request_identity_boundary_test.py)
    add_executable(rinruntime-portal-test tests/portal_contract_test.c)
    target_link_libraries(rinruntime-portal-test PRIVATE RinRuntime::RinRuntime)
    add_test(NAME rinruntime-portal COMMAND rinruntime-portal-test)
    add_executable(rinruntime-policy-test tests/policy_contract_test.c)
    target_link_libraries(rinruntime-policy-test PRIVATE RinRuntime::RinRuntime)
    add_test(NAME rinruntime-policy COMMAND rinruntime-policy-test)
    add_executable(rinruntime-application-data-policy-test
                   tests/application_data_policy_test.cpp)
    target_link_libraries(rinruntime-application-data-policy-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-application-data-policy-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(rinruntime-application-data-policy-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-application-data-policy
             COMMAND rinruntime-application-data-policy-test)
    add_executable(rinruntime-crash-service-test tests/crash_service_contract_test.c)
    target_link_libraries(rinruntime-crash-service-test PRIVATE RinRuntime::RinRuntime)
    add_test(NAME rinruntime-crash-service COMMAND rinruntime-crash-service-test)
    add_executable(rinruntime-file-portal-abi-test tests/file_portal_abi_compile_test.c)
    target_link_libraries(rinruntime-file-portal-abi-test PRIVATE RinRuntime::RinRuntime)
    add_test(NAME rinruntime-file-portal-abi COMMAND rinruntime-file-portal-abi-test)
    add_executable(rinruntime-file-chooser-identity-test
                   tests/file_chooser_identity_contract_test.c)
    target_link_libraries(rinruntime-file-chooser-identity-test
                          PRIVATE RinRuntime::RinRuntime)
    add_test(NAME rinruntime-file-chooser-identity
             COMMAND rinruntime-file-chooser-identity-test)
    if(RINRUNTIME_BUILD_GUI)
        add_executable(rinruntime-window-abi-test tests/window_abi_compile_test.c)
        target_link_libraries(rinruntime-window-abi-test PRIVATE RinRuntime::RinRuntime)
        add_test(NAME rinruntime-window-abi COMMAND rinruntime-window-abi-test)
        add_executable(rinruntime-window-callback-test
                       tests/window_callback_contract_test.cpp)
        target_include_directories(rinruntime-window-callback-test
                                   PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
                                           ${RINRUNTIME_SDK_ROOT}/include
                                           ${RINRUNTIME_AQUAMARINE_ROOT})
        set_target_properties(rinruntime-window-callback-test
                              PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
        add_test(NAME rinruntime-window-callback
                 COMMAND rinruntime-window-callback-test)
        add_library(rinruntime-render-context-abi-test OBJECT
                    tests/render_context_abi_compile_test.cpp)
        target_link_libraries(rinruntime-render-context-abi-test
                              PRIVATE RinRuntime::RinRuntime)
        set_target_properties(rinruntime-render-context-abi-test
                              PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
        add_executable(rinruntime-render-context-test
                       tests/render_context_contract_test.cpp)
        target_link_libraries(rinruntime-render-context-test
                              PRIVATE RinRuntime::RinRuntime)
        target_include_directories(rinruntime-render-context-test
                                   PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
        set_target_properties(rinruntime-render-context-test
                              PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
        add_test(NAME rinruntime-render-context
                 COMMAND rinruntime-render-context-test)
    endif()
    add_executable(rinruntime-accessibility-client-abi-test
                   tests/accessibility_client_abi_compile_test.c)
    target_link_libraries(rinruntime-accessibility-client-abi-test PRIVATE RinRuntime::RinRuntime)
    add_test(NAME rinruntime-accessibility-client-abi
             COMMAND rinruntime-accessibility-client-abi-test)
    add_executable(rinruntime-cursor-test tests/cursor_contract_test.c)
    target_link_libraries(rinruntime-cursor-test PRIVATE RinRuntime::RinRuntime)
    add_test(NAME rinruntime-cursor COMMAND rinruntime-cursor-test)
    if(NOT WIN32)
        add_executable(rinruntime-poll-wait-test
                       tests/poll_wait_contract_test.c src/poll_wait.c)
        target_include_directories(rinruntime-poll-wait-test
                                   PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
                                           ${RINRUNTIME_LIBC_ROOT}/..)
        add_test(NAME rinruntime-poll-wait
                 COMMAND rinruntime-poll-wait-test)
        add_executable(rinruntime-event-loop-poll-test
                       tests/event_loop_poll_contract_test.cpp)
        target_link_libraries(rinruntime-event-loop-poll-test
                              PRIVATE RinRuntime::RinRuntime)
        target_include_directories(rinruntime-event-loop-poll-test
                                   PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
        set_target_properties(rinruntime-event-loop-poll-test
                              PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
        add_test(NAME rinruntime-event-loop-poll
                 COMMAND rinruntime-event-loop-poll-test)
        add_executable(rinruntime-backup-payload-test
                       tests/backup_payload_contract_test.c
                       src/backup_payload.c)
        target_include_directories(rinruntime-backup-payload-test
                                   PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
                                           ${RINRUNTIME_SDK_ROOT}/include)
        add_test(NAME rinruntime-backup-payload
                 COMMAND rinruntime-backup-payload-test)
    endif()
    add_executable(rinruntime-serial-portal-test
                   tests/serial_portal_contract_test.c)
    target_link_libraries(rinruntime-serial-portal-test PRIVATE RinRuntime::RinRuntime)
    add_test(NAME rinruntime-serial-portal COMMAND rinruntime-serial-portal-test)
    if(NOT WIN32)
        add_executable(rinruntime-service-abi-test
                       tests/service_abi_compile_test.c)
        target_link_libraries(rinruntime-service-abi-test PRIVATE RinRuntime::RinRuntime)
        add_test(NAME rinruntime-service-abi COMMAND rinruntime-service-abi-test)
        add_executable(rinruntime-audio-ring-test
                       tests/audio/rin_audio_service_client_ring_test.c)
        target_link_libraries(rinruntime-audio-ring-test PRIVATE RinRuntime::RinRuntime)
    add_test(NAME rinruntime-audio-ring COMMAND rinruntime-audio-ring-test)
    endif()
    add_executable(rinruntime-download-range-test
                   tests/download_range_transport_contract_test.cpp)
    target_link_libraries(rinruntime-download-range-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-download-range-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(rinruntime-download-range-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-download-range
             COMMAND rinruntime-download-range-test)
    add_executable(rinruntime-public-common-adapters-test
                   tests/public_common_adapters_contract_test.cpp)
    target_link_libraries(rinruntime-public-common-adapters-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-public-common-adapters-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(rinruntime-public-common-adapters-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-public-common-adapters
             COMMAND rinruntime-public-common-adapters-test)
    add_executable(rinruntime-drag-drop-test
                   tests/drag_drop_contract_test.cpp)
    target_link_libraries(rinruntime-drag-drop-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-drag-drop-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(rinruntime-drag-drop-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-drag-drop
             COMMAND rinruntime-drag-drop-test)
    add_executable(rinruntime-abi-policy-test tests/abi_policy_test.cpp)
    target_link_libraries(rinruntime-abi-policy-test PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-abi-policy-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(rinruntime-abi-policy-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-abi-policy COMMAND rinruntime-abi-policy-test)
    add_executable(rinruntime-device-manifest-test
                   tests/device_manifest_test.cpp)
    target_link_libraries(rinruntime-device-manifest-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-device-manifest-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(rinruntime-device-manifest-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-device-manifest
             COMMAND rinruntime-device-manifest-test)
    add_executable(rinruntime-device-manifest-json-test
                   tests/device_manifest_json_test.cpp)
    target_link_libraries(rinruntime-device-manifest-json-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-device-manifest-json-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
                                       ${RINRUNTIME_RINJSON_ROOT}/include)
    set_target_properties(rinruntime-device-manifest-json-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-device-manifest-json
             COMMAND rinruntime-device-manifest-json-test)
    add_executable(rinruntime-event-loop-rin-test
                   tests/event_loop_rin_contract_test.cpp
                   ${RINRUNTIME_SDK_ROOT}/src/rinsdk_v1.c)
    target_link_libraries(rinruntime-event-loop-rin-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-event-loop-rin-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
                                       ${RINRUNTIME_SDK_ROOT}/include)
    set_target_properties(rinruntime-event-loop-rin-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-event-loop-rin
             COMMAND rinruntime-event-loop-rin-test)
    add_executable(rinruntime-clipboard-test tests/clipboard_contract_test.c)
    target_link_libraries(rinruntime-clipboard-test PRIVATE RinRuntime::RinRuntime)
    add_test(NAME rinruntime-clipboard COMMAND rinruntime-clipboard-test)
    add_executable(rinruntime-update-metadata-json-test
                   tests/update_metadata_json_test.cpp)
    target_link_libraries(rinruntime-update-metadata-json-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-update-metadata-json-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
                                       ${RINRUNTIME_RINJSON_ROOT}/include)
    set_target_properties(rinruntime-update-metadata-json-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-update-metadata-json
             COMMAND rinruntime-update-metadata-json-test)
    add_executable(rinruntime-package-metadata-json-test
                   tests/package_metadata_json_test.cpp)
    target_link_libraries(rinruntime-package-metadata-json-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-package-metadata-json-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
                                       ${RINRUNTIME_RINJSON_ROOT}/include)
    set_target_properties(rinruntime-package-metadata-json-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-package-metadata-json
             COMMAND rinruntime-package-metadata-json-test)
    add_executable(rinruntime-package-metadata-catalog-json-test
                   tests/package_metadata_catalog_json_test.cpp)
    target_link_libraries(rinruntime-package-metadata-catalog-json-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-package-metadata-catalog-json-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
                                       ${RINRUNTIME_RINJSON_ROOT}/include)
    set_target_properties(rinruntime-package-metadata-catalog-json-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-package-metadata-catalog-json
             COMMAND rinruntime-package-metadata-catalog-json-test)
    add_executable(rinruntime-application-metadata-json-test
                   tests/application_metadata_json_test.cpp)
    target_link_libraries(rinruntime-application-metadata-json-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-application-metadata-json-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
                                       ${RINRUNTIME_RINJSON_ROOT}/include)
    set_target_properties(rinruntime-application-metadata-json-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-application-metadata-json
             COMMAND rinruntime-application-metadata-json-test)
    add_executable(rinruntime-application-metadata-catalog-json-test
                   tests/application_metadata_catalog_json_test.cpp)
    target_link_libraries(rinruntime-application-metadata-catalog-json-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-application-metadata-catalog-json-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
                                       ${RINRUNTIME_RINJSON_ROOT}/include)
    set_target_properties(rinruntime-application-metadata-catalog-json-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-application-metadata-catalog-json
             COMMAND rinruntime-application-metadata-catalog-json-test)
    add_executable(rinruntime-update-metadata-catalog-json-test
                   tests/update_metadata_catalog_json_test.cpp)
    target_link_libraries(rinruntime-update-metadata-catalog-json-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-update-metadata-catalog-json-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
                                       ${RINRUNTIME_RINJSON_ROOT}/include)
    set_target_properties(rinruntime-update-metadata-catalog-json-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-update-metadata-catalog-json
             COMMAND rinruntime-update-metadata-catalog-json-test)
    add_executable(rinruntime-theme-profile-test
                   tests/theme_profile_test.cpp)
    target_link_libraries(rinruntime-theme-profile-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-theme-profile-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(rinruntime-theme-profile-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-theme-profile
             COMMAND rinruntime-theme-profile-test)
    add_executable(rinruntime-theme-profile-json-test
                   tests/theme_profile_json_test.cpp)
    target_link_libraries(rinruntime-theme-profile-json-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-theme-profile-json-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
                                       ${RINRUNTIME_RINJSON_ROOT}/include)
    set_target_properties(rinruntime-theme-profile-json-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-theme-profile-json
             COMMAND rinruntime-theme-profile-json-test)
    add_executable(rinruntime-archive-codec-test
                   tests/archive_codec_contract_test.cpp)
    target_link_libraries(rinruntime-archive-codec-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-archive-codec-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(rinruntime-archive-codec-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-archive-codec
             COMMAND rinruntime-archive-codec-test)
    add_executable(rinruntime-archive-container-test
                   tests/archive_container_contract_test.cpp)
    target_link_libraries(rinruntime-archive-container-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-archive-container-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(rinruntime-archive-container-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-archive-container
             COMMAND rinruntime-archive-container-test)
    add_executable(rinruntime-backup-archive-test
                   tests/backup_archive_contract_test.cpp)
    target_link_libraries(rinruntime-backup-archive-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-backup-archive-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(rinruntime-backup-archive-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-backup-archive
             COMMAND rinruntime-backup-archive-test)
    add_executable(rinruntime-tls-client-certificate-test
                   tests/tls_client_certificate_contract_test.cpp)
    target_link_libraries(rinruntime-tls-client-certificate-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-tls-client-certificate-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(rinruntime-tls-client-certificate-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-tls-client-certificate
             COMMAND rinruntime-tls-client-certificate-test)
    add_executable(rincompression-deflate-test
                   tests/deflate_contract_test.cpp)
    target_link_libraries(rincompression-deflate-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rincompression-deflate-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(rincompression-deflate-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rincompression-deflate
             COMMAND rincompression-deflate-test)
    add_executable(rincompression-lz4-test
                   tests/lz4_contract_test.cpp)
    target_link_libraries(rincompression-lz4-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rincompression-lz4-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(rincompression-lz4-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rincompression-lz4
             COMMAND rincompression-lz4-test)
    add_executable(rincompression-zstd-test
                   tests/zstd_contract_test.cpp)
    target_link_libraries(rincompression-zstd-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rincompression-zstd-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(rincompression-zstd-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rincompression-zstd
             COMMAND rincompression-zstd-test)
    add_executable(rinruntime-timezone-test
                   tests/timezone_contract_test.cpp)
    target_link_libraries(rinruntime-timezone-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-timezone-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(rinruntime-timezone-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-timezone
             COMMAND rinruntime-timezone-test)
    add_executable(rinruntime-unicode-test
                   tests/unicode_contract_test.cpp)
    target_link_libraries(rinruntime-unicode-test
                          PRIVATE RinRuntime::RinRuntime)
    target_include_directories(rinruntime-unicode-test
                               PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_target_properties(rinruntime-unicode-test PROPERTIES
                          CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
    add_test(NAME rinruntime-unicode
             COMMAND rinruntime-unicode-test)
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
