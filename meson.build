project('RinRuntime', ['c', 'cpp'], version: '1.0.0',
        default_options: ['cpp_std=c++17', 'warning_level=3'])

python = import('python').find_installation('python3', required: true)
if not python.language_version().version_compare('>=3.10')
  error('RinRuntime dependency tools require Python 3.10 or newer')
endif
fs = import('fs')
dependency_names = ['rinpath', 'libunicode', 'libc', 'libcxx', 'libi18n',
                    'rinresource', 'rinjson', 'rinos-sdk', 'rinuri', 'rinhttp',
                    'rinwire', 'aquamarine', 'ringpu']
dependency_command = [python, files('scripts/resolve_dependencies.py'),
                      '--source-root', meson.current_source_dir(),
                      '--build-root', meson.current_build_dir(),
                      '--skip-i18n-header']
foreach dependency_name : dependency_names
  dependency_command += ['--dependency', dependency_name]
endforeach
dependency_result = run_command(dependency_command, check: false)
if dependency_result.returncode() != 0
  error('RinRuntime dependency resolution failed: ' +
        dependency_result.stderr().strip())
endif
dependency_paths = []
foreach dependency_path : dependency_result.stdout().strip().split('\n')
  dependency_paths += [dependency_path.strip()]
endforeach
if dependency_paths.length() != dependency_names.length()
  error('RinRuntime dependency resolver returned an incomplete path list')
endif
rinpath_root = dependency_paths[0]
libunicode_root = dependency_paths[1]
libc_root = dependency_paths[2]
libcxx_root = dependency_paths[3]
libi18n_root = dependency_paths[4]
rinresource_root = dependency_paths[5]
rinjson_root = dependency_paths[6]
sdk_root = dependency_paths[7]
rinuri_root = dependency_paths[8]
rinhttp_root = dependency_paths[9]
rinwire_root = dependency_paths[10]
aquamarine_root = dependency_paths[11]
ringpu_root = dependency_paths[12]
generated_include = meson.current_build_dir()
inc = [include_directories('include', '.',
                          join_paths(sdk_root, 'include'),
                          join_paths(rinjson_root, 'include'),
                          join_paths(rinpath_root, 'include'),
                          join_paths(rinresource_root, 'include'),
                          join_paths(rinuri_root, 'include'),
                          join_paths(rinhttp_root, 'include'),
                          join_paths(rinwire_root, 'include'),
                          join_paths(ringpu_root, 'include'),
                          join_paths(libc_root, '..'),
                          join_paths(libcxx_root, '..'),
                          join_paths(aquamarine_root, '..'),
                          libunicode_root, libi18n_root)]
if host_machine.system() != 'windows'
  inc += [include_directories(aquamarine_root)]
endif
runtime_sources = files('src/portal.c', 'src/crash.c',
                        'src/rin_crash_record.c',
                        'src/rin_crash_summary.c', 'src/rin_crash_consent.c',
                        'src/backup_restore.c',
                        'src/known_folders.c', 'src/file_operation.c',
                        'src/safe_save.c', 'src/safe_save_posix.c',
                        'src/session_recovery.c', 'src/crash_service.c',
                        'src/frame_copy.c', 'src/rin_resource.c',
                        'src/performance_trace.c',
                        'src/rin_capture_policy.c',
                        'src/rin_desktop_model.c',
                        'src/rin_theme_palette.c',
                        'src/rin_dhcpv6_client.c',
                        'src/rin_dhcpv6_reconfigure.c',
                        'src/rin_dhcpv6_transport.c',
                        'src/rin_dhcpv4_wire.c',
                        'src/rin_midi_policy.c',
                        'src/rin_icc_display_profile_v1.c',
                        'src/rin_icc_display_transform_v1.c',
                        'src/rin_icc_lut_profile_v1.c',
                        'src/rin_icc_lut_transform_v1.c',
                        'src/rin_icc_connector_profile_store_v1.c',
                        'src/rin_certificate_revocation.c',
                        'src/rin_certificate_revocation_cache.c',
                        'src/rin_web_serial_portal.c',
                        join_paths(rinpath_root, 'path.c'),
                        'src/serial_portal_protocol.c',
                        'src/file_chooser_portal.c',
                        'src/firewall/rule_engine.c',
                        'src/firewall/namespace_policy.c',
                        'src/firewall/profile.c',
                        'src/firewall/application.c', 'src/unicode_grapheme.c',
                        'src/unicode.c',
                        join_paths(libunicode_root, 'core.c'),
                        join_paths(libunicode_root, 'locale_adapter.c'),
                        join_paths(libi18n_root, 'rin_i18n.c'),
                        join_paths(rinjson_root, 'src/json.cpp'),
                        'src/firewall/conntrack_query.c')
i18n_header = custom_target(
  'rinruntime-i18n-v1-header',
  input: files(join_paths(libi18n_root, 'rin_i18n.h')),
  output: 'rin_i18n.h',
  command: [python, files('scripts/prepare_i18n_header.py'), '@INPUT@', '@OUTPUT@'],
  build_by_default: true,
  install: true,
  install_dir: join_paths(get_option('includedir'), 'rini18n', 'v1'),
)
runtime_sources += [i18n_header]
if host_machine.system() != 'windows'
  runtime_sources += files('src/backup_payload.c')
  runtime_sources += files('src/rin_installer_runtime.c')
  runtime_sources += files('src/poll_wait.c')
  runtime_sources += files('src/platform.c')
  runtime_sources += files('src/service.c')
  runtime_sources += files('src/clipboard.c')
  runtime_sources += files('src/crash_service_client.c',
                           'src/file_portal.c',
                           'src/file_portal_startup.c',
                           'src/durable_file_portal.c',
                           'src/pty.c',
                           'src/file_operation_service_client.c',
                           'src/accessibility_service_client.c',
                           'src/audio/rin_audio_service_client.c',
                           'src/rin_keyring_client.c')
  aq_sources = files(join_paths(aquamarine_root, 'aq_blend.c'),
                     join_paths(aquamarine_root, 'aq_color.c'),
                     join_paths(aquamarine_root, 'aq_draw.c'),
                     join_paths(aquamarine_root, 'aq_gradient.c'),
                     join_paths(aquamarine_root, 'aq_path.c'),
                     join_paths(aquamarine_root, 'aq_render3d.c'),
                     join_paths(aquamarine_root, 'aq_surface.c'),
                     join_paths(aquamarine_root, 'aq_text.c'),
                     join_paths(aquamarine_root, 'aq_transform.c'))
  runtime_sources += aq_sources
  runtime_sources += files('src/compositor_gui.c',
                           'src/compositor_gpu_bridge.c',
                           'src/sdk_gui_v1.c', 'src/render.c',
                           'src/media_render.c', 'src/render_context.cpp')
endif
runtime_deps = []
runtime_link_args = []
test_override_options = []
if host_machine.system() != 'windows'
  # The public runtime carries its real RinOS syscall adapters.  Service
  # implementations remain outside this library.
  runtime_link_args += ['-Wl,--allow-shlib-undefined']
  test_override_options += ['b_lundef=false']
endif
runtime = library('RinRuntime', runtime_sources, include_directories: inc,
                  dependencies: runtime_deps,
                  link_args: runtime_link_args,
                  override_options: ['b_lundef=false'],
                  install: true, version: '1.0.0')
runtime_dep = declare_dependency(link_with: runtime, include_directories: inc,
                                 dependencies: runtime_deps,
                                 link_args: runtime_link_args)
rinruntime_header_excludes = ['pe_loader.h', 'rin_cursor.h']
if host_machine.system() == 'windows'
  # These headers expose POSIX-only implementations omitted from the Windows
  # library target. Do not publish declarations that installed consumers
  # cannot link against.
  rinruntime_header_excludes += ['rin_installer_runtime.h', 'pty.h']
endif
install_subdir('include/rinruntime', install_dir: get_option('includedir'),
               exclude_directories: ['crypt'],
               exclude_files: rinruntime_header_excludes)
install_subdir('include/rincompression', install_dir: get_option('includedir'))
license_install_dir = join_paths(get_option('datadir'), 'licenses', 'RinRuntime')
install_data('LICENSE', install_dir: license_install_dir,
             rename: 'RinRuntime-MIT.txt')
install_data(join_paths(sdk_root, 'LICENSE'), install_dir: license_install_dir,
             rename: 'RinOS-SDK-MIT.txt')
install_data(join_paths(sdk_root, 'LICENSES', 'GPL-2.0-or-later.txt'),
             install_dir: license_install_dir,
             rename: 'GPL-2.0-or-later.txt')
install_data('licenses/public-api-license-manifest.json',
             install_dir: license_install_dir)
install_data('licenses/README.md', install_dir: license_install_dir,
             rename: 'LICENSE-README.md')
install_headers(files(join_paths(aquamarine_root, 'aq_types.h')),
                subdir: 'aquamarine')
public_header_command = [python, files('scripts/resolve_dependencies.py'),
                         '--list-public-headers']
public_header_roots = [
  [libc_root, 'libc'],
  [libcxx_root, 'libcxx'],
  [join_paths(rinpath_root, 'include/rinpath'), 'rinpath'],
  [join_paths(rinjson_root, 'include/rinjson'), 'rinjson'],
  [join_paths(rinresource_root, 'include/rinresource'), 'rinresource'],
  [join_paths(sdk_root, 'include/rin'), 'rin'],
  [join_paths(rinuri_root, 'include/rinuri'), 'rinuri'],
  [join_paths(rinhttp_root, 'include/rinhttp'), 'rinhttp'],
  [join_paths(rinwire_root, 'include/rinwire'), 'rinwire'],
  [join_paths(ringpu_root, 'include/ringpu'), 'ringpu'],
]
foreach header_root : public_header_roots
  public_header_command += ['--header-root', header_root[0] + '=' + header_root[1]]
endforeach
public_header_result = run_command(public_header_command, check: false)
if public_header_result.returncode() != 0
  error('RinRuntime public header enumeration failed: ' +
        public_header_result.stderr().strip())
endif
foreach header_entry : public_header_result.stdout().strip().split('\n')
  header_fields = header_entry.strip().split('|')
  if header_fields.length() != 2
    error('RinRuntime public header map contains a malformed entry')
  endif
  install_headers(files(header_fields[0]),
                  install_dir: join_paths(get_option('includedir'),
                                          header_fields[1]))
endforeach
pkgconfig = import('pkgconfig')
pkgconfig.generate(runtime,
  name: 'RinRuntime',
  filebase: 'rinruntime',
  description: 'RinOS public application models and service-client contracts',
  libraries: runtime_link_args,
  version: meson.project_version())

if get_option('build_rll')
  if get_option('rll_sign_key') == '' or get_option('rll_public_key') == ''
    error('build_rll requires rll_sign_key and rll_public_key')
  endif
  configured_rll_sources = get_option('rll_sources')
  if configured_rll_sources.length() == 0
    error('build_rll requires at least one rll_sources entry')
  endif
  rll_sources = []
  foreach rll_source : configured_rll_sources
    if rll_source == '../rinpath/path.c'
      rll_sources += [join_paths(rinpath_root, 'path.c')]
    elif rll_source == '../libunicode/core.c'
      rll_sources += [join_paths(libunicode_root, 'core.c')]
    elif rll_source == '../libunicode/locale_adapter.c'
      rll_sources += [join_paths(libunicode_root, 'locale_adapter.c')]
    elif rll_source == '../libi18n/rin_i18n.c'
      rll_sources += [join_paths(libi18n_root, 'rin_i18n.c')]
    elif rll_source == '../rinjson/src/json.cpp'
      rll_sources += [join_paths(rinjson_root, 'src/json.cpp')]
    elif rll_source == '../aquamarine/aq_blend.c'
      rll_sources += [join_paths(aquamarine_root, 'aq_blend.c')]
    elif rll_source == '../aquamarine/aq_color.c'
      rll_sources += [join_paths(aquamarine_root, 'aq_color.c')]
    elif rll_source == '../aquamarine/aq_draw.c'
      rll_sources += [join_paths(aquamarine_root, 'aq_draw.c')]
    elif rll_source == '../aquamarine/aq_surface.c'
      rll_sources += [join_paths(aquamarine_root, 'aq_surface.c')]
    elif rll_source == '../aquamarine/aq_text.c'
      rll_sources += [join_paths(aquamarine_root, 'aq_text.c')]
    else
      rll_sources += [rll_source]
    endif
  endforeach
  foreach dependency_source : [join_paths(rinpath_root, 'path.c'),
                               join_paths(libunicode_root, 'core.c'),
                               join_paths(libunicode_root, 'locale_adapter.c'),
                               join_paths(libi18n_root, 'rin_i18n.c'),
                               join_paths(rinjson_root, 'src/json.cpp')]
    if dependency_source not in rll_sources
      rll_sources += [dependency_source]
    endif
  endforeach
  foreach rll_source : rll_sources
    rll_source_path = rll_source
    if not fs.is_absolute(rll_source_path)
      rll_source_path = join_paths(meson.current_source_dir(), rll_source)
    endif
    if not fs.is_file(rll_source_path)
      error('build_rll source does not exist: ' + rll_source)
    endif
  endforeach
  rll_source_files = []
  foreach rll_source : rll_sources
    rll_source_files += files(rll_source)
  endforeach
  rll_command = [
    python, files('scripts/build_rll.py'),
    '--rcc', find_program(get_option('rll_rcc'), required: true).full_path(),
    '--rld', find_program(get_option('rll_rld'), required: true).full_path(),
    '--rinsign', find_program(get_option('rll_rinsign'), required: true).full_path(),
    '--sign-key', get_option('rll_sign_key'),
    '--public-key', get_option('rll_public_key'),
    '--sign-profile', get_option('rll_sign_profile'),
    '--target', get_option('rll_target'),
    '--source-root', meson.current_source_dir(),
    '--output', '@OUTPUT@',
    '--include', join_paths(meson.current_source_dir(), 'include'),
    '--include', generated_include,
    '--include', join_paths(rinpath_root, 'include'),
    '--include', join_paths(sdk_root, 'include'),
    '--include', join_paths(libc_root, '..'),
    '--include', join_paths(libcxx_root, '..'),
    '--include', libunicode_root,
    '--include', libi18n_root,
    '--include', join_paths(rinresource_root, 'include'),
    '--include', join_paths(rinjson_root, 'include'),
    '--include', join_paths(aquamarine_root, '..'),
  ]
  foreach dependency_root : dependency_paths
    rll_command += ['--dependency-root', dependency_root]
  endforeach
  foreach rll_source : rll_sources
    rll_command += ['--source', rll_source]
  endforeach
  foreach rll_dependency : get_option('rll_dependencies')
    rll_command += ['--dependency', rll_dependency]
  endforeach
  rinruntime_rll = custom_target(
    'RinRuntime-rll',
    input: rll_source_files + [i18n_header],
    output: 'RinRuntime.rll',
    command: rll_command,
    build_by_default: false,
  )
  alias_target('rll', [rinruntime_rll])
  install_data(rinruntime_rll, install_dir: get_option('libdir'))
endif

if get_option('buildtype') != 'plain'
  test('rinruntime-frame-copy', executable('rinruntime-frame-copy-test',
        'tests/frame_copy_contract_test.c', dependencies: runtime_dep,
        override_options: test_override_options))
  test('rinruntime-domain-headers', executable('rinruntime-domain-headers-test',
        'tests/domain_headers_compile_test.cpp',
        'tests/domain_header_core_test.cpp', 'tests/domain_header_ui_test.cpp',
        'tests/domain_header_media_test.cpp',
        'tests/domain_header_storage_test.cpp',
        'tests/domain_header_system_test.cpp',
        'tests/domain_header_legacy_test.cpp', dependencies: runtime_dep,
        override_options: test_override_options, cpp_args: ['-std=c++17']))
  test('rinruntime-model', executable('rinruntime-model-test',
        'tests/runtime_model_test.cpp', dependencies: runtime_dep,
        override_options: test_override_options))
  test('rinruntime-abi-feature-manifest', executable('rinruntime-abi-feature-manifest-test',
        'tests/abi_feature_manifest_test.cpp', dependencies: runtime_dep,
        override_options: test_override_options, cpp_args: ['-std=c++17']))
  test('rinruntime-application-metadata', executable('rinruntime-application-metadata-test',
        'tests/application_metadata_test.cpp', dependencies: runtime_dep,
        override_options: test_override_options, cpp_args: ['-std=c++17']))
  test('rinruntime-package-metadata', executable('rinruntime-package-metadata-test',
        'tests/package_metadata_test.cpp', dependencies: runtime_dep,
        override_options: test_override_options, cpp_args: ['-std=c++17']))
  test('rinruntime-service-configuration', executable('rinruntime-service-configuration-test',
        'tests/service_configuration_test.cpp', dependencies: runtime_dep,
        override_options: test_override_options, cpp_args: ['-std=c++17']))
  test('rinruntime-update-metadata', executable('rinruntime-update-metadata-test',
        'tests/update_metadata_test.cpp', dependencies: runtime_dep,
        override_options: test_override_options, cpp_args: ['-std=c++17']))
  test('rinruntime-public-io-retry-boundary', python,
        args: [files('tests/public_io_retry_boundary_test.py')])
  test('rinruntime-crash-service-request-identity-boundary', python,
        args: [files('tests/crash_service_request_identity_boundary_test.py')])
  test('rinruntime-file-operation-service-request-identity-boundary', python,
        args: [files('tests/file_operation_service_request_identity_boundary_test.py')])
  test('rinruntime-accessibility-service-request-identity-boundary', python,
        args: [files('tests/accessibility_service_request_identity_boundary_test.py')])
  test('rinruntime-compositor-request-identity-boundary', python,
        args: [files('tests/compositor_request_identity_boundary_test.py')])
  test('rinruntime-audio-service-request-identity-boundary', python,
        args: [files('tests/audio_service_request_identity_boundary_test.py')])
  test('rinruntime-portal', executable('rinruntime-portal-test',
        'tests/portal_contract_test.c', dependencies: runtime_dep,
        override_options: test_override_options))
  test('rinruntime-file-chooser-identity', executable(
        'rinruntime-file-chooser-identity-test',
        'tests/file_chooser_identity_contract_test.c', dependencies: runtime_dep,
        override_options: test_override_options))
  test('rinruntime-policy', executable('rinruntime-policy-test',
        'tests/policy_contract_test.c', dependencies: runtime_dep,
        override_options: test_override_options))
  test('rinruntime-application-data-policy', executable('rinruntime-application-data-policy-test',
        'tests/application_data_policy_test.cpp', dependencies: runtime_dep,
        override_options: test_override_options, cpp_args: ['-std=c++17']))
  test('rinruntime-serial-portal', executable('rinruntime-serial-portal-test',
        'tests/serial_portal_contract_test.c', dependencies: runtime_dep,
        override_options: test_override_options))
  if host_machine.system() != 'windows'
    test('rinruntime-window-abi', executable('rinruntime-window-abi-test',
          'tests/window_abi_compile_test.c', dependencies: runtime_dep,
          override_options: test_override_options))
    static_library('rinruntime-render-context-abi-test',
          'tests/render_context_abi_compile_test.cpp', dependencies: runtime_dep,
          cpp_args: ['-std=c++17'])
  endif
  if host_machine.system() != 'windows'
    test('rinruntime-poll-wait', executable('rinruntime-poll-wait-test',
          'tests/poll_wait_contract_test.c', 'src/poll_wait.c',
          include_directories: inc,
          override_options: test_override_options))
    test('rinruntime-backup-payload', executable('rinruntime-backup-payload-test',
          'tests/backup_payload_contract_test.c', 'src/backup_payload.c',
          include_directories: inc,
          override_options: test_override_options))
    test('rinruntime-audio-ring', executable('rinruntime-audio-ring-test',
          'tests/audio/rin_audio_service_client_ring_test.c',
          dependencies: runtime_dep, override_options: test_override_options))
  endif
  test('rinruntime-download-range', executable('rinruntime-download-range-test',
        'tests/download_range_transport_contract_test.cpp',
        dependencies: runtime_dep, override_options: test_override_options))
  test('rinruntime-public-common-adapters', executable(
        'rinruntime-public-common-adapters-test',
        'tests/public_common_adapters_contract_test.cpp',
        dependencies: runtime_dep, override_options: test_override_options,
        cpp_args: ['-std=c++17']))
  test('rinruntime-drag-drop', executable('rinruntime-drag-drop-test',
        'tests/drag_drop_contract_test.cpp', dependencies: runtime_dep,
        override_options: test_override_options))
  test('rinruntime-abi-policy', executable('rinruntime-abi-policy-test',
        'tests/abi_policy_test.cpp', dependencies: runtime_dep,
        override_options: test_override_options, cpp_args: ['-std=c++17']))
  test('rinruntime-device-manifest', executable('rinruntime-device-manifest-test',
        'tests/device_manifest_test.cpp', dependencies: runtime_dep,
        override_options: test_override_options, cpp_args: ['-std=c++17']))
  test('rinruntime-device-manifest-json', executable('rinruntime-device-manifest-json-test',
        'tests/device_manifest_json_test.cpp',
        dependencies: runtime_dep, override_options: test_override_options,
        cpp_args: ['-std=c++17']))
  test('rinruntime-event-loop-rin', executable('rinruntime-event-loop-rin-test',
        'tests/event_loop_rin_contract_test.cpp', join_paths(sdk_root, 'src/rinsdk_v1.c'),
        dependencies: runtime_dep, override_options: test_override_options,
        cpp_args: ['-std=c++17']))
  test('rinruntime-clipboard', executable('rinruntime-clipboard-test',
        'tests/clipboard_contract_test.c', dependencies: runtime_dep,
        override_options: test_override_options))
  test('rinruntime-update-metadata-json', executable('rinruntime-update-metadata-json-test',
        'tests/update_metadata_json_test.cpp',
        dependencies: runtime_dep, override_options: test_override_options,
        cpp_args: ['-std=c++17']))
  test('rinruntime-package-metadata-json', executable('rinruntime-package-metadata-json-test',
        'tests/package_metadata_json_test.cpp',
        dependencies: runtime_dep, override_options: test_override_options,
        cpp_args: ['-std=c++17']))
  test('rinruntime-package-metadata-catalog-json', executable('rinruntime-package-metadata-catalog-json-test',
        'tests/package_metadata_catalog_json_test.cpp',
        dependencies: runtime_dep, override_options: test_override_options,
        cpp_args: ['-std=c++17']))
  test('rinruntime-application-metadata-json', executable('rinruntime-application-metadata-json-test',
        'tests/application_metadata_json_test.cpp',
        dependencies: runtime_dep, override_options: test_override_options,
        cpp_args: ['-std=c++17']))
  test('rinruntime-application-metadata-catalog-json', executable('rinruntime-application-metadata-catalog-json-test',
        'tests/application_metadata_catalog_json_test.cpp',
        dependencies: runtime_dep, override_options: test_override_options,
        cpp_args: ['-std=c++17']))
  test('rinruntime-update-metadata-catalog-json', executable('rinruntime-update-metadata-catalog-json-test',
        'tests/update_metadata_catalog_json_test.cpp',
        dependencies: runtime_dep, override_options: test_override_options,
        cpp_args: ['-std=c++17']))
  test('rinruntime-theme-profile', executable('rinruntime-theme-profile-test',
        'tests/theme_profile_test.cpp', dependencies: runtime_dep,
        override_options: test_override_options, cpp_args: ['-std=c++17']))
  test('rinruntime-theme-profile-json', executable('rinruntime-theme-profile-json-test',
        'tests/theme_profile_json_test.cpp',
        dependencies: runtime_dep, override_options: test_override_options,
        cpp_args: ['-std=c++17']))
  test('rinruntime-cursor', executable('rinruntime-cursor-test',
        'tests/cursor_contract_test.c', dependencies: runtime_dep,
        override_options: test_override_options))
  test('rinruntime-archive-codec', executable('rinruntime-archive-codec-test',
        'tests/archive_codec_contract_test.cpp', dependencies: runtime_dep,
        override_options: test_override_options, cpp_args: ['-std=c++17']))
  test('rinruntime-tls-client-certificate', executable('rinruntime-tls-client-certificate-test',
        'tests/tls_client_certificate_contract_test.cpp', dependencies: runtime_dep,
        override_options: test_override_options, cpp_args: ['-std=c++17']))
  test('rincompression-deflate', executable('rincompression-deflate-test',
        'tests/deflate_contract_test.cpp', dependencies: runtime_dep,
        override_options: test_override_options, cpp_args: ['-std=c++17']))
  test('rincompression-lz4', executable('rincompression-lz4-test',
        'tests/lz4_contract_test.cpp', dependencies: runtime_dep,
        override_options: test_override_options, cpp_args: ['-std=c++17']))
  test('rincompression-zstd', executable('rincompression-zstd-test',
        'tests/zstd_contract_test.cpp', dependencies: runtime_dep,
        override_options: test_override_options, cpp_args: ['-std=c++17']))
  test('rinruntime-timezone', executable('rinruntime-timezone-test',
        'tests/timezone_contract_test.cpp', dependencies: runtime_dep,
        override_options: test_override_options, cpp_args: ['-std=c++17']))
  test('rinruntime-unicode', executable('rinruntime-unicode-test',
        'tests/unicode_contract_test.cpp', dependencies: runtime_dep,
        override_options: test_override_options, cpp_args: ['-std=c++17']))
endif
