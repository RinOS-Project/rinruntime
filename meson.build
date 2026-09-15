project('RinRuntime', ['c', 'cpp'], version: '1.0.0',
        default_options: ['cpp_std=c++17', 'warning_level=3'])

python = import('python').find_installation(required: true)
fs = import('fs')
inc = include_directories('include', '../../RinOS-SDK/include',
                          '../rinjson/include', '../rinpath/include')
runtime_sources = files('src/portal.c', 'src/crash.c', 'src/backup_restore.c',
                        'src/known_folders.c', 'src/file_operation.c',
                        'src/safe_save.c', 'src/safe_save_posix.c',
                        'src/session_recovery.c', 'src/crash_service.c',
                        'src/path.c', 'src/serial_portal_protocol.c')
if host_machine.system() != 'windows'
  runtime_sources += files('src/backup_payload.c')
  runtime_sources += files('src/platform.c')
  runtime_sources += files('src/clipboard.c')
  runtime_sources += files('src/crash_service_client.c',
                           'src/file_portal.c',
                           'src/durable_file_portal.c',
                           'src/file_chooser_portal.c',
                           'src/file_operation_service_client.c',
                           'src/accessibility_service_client.c',
                           'src/audio/rin_audio_service_client.c',
                           'src/rin_keyring_client.c')
  aq_inc = include_directories('../aquamarine', '../libunicode', '../../RinOS-SDK/include')
  aq_sources = files('../aquamarine/aq_blend.c', '../aquamarine/aq_color.c',
                     '../aquamarine/aq_draw.c', '../aquamarine/aq_gradient.c',
                     '../aquamarine/aq_path.c', '../aquamarine/aq_render3d.c',
                     '../aquamarine/aq_surface.c', '../aquamarine/aq_text.c',
                     '../aquamarine/aq_transform.c', '../libunicode/core.c')
  aquamarine = static_library('Aquamarine', aq_sources,
                              include_directories: aq_inc)
  aquamarine_dep = declare_dependency(link_with: aquamarine,
                                       include_directories: aq_inc)
  runtime_sources += files('src/compositor_gui.c', 'src/render.c',
                           'src/render_context.cpp')
endif
runtime_deps = []
runtime_link_args = []
test_override_options = []
if host_machine.system() != 'windows'
  runtime_deps += aquamarine_dep
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
                                 dependencies: runtime_deps)
install_subdir('include/rinruntime', install_dir: get_option('includedir'))
install_subdir('include/rincompression', install_dir: get_option('includedir'))

if get_option('build_rll')
  if get_option('rll_sign_key') == '' or get_option('rll_public_key') == ''
    error('build_rll requires rll_sign_key and rll_public_key')
  endif
  rll_sources = get_option('rll_sources')
  if rll_sources.length() == 0
    error('build_rll requires at least one rll_sources entry')
  endif
  foreach rll_source : rll_sources
    if not fs.is_file(join_paths(meson.current_source_dir(), rll_source))
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
    '--include', join_paths(meson.current_source_dir(), '../../RinOS-SDK/include'),
  ]
  foreach rll_source : rll_sources
    rll_command += ['--source', rll_source]
  endforeach
  foreach rll_dependency : get_option('rll_dependencies')
    rll_command += ['--dependency', rll_dependency]
  endforeach
  rinruntime_rll = custom_target(
    'RinRuntime-rll',
    input: rll_source_files,
    output: 'RinRuntime.rll',
    command: rll_command,
    build_by_default: false,
  )
  alias_target('rll', [rinruntime_rll])
  install_data(rinruntime_rll, install_dir: get_option('libdir'))
endif

if get_option('buildtype') != 'plain'
  test('rinruntime-model', executable('rinruntime-model-test',
        'tests/runtime_model_test.cpp', dependencies: runtime_dep,
        override_options: test_override_options))
  test('rinruntime-portal', executable('rinruntime-portal-test',
        'tests/portal_contract_test.c', dependencies: runtime_dep,
        override_options: test_override_options))
  test('rinruntime-policy', executable('rinruntime-policy-test',
        'tests/policy_contract_test.c', dependencies: runtime_dep,
        override_options: test_override_options))
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
    test('rinruntime-audio-ring', executable('rinruntime-audio-ring-test',
          'tests/audio/rin_audio_service_client_ring_test.c',
          dependencies: runtime_dep, override_options: test_override_options))
  endif
  test('rinruntime-download-range', executable('rinruntime-download-range-test',
        'tests/download_range_transport_contract_test.cpp',
        dependencies: runtime_dep, override_options: test_override_options))
  test('rinruntime-drag-drop', executable('rinruntime-drag-drop-test',
        'tests/drag_drop_contract_test.cpp', dependencies: runtime_dep,
        override_options: test_override_options))
  test('rinruntime-abi-policy', executable('rinruntime-abi-policy-test',
        'tests/abi_policy_test.cpp', dependencies: runtime_dep,
        override_options: test_override_options, cpp_args: ['-std=c++17']))
  test('rinruntime-event-loop-rin', executable('rinruntime-event-loop-rin-test',
        'tests/event_loop_rin_contract_test.cpp', '../../RinOS-SDK/src/rinsdk_v1.c',
        dependencies: runtime_dep, override_options: test_override_options,
        cpp_args: ['-std=c++17']))
  test('rinruntime-clipboard', executable('rinruntime-clipboard-test',
        'tests/clipboard_contract_test.c', dependencies: runtime_dep,
        override_options: test_override_options))
  test('rinruntime-update-metadata-json', executable('rinruntime-update-metadata-json-test',
        'tests/update_metadata_json_test.cpp', '../rinjson/src/json.cpp',
        dependencies: runtime_dep, override_options: test_override_options,
        cpp_args: ['-std=c++17']))
  test('rinruntime-package-metadata-json', executable('rinruntime-package-metadata-json-test',
        'tests/package_metadata_json_test.cpp', '../rinjson/src/json.cpp',
        dependencies: runtime_dep, override_options: test_override_options,
        cpp_args: ['-std=c++17']))
  test('rinruntime-application-metadata-json', executable('rinruntime-application-metadata-json-test',
        'tests/application_metadata_json_test.cpp', '../rinjson/src/json.cpp',
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
endif
