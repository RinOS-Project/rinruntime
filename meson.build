project('RinRuntime', ['c', 'cpp'], version: '1.0.0',
        default_options: ['cpp_std=c++17', 'warning_level=3'])

inc = include_directories('include', '../../RinOS-SDK/include')
runtime_sources = files('src/portal.c', 'src/crash.c', 'src/backup_restore.c',
                        'src/known_folders.c', 'src/file_operation.c',
                        'src/serial_portal_protocol.c')
if host_machine.system() != 'windows'
  runtime_sources += files('src/audio/rin_audio_service_client.c')
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
  # RinOS supplies the SHM, clock, sleep, and service hooks at final app
  # link/load time.  Keep these real platform ABI imports instead of adding
  # host-only fallback implementations to the public runtime.
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
endif
