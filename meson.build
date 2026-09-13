project('RinRuntime', ['c', 'cpp'], version: '1.0.0',
        default_options: ['cpp_std=c++17', 'warning_level=3'])

inc = include_directories('include')
runtime_sources = files('src/portal.c', 'src/crash.c', 'src/backup_restore.c',
                        'src/known_folders.c', 'src/file_operation.c')
runtime = library('RinRuntime', runtime_sources, include_directories: inc,
                  install: true, version: '1.0.0')
runtime_dep = declare_dependency(link_with: runtime, include_directories: inc)
install_subdir('include/rinruntime', install_dir: get_option('includedir'))

if get_option('buildtype') != 'plain'
  test('rinruntime-model', executable('rinruntime-model-test',
        'tests/runtime_model_test.cpp', dependencies: runtime_dep))
  test('rinruntime-portal', executable('rinruntime-portal-test',
        'tests/portal_contract_test.c', dependencies: runtime_dep))
  test('rinruntime-policy', executable('rinruntime-policy-test',
        'tests/policy_contract_test.c', dependencies: runtime_dep))
endif
