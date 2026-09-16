/* SPDX-License-Identifier: MIT */

#include <rinruntime/known_folders.h>

#include <stdlib.h>

static int rinruntime_string_length(const char* value, size_t limit,
                                    size_t* length_out)
{
    size_t length;
    if (value == NULL || length_out == NULL) return 0;
    for (length = 0u; length < limit; ++length) {
        if (value[length] == '\0') {
            *length_out = length;
            return 1;
        }
    }
    return 0;
}

static void rinruntime_clear_output(char* output, size_t capacity)
{
    if (output != NULL && capacity != 0u) output[0] = '\0';
}

static int rinruntime_home_is_canonical(const char* home, size_t* length_out)
{
    size_t index = 0u;
    size_t component_start = 0u;
    if (home == NULL || home[0] != '/') return 0;
    while (index < RINRUNTIME_KNOWN_FOLDER_PATH_MAX &&
           home[index] != '\0') {
        unsigned char character = (unsigned char)home[index];
        if (character < 0x20u || character == 0x7fu || character == '\\')
            return 0;
        if (character == '/') {
            size_t component_length = index - component_start;
            if (index != 0u && component_length == 0u) return 0;
            if (component_length == 1u && home[component_start] == '.') return 0;
            if (component_length == 2u && home[component_start] == '.' &&
                home[component_start + 1u] == '.') return 0;
            component_start = index + 1u;
        }
        ++index;
    }
    if (index == RINRUNTIME_KNOWN_FOLDER_PATH_MAX) return 0;
    if (index > 1u && home[index - 1u] == '/') return 0;
    if (component_start < index) {
        size_t component_length = index - component_start;
        if ((component_length == 1u && home[component_start] == '.') ||
            (component_length == 2u && home[component_start] == '.' &&
             home[component_start + 1u] == '.')) return 0;
    }
    if (length_out != NULL) *length_out = index;
    return 1;
}

static int rinruntime_application_id_is_valid(const char* value, size_t* length_out)
{
    size_t index = 0u;
    if (value == NULL || value[0] == '\0') return 0;
    while (index < RINRUNTIME_APPLICATION_ID_MAX && value[index] != '\0') {
        unsigned char character = (unsigned char)value[index];
        int allowed = (character >= 'a' && character <= 'z') ||
                      (character >= 'A' && character <= 'Z') ||
                      (character >= '0' && character <= '9') ||
                      character == '.' || character == '_' || character == '-';
        if (!allowed) return 0;
        ++index;
    }
    if (index == RINRUNTIME_APPLICATION_ID_MAX) return 0;
    if ((index == 1u && value[0] == '.') ||
        (index == 2u && value[0] == '.' && value[1] == '.')) return 0;
    if (length_out != NULL) *length_out = index;
    return 1;
}

static const char* rinruntime_folder_suffix(RinRuntimeKnownFolder folder)
{
    switch (folder) {
    case RINRUNTIME_KNOWN_FOLDER_HOME: return "";
    case RINRUNTIME_KNOWN_FOLDER_DESKTOP: return "desktop";
    case RINRUNTIME_KNOWN_FOLDER_DOCUMENTS: return "docs";
    case RINRUNTIME_KNOWN_FOLDER_DOWNLOADS: return "downloads";
    case RINRUNTIME_KNOWN_FOLDER_MUSIC: return "music";
    case RINRUNTIME_KNOWN_FOLDER_PICTURES: return "pictures";
    case RINRUNTIME_KNOWN_FOLDER_VIDEOS: return "videos";
    case RINRUNTIME_KNOWN_FOLDER_TRASH: return ".Trash";
    default: return NULL;
    }
}

static const char* rinruntime_application_root(
    RinRuntimeApplicationDirectory directory)
{
    switch (directory) {
    case RINRUNTIME_APPLICATION_DIRECTORY_CONFIG: return "config";
    case RINRUNTIME_APPLICATION_DIRECTORY_DATA: return "data";
    case RINRUNTIME_APPLICATION_DIRECTORY_CACHE: return "cache";
    case RINRUNTIME_APPLICATION_DIRECTORY_STATE: return "state";
    case RINRUNTIME_APPLICATION_DIRECTORY_BACKUP: return "backup";
    default: return NULL;
    }
}

static const char* rinruntime_folder_environment_name(
    RinRuntimeKnownFolder folder)
{
    switch (folder) {
    case RINRUNTIME_KNOWN_FOLDER_HOME: return "RIN_KNOWN_FOLDER_HOME";
    case RINRUNTIME_KNOWN_FOLDER_DESKTOP: return "RIN_KNOWN_FOLDER_DESKTOP";
    case RINRUNTIME_KNOWN_FOLDER_DOCUMENTS: return "RIN_KNOWN_FOLDER_DOCUMENTS";
    case RINRUNTIME_KNOWN_FOLDER_DOWNLOADS: return "RIN_KNOWN_FOLDER_DOWNLOADS";
    case RINRUNTIME_KNOWN_FOLDER_MUSIC: return "RIN_KNOWN_FOLDER_MUSIC";
    case RINRUNTIME_KNOWN_FOLDER_PICTURES: return "RIN_KNOWN_FOLDER_PICTURES";
    case RINRUNTIME_KNOWN_FOLDER_VIDEOS: return "RIN_KNOWN_FOLDER_VIDEOS";
    case RINRUNTIME_KNOWN_FOLDER_TRASH: return "RIN_KNOWN_FOLDER_TRASH";
    default: return NULL;
    }
}

static const char* rinruntime_application_environment_name(
    RinRuntimeApplicationDirectory directory)
{
    switch (directory) {
    case RINRUNTIME_APPLICATION_DIRECTORY_CONFIG: return "RIN_KNOWN_FOLDER_APP_CONFIG";
    case RINRUNTIME_APPLICATION_DIRECTORY_DATA: return "RIN_KNOWN_FOLDER_APP_DATA";
    case RINRUNTIME_APPLICATION_DIRECTORY_CACHE: return "RIN_KNOWN_FOLDER_APP_CACHE";
    case RINRUNTIME_APPLICATION_DIRECTORY_STATE: return "RIN_KNOWN_FOLDER_APP_STATE";
    case RINRUNTIME_APPLICATION_DIRECTORY_BACKUP: return "RIN_KNOWN_FOLDER_APP_BACKUP";
    default: return NULL;
    }
}

static RinRuntimeKnownFolderResult rinruntime_build_path(
    const char* home, size_t home_length, const char* first, const char* second,
    char* path_out, size_t path_capacity)
{
    char path[RINRUNTIME_KNOWN_FOLDER_PATH_MAX];
    size_t first_length;
    size_t second_length;
    size_t length = home_length;
    size_t index;
    size_t separator_count = 0u;
    if (!rinruntime_string_length(first, RINRUNTIME_KNOWN_FOLDER_PATH_MAX,
                                 &first_length) ||
        !rinruntime_string_length(second, RINRUNTIME_KNOWN_FOLDER_PATH_MAX,
                                  &second_length)) {
        rinruntime_clear_output(path_out, path_capacity);
        return RINRUNTIME_KNOWN_FOLDER_INVALID_ARGUMENT;
    }
    if (first_length != 0u && home_length != 1u) ++separator_count;
    if (second_length != 0u) ++separator_count;
    if (home_length > RINRUNTIME_KNOWN_FOLDER_PATH_MAX - 1u ||
        first_length > RINRUNTIME_KNOWN_FOLDER_PATH_MAX - 1u - home_length ||
        second_length > RINRUNTIME_KNOWN_FOLDER_PATH_MAX - 1u - home_length -
                            first_length ||
        separator_count > RINRUNTIME_KNOWN_FOLDER_PATH_MAX - 1u - home_length -
                              first_length - second_length) {
        rinruntime_clear_output(path_out, path_capacity);
        return RINRUNTIME_KNOWN_FOLDER_BUFFER_TOO_SMALL;
    }
    for (index = 0u; index < home_length; ++index) path[index] = home[index];
    if (first_length != 0u) {
        if (length != 1u) path[length++] = '/';
        for (index = 0u; index < first_length; ++index) path[length++] = first[index];
    }
    if (second_length != 0u) {
        path[length++] = '/';
        for (index = 0u; index < second_length; ++index) path[length++] = second[index];
    }
    path[length] = '\0';
    if (length + 1u > path_capacity) {
        rinruntime_clear_output(path_out, path_capacity);
        return RINRUNTIME_KNOWN_FOLDER_BUFFER_TOO_SMALL;
    }
    for (index = 0u; index <= length; ++index) path_out[index] = path[index];
    return RINRUNTIME_KNOWN_FOLDER_OK;
}

static RinRuntimeKnownFolderResult rinruntime_copy_canonical_path(
    const char* source, char* path_out, size_t path_capacity)
{
    size_t source_length;
    if (path_out == NULL || path_capacity == 0u ||
        !rinruntime_home_is_canonical(source, &source_length)) {
        rinruntime_clear_output(path_out, path_capacity);
        return RINRUNTIME_KNOWN_FOLDER_INVALID_ARGUMENT;
    }
    return rinruntime_build_path(source, source_length, "", "", path_out,
                                 path_capacity);
}

static RinRuntimeKnownFolderResult rinruntime_current_home(
    char* path_out, size_t path_capacity)
{
    const char* relocated_home = getenv("RIN_KNOWN_FOLDER_HOME");
    const char* home;
    if (relocated_home != NULL)
        return rinruntime_copy_canonical_path(relocated_home, path_out,
                                              path_capacity);
    home = getenv("HOME");
    if (home == NULL || home[0] == '\0') {
        rinruntime_clear_output(path_out, path_capacity);
        return RINRUNTIME_KNOWN_FOLDER_UNAVAILABLE;
    }
    return rinruntime_copy_canonical_path(home, path_out, path_capacity);
}

RinRuntimeKnownFolderResult rinruntime_known_folder_resolve(
    const char* home, RinRuntimeKnownFolder folder, char* path_out,
    size_t path_capacity)
{
    const char* suffix = rinruntime_folder_suffix(folder);
    size_t home_length;
    if (path_out == NULL || path_capacity == 0u || suffix == NULL ||
        !rinruntime_home_is_canonical(home, &home_length)) {
        rinruntime_clear_output(path_out, path_capacity);
        return RINRUNTIME_KNOWN_FOLDER_INVALID_ARGUMENT;
    }
    return rinruntime_build_path(home, home_length, suffix, "", path_out,
                                 path_capacity);
}

RinRuntimeKnownFolderResult rinruntime_application_directory_resolve(
    const char* home, RinRuntimeApplicationDirectory directory,
    const char* application_id, char* path_out, size_t path_capacity)
{
    const char* root = rinruntime_application_root(directory);
    size_t home_length;
    if (path_out == NULL || path_capacity == 0u || root == NULL ||
        !rinruntime_home_is_canonical(home, &home_length) ||
        !rinruntime_application_id_is_valid(application_id, NULL)) {
        rinruntime_clear_output(path_out, path_capacity);
        return RINRUNTIME_KNOWN_FOLDER_INVALID_ARGUMENT;
    }
    return rinruntime_build_path(home, home_length, root, application_id,
                                 path_out, path_capacity);
}

RinRuntimeKnownFolderResult rinruntime_known_folder_current(
    RinRuntimeKnownFolder folder, char* path_out, size_t path_capacity)
{
    const char* relocation_name = rinruntime_folder_environment_name(folder);
    const char* relocated_path;
    char home[RINRUNTIME_KNOWN_FOLDER_PATH_MAX];
    RinRuntimeKnownFolderResult result;
    if (relocation_name == NULL) {
        rinruntime_clear_output(path_out, path_capacity);
        return RINRUNTIME_KNOWN_FOLDER_INVALID_ARGUMENT;
    }
    if (folder == RINRUNTIME_KNOWN_FOLDER_HOME)
        return rinruntime_current_home(path_out, path_capacity);
    relocated_path = getenv(relocation_name);
    if (relocated_path != NULL)
        return rinruntime_copy_canonical_path(relocated_path, path_out,
                                              path_capacity);
    result = rinruntime_current_home(home, sizeof(home));
    if (result != RINRUNTIME_KNOWN_FOLDER_OK) {
        rinruntime_clear_output(path_out, path_capacity);
        return result;
    }
    return rinruntime_known_folder_resolve(home, folder, path_out, path_capacity);
}

RinRuntimeKnownFolderResult rinruntime_application_directory_current(
    RinRuntimeApplicationDirectory directory, const char* application_id,
    char* path_out, size_t path_capacity)
{
    const char* relocation_name = rinruntime_application_environment_name(directory);
    const char* relocated_root;
    size_t root_length;
    char home[RINRUNTIME_KNOWN_FOLDER_PATH_MAX];
    RinRuntimeKnownFolderResult result;
    if (relocation_name == NULL || path_out == NULL || path_capacity == 0u ||
        !rinruntime_application_id_is_valid(application_id, NULL)) {
        rinruntime_clear_output(path_out, path_capacity);
        return RINRUNTIME_KNOWN_FOLDER_INVALID_ARGUMENT;
    }
    relocated_root = getenv(relocation_name);
    if (relocated_root != NULL) {
        if (!rinruntime_home_is_canonical(relocated_root, &root_length)) {
            rinruntime_clear_output(path_out, path_capacity);
            return RINRUNTIME_KNOWN_FOLDER_INVALID_ARGUMENT;
        }
        return rinruntime_build_path(relocated_root, root_length, "",
                                     application_id, path_out, path_capacity);
    }
    result = rinruntime_current_home(home, sizeof(home));
    if (result != RINRUNTIME_KNOWN_FOLDER_OK) {
        rinruntime_clear_output(path_out, path_capacity);
        return result;
    }
    return rinruntime_application_directory_resolve(home, directory,
                                                    application_id, path_out,
                                                    path_capacity);
}
