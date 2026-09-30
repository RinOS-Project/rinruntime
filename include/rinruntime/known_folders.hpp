/* SPDX-License-Identifier: MIT */
/* C++ convenience wrapper for the public known-folders runtime ABI. */

#ifndef RINRUNTIME_KNOWN_FOLDERS_HPP
#define RINRUNTIME_KNOWN_FOLDERS_HPP

#include "known_folders.h"
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
#    include <new>
#endif
#include <string>

namespace RinRuntime {

enum class KnownFolder {
    Home = RINRUNTIME_KNOWN_FOLDER_HOME,
    Desktop = RINRUNTIME_KNOWN_FOLDER_DESKTOP,
    Documents = RINRUNTIME_KNOWN_FOLDER_DOCUMENTS,
    Downloads = RINRUNTIME_KNOWN_FOLDER_DOWNLOADS,
    Music = RINRUNTIME_KNOWN_FOLDER_MUSIC,
    Pictures = RINRUNTIME_KNOWN_FOLDER_PICTURES,
    Videos = RINRUNTIME_KNOWN_FOLDER_VIDEOS,
    Trash = RINRUNTIME_KNOWN_FOLDER_TRASH,
};

enum class ApplicationDirectory {
    Config = RINRUNTIME_APPLICATION_DIRECTORY_CONFIG,
    Data = RINRUNTIME_APPLICATION_DIRECTORY_DATA,
    Cache = RINRUNTIME_APPLICATION_DIRECTORY_CACHE,
    State = RINRUNTIME_APPLICATION_DIRECTORY_STATE,
    Backup = RINRUNTIME_APPLICATION_DIRECTORY_BACKUP,
};

inline std::string knownFolder(KnownFolder folder)
{
    char path[RINRUNTIME_KNOWN_FOLDER_PATH_MAX] = {};
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
    try {
#endif
    if (rinruntime_known_folder_current(
            static_cast<RinRuntimeKnownFolder>(folder), path,
            sizeof(path)) != RINRUNTIME_KNOWN_FOLDER_OK)
        return {};
    return path;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
    } catch (const std::bad_alloc&) {
        return {};
    }
#endif
}

inline std::string applicationDirectory(ApplicationDirectory directory,
                                        const std::string& applicationId)
{
    char path[RINRUNTIME_KNOWN_FOLDER_PATH_MAX] = {};
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
    try {
#endif
    if (rinruntime_application_directory_current(
            static_cast<RinRuntimeApplicationDirectory>(directory),
            applicationId.c_str(), path, sizeof(path)) !=
        RINRUNTIME_KNOWN_FOLDER_OK)
        return {};
    return path;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
    } catch (const std::bad_alloc&) {
        return {};
    }
#endif
}

} // namespace RinRuntime

#endif /* RINRUNTIME_KNOWN_FOLDERS_HPP */
