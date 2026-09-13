/* SPDX-License-Identifier: MIT */
/* Public, toolkit-independent user folder and per-application storage API. */

#ifndef RINRUNTIME_KNOWN_FOLDERS_H
#define RINRUNTIME_KNOWN_FOLDERS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Includes the terminating NUL.  Callers may supply a larger buffer. */
#define RINRUNTIME_KNOWN_FOLDER_PATH_MAX 512u
#define RINRUNTIME_APPLICATION_ID_MAX 64u

typedef enum RinRuntimeKnownFolder {
    RINRUNTIME_KNOWN_FOLDER_HOME = 0,
    RINRUNTIME_KNOWN_FOLDER_DESKTOP = 1,
    RINRUNTIME_KNOWN_FOLDER_DOCUMENTS = 2,
    RINRUNTIME_KNOWN_FOLDER_DOWNLOADS = 3,
    RINRUNTIME_KNOWN_FOLDER_MUSIC = 4,
    RINRUNTIME_KNOWN_FOLDER_PICTURES = 5,
    RINRUNTIME_KNOWN_FOLDER_VIDEOS = 6,
    /* Per-user persistent Trash root.  The caller creates its contents on
     * demand, so resolving this folder never mutates the filesystem. */
    RINRUNTIME_KNOWN_FOLDER_TRASH = 7
} RinRuntimeKnownFolder;

typedef enum RinRuntimeApplicationDirectory {
    RINRUNTIME_APPLICATION_DIRECTORY_CONFIG = 0,
    RINRUNTIME_APPLICATION_DIRECTORY_DATA = 1,
    RINRUNTIME_APPLICATION_DIRECTORY_CACHE = 2,
    RINRUNTIME_APPLICATION_DIRECTORY_STATE = 3,
    /* Durable, explicitly-declared backup payloads.  This is separate from
     * state so an application can clear transient session data without
     * affecting a user-selected backup set. */
    RINRUNTIME_APPLICATION_DIRECTORY_BACKUP = 4
} RinRuntimeApplicationDirectory;

typedef enum RinRuntimeKnownFolderResult {
    RINRUNTIME_KNOWN_FOLDER_OK = 0,
    RINRUNTIME_KNOWN_FOLDER_INVALID_ARGUMENT = -1,
    RINRUNTIME_KNOWN_FOLDER_BUFFER_TOO_SMALL = -2,
    RINRUNTIME_KNOWN_FOLDER_UNAVAILABLE = -3
} RinRuntimeKnownFolderResult;

/* Resolve a user-visible standard folder below an absolute, canonical home
 * directory.  The input may alias `path_out`; output is cleared on failure
 * whenever capacity permits. */
RinRuntimeKnownFolderResult rinruntime_known_folder_resolve(
    const char* home, RinRuntimeKnownFolder folder, char* path_out,
    size_t path_capacity);

/* Resolve an application's XDG-style storage root:
 *   config/<id>, data/<id>, cache/<id>, state/<id>, or backup/<id>.
 * `application_id` is deliberately a bounded identifier, not a path, so an
 * external app cannot escape the selected root with separators or `..`.
 * Sandboxed RinOS apps receive a kernel-controlled private profile instead;
 * they must use their sandbox storage capability, rather than treating this
 * convenience API as authority to access the ambient home directory. */
RinRuntimeKnownFolderResult rinruntime_application_directory_resolve(
    const char* home, RinRuntimeApplicationDirectory directory,
    const char* application_id, char* path_out, size_t path_capacity);

/* Current-user variants use the authenticated session's relocation overlay on
 * every call.  The session launcher may set these absolute canonical roots:
 *
 *   RIN_KNOWN_FOLDER_HOME, RIN_KNOWN_FOLDER_DESKTOP,
 *   RIN_KNOWN_FOLDER_DOCUMENTS, RIN_KNOWN_FOLDER_DOWNLOADS,
 *   RIN_KNOWN_FOLDER_MUSIC, RIN_KNOWN_FOLDER_PICTURES,
 *   RIN_KNOWN_FOLDER_VIDEOS, RIN_KNOWN_FOLDER_TRASH,
 *   RIN_KNOWN_FOLDER_APP_CONFIG, RIN_KNOWN_FOLDER_APP_DATA,
 *   RIN_KNOWN_FOLDER_APP_CACHE, RIN_KNOWN_FOLDER_APP_STATE, and
 *   RIN_KNOWN_FOLDER_APP_BACKUP.
 *
 * A per-folder root replaces only that location; missing values retain the
 * canonical HOME-derived layout.  Invalid present values fail closed and are
 * never replaced with a guessed system path.  This is location discovery,
 * not a file-access capability. */
RinRuntimeKnownFolderResult rinruntime_known_folder_current(
    RinRuntimeKnownFolder folder, char* path_out, size_t path_capacity);
RinRuntimeKnownFolderResult rinruntime_application_directory_current(
    RinRuntimeApplicationDirectory directory, const char* application_id,
    char* path_out, size_t path_capacity);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_KNOWN_FOLDERS_H */
