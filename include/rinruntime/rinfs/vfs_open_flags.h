/* SPDX-License-Identifier: MIT */

#ifndef RIN_SHARED_RINFS_VFS_OPEN_FLAGS_H
#define RIN_SHARED_RINFS_VFS_OPEN_FLAGS_H

/* Shared owner-level flags consumed by RinFS providers. These are distinct
 * from the POSIX O_* ABI translated at the syscall boundary. */
#define RIN_VFS_OPEN_READ   0x0001u
#define RIN_VFS_OPEN_WRITE  0x0002u
#define RIN_VFS_OPEN_RDWR   0x0003u
#define RIN_VFS_OPEN_CREATE 0x0100u
#define RIN_VFS_OPEN_TRUNC  0x0200u
#define RIN_VFS_OPEN_APPEND 0x0400u
#define RIN_VFS_OPEN_EXCL   0x0800u
#define RIN_VFS_OPEN_SYNC   0x1000u
#define RIN_VFS_OPEN_NONBLOCK 0x2000u
#define RIN_VFS_OPEN_DIRECT 0x4000u
#define RIN_VFS_OPEN_REPARSE 0x8000u
#define RIN_VFS_OPEN_NOFOLLOW 0x10000u
#define RIN_VFS_OPEN_PATH 0x20000u
#define RIN_VFS_OPEN_TMPFILE 0x40000u
#define RIN_VFS_OPEN_DIRECTORY 0x80000u

/* fcntl status flags are deliberately separate from the VFS open-flag
 * namespace. The syscall boundary translates its O_* ABI values before
 * calling vfs_{get,set}_fcntl_flags(). */
#define RIN_VFS_FCNTL_READ     0x0001u
#define RIN_VFS_FCNTL_WRITE    0x0002u
#define RIN_VFS_FCNTL_APPEND   0x0004u
#define RIN_VFS_FCNTL_SYNC     0x0008u
#define RIN_VFS_FCNTL_NONBLOCK 0x0010u
#define RIN_VFS_FCNTL_DIRECT   0x0020u
#define RIN_VFS_FCNTL_PATH     0x0040u
#define RIN_VFS_FCNTL_TMPFILE  0x0080u
#define RIN_VFS_FCNTL_MUTABLE \
    (RIN_VFS_FCNTL_APPEND | RIN_VFS_FCNTL_SYNC | RIN_VFS_FCNTL_NONBLOCK | \
     RIN_VFS_FCNTL_DIRECT)

#endif /* RIN_SHARED_RINFS_VFS_OPEN_FLAGS_H */
