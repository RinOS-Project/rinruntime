/* SPDX-License-Identifier: MIT */
#ifndef RINRUNTIME_PRIVATE_SERVICE_SOCKET_H
#define RINRUNTIME_PRIVATE_SERVICE_SOCKET_H

#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

/* Private service channels must not survive exec in a child process.  Prefer
 * atomic creation; if the platform rejects only SOCK_CLOEXEC, set the flag
 * before returning the descriptor and fail closed if either fcntl call fails. */
static inline int rinruntime_create_private_unix_stream_socket(void)
{
    int fd;
#if defined(SOCK_CLOEXEC)
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd >= 0) return fd;
    if (errno != EINVAL && errno != ENOSYS && errno != EOPNOTSUPP)
        return -1;
#endif

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    {
        const int descriptor_flags = fcntl(fd, F_GETFD, 0);
        if (descriptor_flags < 0 ||
            fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0) {
            (void)close(fd);
            return -1;
        }
    }
    return fd;
}

#endif
