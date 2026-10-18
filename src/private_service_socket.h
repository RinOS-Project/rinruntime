/* SPDX-License-Identifier: MIT */
#ifndef RINRUNTIME_PRIVATE_SERVICE_SOCKET_H
#define RINRUNTIME_PRIVATE_SERVICE_SOCKET_H

#include <stddef.h>
#include <sys/socket.h>
#include <unistd.h>

/* Private service channels must not survive exec in a child process, so both
 * socket constructors require atomic CLOEXEC creation. */
static inline int rinruntime_create_private_unix_stream_socket(void)
{
#if defined(SOCK_CLOEXEC)
    return socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    return -1;
#endif
}

/* Internal runtime socket pairs carry process-scoped evidence too.  Both
 * endpoints must be closed when the current process replaces itself. */
static inline int rinruntime_create_private_unix_stream_socketpair(
    int descriptors[2])
{
    int result;
    if (descriptors == NULL) return -1;
    descriptors[0] = -1;
    descriptors[1] = -1;
#if defined(SOCK_CLOEXEC)
    result = socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, descriptors);
    if (result == 0) return 0;
    if (descriptors[0] >= 0) (void)close(descriptors[0]);
    if (descriptors[1] >= 0) (void)close(descriptors[1]);
    descriptors[0] = -1;
    descriptors[1] = -1;
    return -1;
#else
    return -1;
#endif
}

#endif
