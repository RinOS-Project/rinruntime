/* SPDX-License-Identifier: MIT */

#include <rinruntime/pty.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <rin/tty/abi.h>

static void pty_reset(RinRuntimePtyV1* pty)
{
    if (pty == NULL) return;
    memset(pty, 0, sizeof(*pty));
    pty->struct_size = sizeof(*pty);
    pty->version = RIN_RUNTIME_PTY_VERSION;
    pty->master_fd = -1;
    pty->slave_fd = -1;
}

static int pty_slave_path(uint32_t number, char* output, size_t capacity)
{
    char digits[10];
    size_t count = 0u;
    size_t index;
    static const char prefix[] = "/dev/pts/";
    if (output == NULL || capacity < sizeof(prefix) + 1u) return -1;
    do {
        digits[count++] = (char)('0' + number % 10u);
        number /= 10u;
    } while (number != 0u && count < sizeof(digits));
    if (number != 0u || sizeof(prefix) + count > capacity) return -1;
    memcpy(output, prefix, sizeof(prefix) - 1u);
    for (index = 0u; index < count; ++index)
        output[sizeof(prefix) - 1u + index] = digits[count - index - 1u];
    output[sizeof(prefix) - 1u + count] = '\0';
    return 0;
}

int rinruntime_pty_open(RinRuntimePtyV1* pty)
{
    RinRuntimePtyV1 candidate;
    int number = -1;
    int unlocked = 0;
    int saved_errno;
    pty_reset(pty);
    if (pty == NULL) {
        errno = EINVAL;
        return -1;
    }
    pty_reset(&candidate);
    candidate.master_fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    if (candidate.master_fd < 0) goto fail;
    if (ioctl(candidate.master_fd, RIN_TTY_IOCTL_TIOCGPTN, &number) != 0)
        goto fail;
    if (number < 0) {
        errno = EIO;
        goto fail;
    }
    if (ioctl(candidate.master_fd, RIN_TTY_IOCTL_TIOCSPTLCK,
              &unlocked) != 0)
        goto fail;
    if (pty_slave_path((uint32_t)number, candidate.slave_path,
                       sizeof(candidate.slave_path)) != 0) {
        errno = EOVERFLOW;
        goto fail;
    }
    candidate.slave_fd = open(candidate.slave_path, O_RDWR | O_NOCTTY);
    if (candidate.slave_fd < 0) goto fail;
    *pty = candidate;
    memset(&candidate, 0, sizeof(candidate));
    return 0;

fail:
    saved_errno = errno;
    if (candidate.slave_fd >= 0) (void)close(candidate.slave_fd);
    if (candidate.master_fd >= 0) (void)close(candidate.master_fd);
    memset(&candidate, 0, sizeof(candidate));
    pty_reset(pty);
    errno = saved_errno;
    return -1;
}

int rinruntime_pty_close(RinRuntimePtyV1* pty)
{
    int master_fd;
    int slave_fd;
    int saved_errno = 0;
    int result = 0;
    if (pty == NULL || pty->struct_size != sizeof(*pty) ||
        pty->version != RIN_RUNTIME_PTY_VERSION) {
        errno = EINVAL;
        return -1;
    }
    master_fd = pty->master_fd;
    slave_fd = pty->slave_fd;
    pty_reset(pty);
    if (slave_fd >= 0 && close(slave_fd) != 0) {
        result = -1;
        saved_errno = errno;
    }
    if (master_fd >= 0 && close(master_fd) != 0 && result == 0) {
        result = -1;
        saved_errno = errno;
    }
    if (result != 0) errno = saved_errno;
    return result;
}
