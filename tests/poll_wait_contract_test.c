/* SPDX-License-Identifier: MIT */

#include <assert.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../include/rinruntime/poll_wait.h"

static uint64_t g_clock_values[4];
static uint32_t g_clock_count;
static uint32_t g_clock_index;

uint64_t rin_monotonic_ms(void)
{
    assert(g_clock_count != 0u);
    return g_clock_values[g_clock_index < g_clock_count
                              ? g_clock_index++
                              : g_clock_count - 1u];
}

static void set_clock(uint64_t first, uint64_t second, uint32_t count)
{
    g_clock_values[0] = first;
    g_clock_values[1] = second;
    g_clock_count = count;
    g_clock_index = 0u;
}

int main(void)
{
    int sockets[2] = {-1, -1};
    char byte = 'p';

    assert(rinruntime_poll_wait(-1, RINRUNTIME_POLL_WAIT_READABLE, 0u) ==
           RINRUNTIME_POLL_WAIT_FAILURE);
    assert(rinruntime_poll_wait(1, 0u, 0u) == RINRUNTIME_POLL_WAIT_FAILURE);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);

    set_clock(100u, 0u, 1u);
    assert(write(sockets[0], &byte, sizeof(byte)) == 1);
    assert(rinruntime_poll_wait(
               sockets[1], RINRUNTIME_POLL_WAIT_READABLE, 10u) ==
           RINRUNTIME_POLL_WAIT_READY);
    assert(read(sockets[1], &byte, sizeof(byte)) == 1);

    set_clock(200u, 201u, 2u);
    assert(rinruntime_poll_wait(
               sockets[1], RINRUNTIME_POLL_WAIT_READABLE, 1u) ==
           RINRUNTIME_POLL_WAIT_TIMEOUT);

    set_clock(300u, 0u, 1u);
    assert(close(sockets[0]) == 0);
    assert(rinruntime_poll_wait(
               sockets[1], RINRUNTIME_POLL_WAIT_READABLE, 1u) ==
           RINRUNTIME_POLL_WAIT_FAILURE);

    set_clock(400u, 399u, 2u);
    assert(rinruntime_poll_wait(
               sockets[1], RINRUNTIME_POLL_WAIT_READABLE, 1u) ==
           RINRUNTIME_POLL_WAIT_FAILURE);
    assert(close(sockets[1]) == 0);
    return 0;
}
