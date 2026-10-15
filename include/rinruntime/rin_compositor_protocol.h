/* SPDX-License-Identifier: MIT */
/*
 * Compatibility include.  The complete compositor wire contract is public
 * in RinOS-SDK; keep the legacy socket ABI transitively available to
 * OS-Core code that historically included this header.
 */
#ifndef RINOS_COMPOSITOR_PROTOCOL_H
#define RINOS_COMPOSITOR_PROTOCOL_H
#include <rin/gui/compositor_protocol.h>
#include <rin/net/socket_abi.h>
/* OS-Core transport endpoint; the wire contract above remains portable. */
#define RIN_COMPOSITOR_SOCKET_PATH "/run/rin/compositor.sock"
#endif
