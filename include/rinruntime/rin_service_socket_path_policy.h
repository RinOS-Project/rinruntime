/* SPDX-License-Identifier: MIT */
#ifndef RIN_SHARED_SERVICE_SOCKET_PATH_POLICY_H
#define RIN_SHARED_SERVICE_SOCKET_PATH_POLICY_H

#include <stddef.h>
#include <stdint.h>

#define RIN_SERVICE_SOCKET_PATH_POLICY_V1 UINT32_C(0x00010000)
#define RIN_SERVICE_SOCKET_PATH_MAX 107u /* sockaddr_un.sun_path - NUL */
#define RIN_SERVICE_SOCKET_SERVICE_MAX 32u

static inline int rin_service_socket_component_char(char value)
{
    return (value >= 'a' && value <= 'z') ||
           (value >= '0' && value <= '9') || value == '-';
}

/* Validate the exact private service namespace before unlink/bind.  This is
 * deliberately header-only so every daemon gets the same admission without
 * a libc or service-manager dependency in its freestanding image. */
static inline int rin_service_socket_path_valid(const char* path,
                                                const char* service)
{
    static const char prefix[] = "/run/rin/";
    static const char suffix[] = ".sock";
    size_t path_length = 0u;
    size_t service_length = 0u;
    size_t index;

    if (!path || !service) return 0;
    while (path[path_length] != '\0') {
        if (path_length >= RIN_SERVICE_SOCKET_PATH_MAX) return 0;
        ++path_length;
    }
    while (service[service_length] != '\0') {
        if (service_length >= RIN_SERVICE_SOCKET_SERVICE_MAX) return 0;
        ++service_length;
    }
    if (service_length == 0u || service[0] == '-' ||
        service[service_length - 1u] == '-')
        return 0;
    if (path_length != (sizeof(prefix) - 1u) + service_length +
                          (sizeof(suffix) - 1u))
        return 0;
    for (index = 0u; index < sizeof(prefix) - 1u; ++index)
        if (path[index] != prefix[index]) return 0;
    for (index = 0u; index < service_length; ++index) {
        if (!rin_service_socket_component_char(service[index]) ||
            path[(sizeof(prefix) - 1u) + index] != service[index])
            return 0;
    }
    for (index = 0u; index < sizeof(suffix) - 1u; ++index) {
        if (path[(sizeof(prefix) - 1u) + service_length + index] !=
            suffix[index])
            return 0;
    }
    return 1;
}

#endif /* RIN_SHARED_SERVICE_SOCKET_PATH_POLICY_H */
