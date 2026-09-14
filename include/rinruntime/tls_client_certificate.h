/* SPDX-License-Identifier: MIT */
/* Public, backend-independent admission for TLS client-certificate
 * capabilities. Private keys never cross this boundary. */

#ifndef RINRUNTIME_TLS_CLIENT_CERTIFICATE_H
#define RINRUNTIME_TLS_CLIENT_CERTIFICATE_H

#include <stddef.h>
#include <stdint.h>

#define RINRUNTIME_TLS_CLIENT_CERTIFICATE_VERSION UINT32_C(1)
#define RINRUNTIME_TLS_CLIENT_CERTIFICATE_CHAIN_MAX (UINT32_C(16) * UINT32_C(1024))
#define RINRUNTIME_TLS_CLIENT_CERTIFICATE_CAPABILITY_BYTES UINT32_C(32)
#define RINRUNTIME_TLS_CLIENT_CERTIFICATE_TRANSCRIPT_MAX (UINT32_C(16) * UINT32_C(1024))

/* A capability request carries only a TLS wire certificate_list and an
 * opaque signer capability issued by the authenticated key owner. */
typedef struct RinRuntimeTlsClientCertificateRequestV1 {
    uint32_t struct_size;
    uint32_t version;
    uint64_t request_id;
    uint64_t connection_generation;
    const uint8_t* certificate_list;
    uint32_t certificate_list_size;
    const uint8_t* signer_capability;
    uint32_t signer_capability_size;
} RinRuntimeTlsClientCertificateRequestV1;

static inline int rinruntime_tls_client_certificate_nonzero(
    const uint8_t* bytes, size_t size)
{
    size_t index;
    uint8_t value = 0u;
    if (bytes == NULL || size == 0u) return 0;
    for (index = 0u; index < size; ++index) value |= bytes[index];
    return value != 0u;
}

/* CertificateEntry.extensions is a vector of uint16 type, uint16 length,
 * and bounded data. Extension semantics belong to RinTLS. */
static inline int rinruntime_tls_client_certificate_extensions_valid(
    const uint8_t* bytes, size_t size)
{
    size_t offset = 0u;
    if (bytes == NULL && size != 0u) return 0;
    while (offset < size) {
        uint32_t extension_size;
        if (size - offset < 4u) return 0;
        extension_size = ((uint32_t)bytes[offset + 2u] << 8) |
                         (uint32_t)bytes[offset + 3u];
        offset += 4u;
        if ((size_t)extension_size > size - offset) return 0;
        offset += (size_t)extension_size;
    }
    return offset == size;
}

/* Validate the TLS 1.3 Certificate message certificate_list framing without
 * interpreting DER. This prevents truncation and legacy list shapes at IPC
 * admission; X.509 semantics remain the TLS backend's responsibility. */
static inline int rinruntime_tls_client_certificate_list_valid(
    const uint8_t* bytes, size_t size)
{
    size_t offset;
    size_t certificate_count = 0u;
    uint32_t total;
    if (bytes == NULL || size < 6u ||
        size > RINRUNTIME_TLS_CLIENT_CERTIFICATE_CHAIN_MAX)
        return 0;
    total = ((uint32_t)bytes[0] << 16) | ((uint32_t)bytes[1] << 8) |
            (uint32_t)bytes[2];
    if ((size_t)total != size - 3u) return 0;
    offset = 3u;
    while (offset < size) {
        uint32_t certificate_size;
        uint32_t extensions_size;
        if (size - offset < 3u) return 0;
        certificate_size = ((uint32_t)bytes[offset] << 16) |
                           ((uint32_t)bytes[offset + 1u] << 8) |
                           (uint32_t)bytes[offset + 2u];
        offset += 3u;
        if (certificate_size == 0u ||
            (size_t)certificate_size > size - offset)
            return 0;
        offset += (size_t)certificate_size;
        if (size - offset < 2u) return 0;
        extensions_size = ((uint32_t)bytes[offset] << 8) |
                          (uint32_t)bytes[offset + 1u];
        offset += 2u;
        if ((size_t)extensions_size > size - offset ||
            !rinruntime_tls_client_certificate_extensions_valid(
                bytes + offset, extensions_size))
            return 0;
        offset += (size_t)extensions_size;
        ++certificate_count;
    }
    return certificate_count != 0u && offset == size;
}

static inline int rinruntime_tls_client_certificate_request_valid(
    const RinRuntimeTlsClientCertificateRequestV1* request)
{
    if (request == NULL || request->struct_size < sizeof(*request) ||
        request->version != RINRUNTIME_TLS_CLIENT_CERTIFICATE_VERSION ||
        request->request_id == 0u || request->connection_generation == 0u ||
        !rinruntime_tls_client_certificate_list_valid(
            request->certificate_list, request->certificate_list_size) ||
        request->signer_capability_size !=
            RINRUNTIME_TLS_CLIENT_CERTIFICATE_CAPABILITY_BYTES ||
        !rinruntime_tls_client_certificate_nonzero(
            request->signer_capability, request->signer_capability_size))
        return 0;
    return 1;
}

/* Constant-time comparison for an adapter matching a response to the
 * capability it issued for the same request/generation. */
static inline int rinruntime_tls_client_certificate_capability_equal(
    const uint8_t* left, const uint8_t* right, size_t size)
{
    size_t index;
    uint8_t difference = 0u;
    if (left == NULL || right == NULL || size == 0u) return 0;
    for (index = 0u; index < size; ++index) difference |= left[index] ^ right[index];
    return difference == 0u;
}

#endif /* RINRUNTIME_TLS_CLIENT_CERTIFICATE_H */
