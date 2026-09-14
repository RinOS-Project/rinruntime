/* SPDX-License-Identifier: MIT */
/* Fail-closed admission and publication policy for user-space downloads. */

#ifndef RINRUNTIME_DOWNLOAD_POLICY_H
#define RINRUNTIME_DOWNLOAD_POLICY_H

#include <stddef.h>
#include <stdint.h>

#include "../../../../libs/rinuri/include/rinuri/uri.h"

#define RIN_BROWSER_DOWNLOAD_MAX_URL_BYTES UINT32_C(2047)
#define RIN_BROWSER_DOWNLOAD_MAX_FILENAME_BYTES UINT32_C(255)
#define RIN_BROWSER_DOWNLOAD_MAX_BYTES (UINT64_C(128) * 1024u * 1024u)
#define RIN_BROWSER_DOWNLOAD_MAX_CHUNK_BYTES UINT32_C(65536)
#define RIN_BROWSER_DOWNLOAD_UNKNOWN_CONTENT_LENGTH UINT64_MAX

#define RIN_BROWSER_DOWNLOAD_ADMISSION_AUTHENTICATED_HTTPS UINT32_C(1)
#define RIN_BROWSER_DOWNLOAD_ADMISSION_FILE_PORTAL         UINT32_C(2)
#define RIN_BROWSER_DOWNLOAD_ADMISSION_CONTENT_LENGTH      UINT32_C(4)
#define RIN_BROWSER_DOWNLOAD_ADMISSION_REQUIRED                         \
    (RIN_BROWSER_DOWNLOAD_ADMISSION_AUTHENTICATED_HTTPS |              \
     RIN_BROWSER_DOWNLOAD_ADMISSION_FILE_PORTAL |                      \
     RIN_BROWSER_DOWNLOAD_ADMISSION_CONTENT_LENGTH)

#define RIN_BROWSER_DOWNLOAD_PUBLISH_FILE_SYNC       UINT32_C(1)
#define RIN_BROWSER_DOWNLOAD_PUBLISH_READBACK_MATCH  UINT32_C(2)
#define RIN_BROWSER_DOWNLOAD_PUBLISH_ATOMIC_RENAME   UINT32_C(4)
#define RIN_BROWSER_DOWNLOAD_PUBLISH_DIRECTORY_SYNC  UINT32_C(8)
#define RIN_BROWSER_DOWNLOAD_PUBLISH_REQUIRED                        \
    (RIN_BROWSER_DOWNLOAD_PUBLISH_FILE_SYNC |                       \
     RIN_BROWSER_DOWNLOAD_PUBLISH_READBACK_MATCH |                  \
     RIN_BROWSER_DOWNLOAD_PUBLISH_ATOMIC_RENAME |                   \
     RIN_BROWSER_DOWNLOAD_PUBLISH_DIRECTORY_SYNC)

typedef enum RinBrowserDownloadPolicyResult {
    RIN_BROWSER_DOWNLOAD_POLICY_OK = 0,
    RIN_BROWSER_DOWNLOAD_POLICY_INVALID_ARGUMENT = -1,
    RIN_BROWSER_DOWNLOAD_POLICY_UNSAFE_URL = -2,
    RIN_BROWSER_DOWNLOAD_POLICY_UNSAFE_FILENAME = -3,
    RIN_BROWSER_DOWNLOAD_POLICY_SIZE_REJECTED = -4,
    RIN_BROWSER_DOWNLOAD_POLICY_BACKEND_UNAVAILABLE = -5,
    RIN_BROWSER_DOWNLOAD_POLICY_TRANSFER_FAILED = -6,
    RIN_BROWSER_DOWNLOAD_POLICY_DURABILITY_FAILED = -7,
    RIN_BROWSER_DOWNLOAD_POLICY_CANCELLED = -8,
    RIN_BROWSER_DOWNLOAD_POLICY_BACKEND_PROTOCOL = -9
} RinBrowserDownloadPolicyResult;

typedef struct RinBrowserDownloadAdmissionV1 {
    const char* url;
    size_t url_size;
    const char* filename;
    size_t filename_size;
    uint64_t content_length;
    uint32_t flags;
} RinBrowserDownloadAdmissionV1;

static inline int rin_browser_download_content_length_admissible(
    uint64_t content_length)
{
    return content_length == RIN_BROWSER_DOWNLOAD_UNKNOWN_CONTENT_LENGTH ||
           (content_length != 0u &&
            content_length <= RIN_BROWSER_DOWNLOAD_MAX_BYTES);
}

static inline int rin_browser_download_dns_host_valid(RinUriSpan host)
{
    size_t index;
    size_t label_begin = 0u;
    if (host.size == 0u || host.size > 253u || !host.data) return 0;
    for (index = 0u; index <= host.size; ++index) {
        if (index == host.size || host.data[index] == '.') {
            size_t label_size = index - label_begin;
            if (label_size == 0u || label_size > 63u ||
                host.data[label_begin] == '-' || host.data[index - 1u] == '-')
                return 0;
            label_begin = index + 1u;
            continue;
        }
        if (!((host.data[index] >= 'a' && host.data[index] <= 'z') ||
              (host.data[index] >= 'A' && host.data[index] <= 'Z') ||
              (host.data[index] >= '0' && host.data[index] <= '9') ||
              host.data[index] == '-')) return 0;
    }
    return 1;
}

static inline int rin_browser_download_lowercase_https(RinUriSpan scheme)
{
    return scheme.size == 5u && scheme.data && scheme.data[0] == 'h' &&
           scheme.data[1] == 't' && scheme.data[2] == 't' &&
           scheme.data[3] == 'p' && scheme.data[4] == 's';
}

static inline int rin_browser_download_url_valid(const char* url, size_t size)
{
    RinUri parsed;
    if (!url || size <= 8u || size > RIN_BROWSER_DOWNLOAD_MAX_URL_BYTES ||
        rin_uri_parse(url, size, &parsed) != RIN_URI_OK ||
        !rin_browser_download_lowercase_https(parsed.scheme) ||
        !parsed.has_authority || parsed.host.size == 0u || parsed.has_userinfo ||
        (parsed.port.size != 0u && parsed.port_number == 0u))
        return 0;
    if (parsed.host_kind == RIN_URI_HOST_REG_NAME)
        return rin_browser_download_dns_host_valid(parsed.host);
    return parsed.host_kind == RIN_URI_HOST_IPV4 ||
           parsed.host_kind == RIN_URI_HOST_IPV6;
}

static inline int rin_browser_download_filename_valid(const char* name,
                                                      size_t size)
{
    size_t index = 0u;
    if (!name || size == 0u ||
        size > RIN_BROWSER_DOWNLOAD_MAX_FILENAME_BYTES ||
        (size == 1u && name[0] == '.') ||
        (size == 2u && name[0] == '.' && name[1] == '.') ||
        name[0] == ' ' || name[size - 1u] == ' ' || name[size - 1u] == '.')
        return 0;

    while (index < size) {
        unsigned char first = (unsigned char)name[index];
        uint32_t codepoint;
        size_t count;
        size_t continuation;
        if (first == 0u || first <= 0x1fu || first == 0x7fu || first == '/' ||
            first == '\\' || first == ':')
            return 0;
        if (first < 0x80u) {
            ++index;
            continue;
        }
        if (first >= 0xc2u && first <= 0xdfu) {
            codepoint = first & 0x1fu;
            count = 2u;
        } else if (first >= 0xe0u && first <= 0xefu) {
            codepoint = first & 0x0fu;
            count = 3u;
        } else if (first >= 0xf0u && first <= 0xf4u) {
            codepoint = first & 0x07u;
            count = 4u;
        } else {
            return 0;
        }
        if (count > size - index) return 0;
        for (continuation = 1u; continuation < count; ++continuation) {
            unsigned char value = (unsigned char)name[index + continuation];
            if ((value & 0xc0u) != 0x80u) return 0;
            codepoint = (codepoint << 6u) | (uint32_t)(value & 0x3fu);
        }
        if ((count == 3u && codepoint < 0x800u) ||
            (count == 4u && codepoint < 0x10000u) ||
            codepoint > 0x10ffffu ||
            (codepoint >= 0xd800u && codepoint <= 0xdfffu) ||
            (codepoint >= 0x80u && codepoint <= 0x9fu) ||
            codepoint == 0x2028u || codepoint == 0x2029u ||
            (codepoint >= 0x202au && codepoint <= 0x202eu) ||
            (codepoint >= 0x2066u && codepoint <= 0x2069u) ||
            codepoint == 0xfeffu)
            return 0;
        index += count;
    }
    return 1;
}

static inline RinBrowserDownloadPolicyResult
rin_browser_download_admit_with_length_mode(
    const RinBrowserDownloadAdmissionV1* request, int allow_unknown_length)
{
    if (!request) return RIN_BROWSER_DOWNLOAD_POLICY_INVALID_ARGUMENT;
    if (request->flags != RIN_BROWSER_DOWNLOAD_ADMISSION_REQUIRED)
        return RIN_BROWSER_DOWNLOAD_POLICY_BACKEND_UNAVAILABLE;
    if (!rin_browser_download_url_valid(request->url, request->url_size))
        return RIN_BROWSER_DOWNLOAD_POLICY_UNSAFE_URL;
    if (!rin_browser_download_filename_valid(request->filename,
                                             request->filename_size))
        return RIN_BROWSER_DOWNLOAD_POLICY_UNSAFE_FILENAME;
    if (!rin_browser_download_content_length_admissible(request->content_length) ||
        (!allow_unknown_length && request->content_length ==
             RIN_BROWSER_DOWNLOAD_UNKNOWN_CONTENT_LENGTH))
        return RIN_BROWSER_DOWNLOAD_POLICY_SIZE_REJECTED;
    return RIN_BROWSER_DOWNLOAD_POLICY_OK;
}

static inline RinBrowserDownloadPolicyResult
rin_browser_download_admit(const RinBrowserDownloadAdmissionV1* request)
{
    return rin_browser_download_admit_with_length_mode(request, 0);
}

static inline RinBrowserDownloadPolicyResult
rin_browser_download_stream_admit(const RinBrowserDownloadAdmissionV1* request)
{
    return rin_browser_download_admit_with_length_mode(request, 1);
}

static inline RinBrowserDownloadPolicyResult
rin_browser_download_accept_chunk(uint64_t total_size, uint64_t committed_size,
                                  uint32_t requested_size, int64_t backend_result,
                                  uint64_t* next_size)
{
    if (next_size) *next_size = 0u;
    if (!next_size || total_size == 0u ||
        total_size > RIN_BROWSER_DOWNLOAD_MAX_BYTES ||
        committed_size > total_size || requested_size == 0u ||
        requested_size > RIN_BROWSER_DOWNLOAD_MAX_CHUNK_BYTES ||
        (uint64_t)requested_size > total_size - committed_size ||
        backend_result < 0 || (uint64_t)backend_result != requested_size)
        return RIN_BROWSER_DOWNLOAD_POLICY_TRANSFER_FAILED;
    *next_size = committed_size + requested_size;
    return RIN_BROWSER_DOWNLOAD_POLICY_OK;
}

static inline RinBrowserDownloadPolicyResult
rin_browser_download_accept_stream_chunk(uint64_t declared_length,
                                         uint64_t committed_size,
                                         uint32_t requested_size,
                                         int64_t backend_result,
                                         uint64_t* next_size)
{
    if (declared_length != RIN_BROWSER_DOWNLOAD_UNKNOWN_CONTENT_LENGTH)
        return rin_browser_download_accept_chunk(
            declared_length, committed_size, requested_size, backend_result,
            next_size);
    if (next_size) *next_size = 0u;
    if (!next_size || committed_size > RIN_BROWSER_DOWNLOAD_MAX_BYTES ||
        requested_size == 0u ||
        requested_size > RIN_BROWSER_DOWNLOAD_MAX_CHUNK_BYTES ||
        (uint64_t)requested_size >
            RIN_BROWSER_DOWNLOAD_MAX_BYTES - committed_size ||
        backend_result < 0 || (uint64_t)backend_result != requested_size)
        return RIN_BROWSER_DOWNLOAD_POLICY_TRANSFER_FAILED;
    *next_size = committed_size + requested_size;
    return RIN_BROWSER_DOWNLOAD_POLICY_OK;
}

static inline RinBrowserDownloadPolicyResult
rin_browser_download_publish(uint64_t total_size, uint64_t committed_size,
                             uint32_t flags)
{
    if (total_size == 0u || total_size > RIN_BROWSER_DOWNLOAD_MAX_BYTES ||
        committed_size != total_size ||
        flags != RIN_BROWSER_DOWNLOAD_PUBLISH_REQUIRED)
        return RIN_BROWSER_DOWNLOAD_POLICY_DURABILITY_FAILED;
    return RIN_BROWSER_DOWNLOAD_POLICY_OK;
}

#endif /* RINRUNTIME_DOWNLOAD_POLICY_H */
