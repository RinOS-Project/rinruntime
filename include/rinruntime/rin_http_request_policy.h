/* SPDX-License-Identifier: MIT */

#ifndef RIN_HTTP_REQUEST_POLICY_H
#define RIN_HTTP_REQUEST_POLICY_H

/* Small, allocation-free admission helpers shared by the legacy HTTP
 * request facades.  The transport still owns URL resolution and TLS policy;
 * this header only prevents malformed request metadata from reaching either
 * owner. */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline int rin_http_request_policy_is_token_char(unsigned char value)
{
    return (value >= (unsigned char)'0' && value <= (unsigned char)'9') ||
           (value >= (unsigned char)'A' && value <= (unsigned char)'Z') ||
           (value >= (unsigned char)'a' && value <= (unsigned char)'z') ||
           value == (unsigned char)'!' || value == (unsigned char)'#' ||
           value == (unsigned char)'$' || value == (unsigned char)'%' ||
           value == (unsigned char)'&' || value == (unsigned char) '\'' ||
           value == (unsigned char)'*' || value == (unsigned char)'+' ||
           value == (unsigned char)'-' || value == (unsigned char)'.' ||
           value == (unsigned char)'^' || value == (unsigned char)'_' ||
           value == (unsigned char)'`' || value == (unsigned char)'|' ||
           value == (unsigned char)'~';
}

static inline int rin_http_request_policy_validate_header(
    const char* key, size_t key_capacity,
    const char* value, size_t value_capacity)
{
    size_t index;
    size_t key_length = 0u;
    size_t value_length = 0u;

    if (!key || !value || key_capacity == 0u || value_capacity == 0u)
        return 0;
    while (key_length < key_capacity && key[key_length] != '\0') ++key_length;
    while (value_length < value_capacity && value[value_length] != '\0')
        ++value_length;
    if (key_length == 0u || key_length == key_capacity ||
        value_length == value_capacity)
        return 0;
    for (index = 0u; index < key_length; ++index) {
        if (!rin_http_request_policy_is_token_char(
                (unsigned char)key[index]))
            return 0;
    }
    for (index = 0u; index < value_length; ++index) {
        unsigned char character = (unsigned char)value[index];
        /* HTAB is legal optional whitespace; all other controls are not. */
        if (character < 0x20u && character != 0x09u) return 0;
        if (character == 0x7fu) return 0;
    }
    return 1;
}

static inline int rin_http_request_policy_validate_url(
    const char* url, size_t capacity)
{
    const char* authority;
    const char* cursor;
    size_t length = 0u;
    size_t authority_length = 0u;

    if (!url || capacity == 0u) return 0;
    while (length < capacity && url[length] != '\0') ++length;
    if (length == 0u || length == capacity) return 0;
    if ((length < 7u || url[0] != 'h' || url[1] != 't' ||
         url[2] != 't' || url[3] != 'p' || url[4] != ':' ||
         url[5] != '/' || url[6] != '/') &&
        (length < 8u || url[0] != 'h' || url[1] != 't' ||
         url[2] != 't' || url[3] != 'p' || url[4] != 's' ||
         url[5] != ':' || url[6] != '/' || url[7] != '/'))
        return 0;
    authority = url + (url[4] == 's' ? 8u : 7u);
    cursor = authority;
    while ((size_t)(cursor - url) < length && *cursor != '/' &&
           *cursor != '?' && *cursor != '#') {
        unsigned char character = (unsigned char)*cursor;
        if (character <= 0x20u || character == 0x7fu) return 0;
        ++cursor;
    }
    authority_length = (size_t)(cursor - authority);
    if (authority_length == 0u) return 0;
    /* A fragment is a client-side reference and must never reach the wire. */
    for (cursor = url; (size_t)(cursor - url) < length; ++cursor)
        if (*cursor == '#') return 0;
    return 1;
}

#ifdef __cplusplus
}
#endif

#endif /* RIN_HTTP_REQUEST_POLICY_H */
