/* SPDX-License-Identifier: MIT */
/* RinOS RequestServer direct-transport completion classification. */

#ifndef RIN_SHARED_RINOS_HTTP_TRANSPORT_POLICY_H
#define RIN_SHARED_RINOS_HTTP_TRANSPORT_POLICY_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

enum {
    RIN_HTTP_TRANSPORT_RESULT_OK = 0,
    RIN_HTTP_TRANSPORT_RESULT_MALFORMED_RESPONSE = 8,
    RIN_HTTP_TRANSPORT_RESULT_TIMEOUT = 28,
    RIN_HTTP_TRANSPORT_RESULT_INCOMPLETE_RESPONSE = 56,
    RIN_HTTP_TRANSPORT_MAX_LINE_BYTES = 16 * 1024
};

typedef enum RinHttpTransportFailureClass {
    RIN_HTTP_TRANSPORT_FAILURE_UNKNOWN = 0,
    RIN_HTTP_TRANSPORT_FAILURE_TIMEOUT = 1,
    RIN_HTTP_TRANSPORT_FAILURE_INCOMPLETE_RESPONSE = 2
} RinHttpTransportFailureClass;

/* Result values are private to the RinOS direct HTTP transport.  Keep their
 * conversion at the RequestServer boundary so WebContent receives only the
 * stable Requests::NetworkError vocabulary. */
static inline RinHttpTransportFailureClass
rin_http_transport_failure_classify(int result_code)
{
    if (result_code == RIN_HTTP_TRANSPORT_RESULT_TIMEOUT)
        return RIN_HTTP_TRANSPORT_FAILURE_TIMEOUT;
    if (result_code == RIN_HTTP_TRANSPORT_RESULT_INCOMPLETE_RESPONSE)
        return RIN_HTTP_TRANSPORT_FAILURE_INCOMPLETE_RESPONSE;
    return RIN_HTTP_TRANSPORT_FAILURE_UNKNOWN;
}

/* The direct transport is event-driven.  A readiness notification can race
 * with another consumer, so these POSIX retry conditions do not terminate an
 * HTTP request.  Every other read error must complete the request instead of
 * leaving its caller indefinitely loading. */
static inline int
rin_http_transport_errno_is_retryable(int error_code)
{
    return error_code == EINTR || error_code == EAGAIN ||
        error_code == EWOULDBLOCK;
}

/* Append exactly one HTTP chunk-size hexadecimal digit.  Reject both syntax
 * errors and arithmetic overflow; callers must never turn either into a
 * zero-sized terminal chunk. */
static inline int
rin_http_transport_hex_size_append(size_t previous, unsigned char character,
    size_t* next)
{
    size_t digit;

    if (character >= '0' && character <= '9')
        digit = (size_t)(character - '0');
    else if (character >= 'a' && character <= 'f')
        digit = (size_t)(character - 'a') + 10u;
    else if (character >= 'A' && character <= 'F')
        digit = (size_t)(character - 'A') + 10u;
    else
        return 0;

    if (previous > (SIZE_MAX - digit) / 16u)
        return 0;
    *next = previous * 16u + digit;
    return 1;
}

/* A declared Content-Length is exact.  Check before exposing data to the
 * caller so a surplus byte cannot be treated as body data or a following
 * response. */
static inline int
rin_http_transport_body_append_is_within_declared_length(size_t received,
    size_t appended, size_t declared_length)
{
    return received <= declared_length && appended <= declared_length - received;
}

/* Includes CR/LF while a line is being assembled.  The test is deliberately
 * strict-before-append, so an unterminated peer line cannot allocate beyond
 * this per-request limit. */
static inline int
rin_http_transport_line_byte_fits(size_t buffered_bytes)
{
    return buffered_bytes < RIN_HTTP_TRANSPORT_MAX_LINE_BYTES;
}

#endif /* RIN_SHARED_RINOS_HTTP_TRANSPORT_POLICY_H */
