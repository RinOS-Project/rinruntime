/* SPDX-License-Identifier: MIT */
/* RequestServer-side validation for the authenticated TLS client-certificate
 * IPC.  The IPC carries a wire certificate_list and an opaque signer
 * capability; private key material never crosses this boundary. */

#ifndef RIN_SHARED_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_POLICY_H
#define RIN_SHARED_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_POLICY_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../../public-base/libs/rinruntime/include/rinruntime/tls_client_certificate.h"

static inline int rin_requestserver_tls_client_certificate_ipc_valid(
    uint64_t expected_request_id,
    uint64_t expected_connection_generation,
    const uint8_t* certificate_list,
    size_t certificate_list_size,
    const uint8_t* signer_capability,
    size_t signer_capability_size)
{
    RinRuntimeTlsClientCertificateRequestV1 request;

    request.struct_size = sizeof(request);
    request.version = RINRUNTIME_TLS_CLIENT_CERTIFICATE_VERSION;
    request.request_id = expected_request_id;
    request.connection_generation = expected_connection_generation;
    request.certificate_list = certificate_list;
    request.certificate_list_size = (uint32_t)certificate_list_size;
    request.signer_capability = signer_capability;
    request.signer_capability_size = (uint32_t)signer_capability_size;

    if (expected_request_id == 0u || expected_request_id == UINT64_MAX ||
        expected_connection_generation == 0u ||
        expected_connection_generation == UINT64_MAX ||
        certificate_list_size > UINT32_MAX || signer_capability_size > UINT32_MAX)
        return 0;
    return rinruntime_tls_client_certificate_request_valid(&request);
}

static inline int rin_requestserver_tls_signature_vector_valid(
    const uint8_t* bytes, size_t size, int required)
{
    size_t offset;
    size_t end;
    uint16_t vector_size;
    if (size == 0u)
        return !required;
    if (bytes == NULL || size < 4u || size > 130u)
        return 0;
    vector_size = (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
    if ((size_t)vector_size != size - 2u || (vector_size & 1u) != 0u ||
        vector_size > 128u)
        return 0;
    offset = 2u;
    end = size;
    while (offset < end) {
        /* Preserve unknown SignatureScheme values. RFC 8446 requires a
         * receiver to ignore schemes it does not implement; selection below
         * separately admits only RinTLS-supported values. */
        offset += 2u;
    }
    return offset == end;
}

static inline int rin_requestserver_tls_certificate_authorities_valid(
    const uint8_t* bytes, size_t size)
{
    size_t offset;
    size_t end;
    uint16_t vector_size;
    if (size == 0u)
        return 1;
    if (bytes == NULL || size < 2u || size > 4098u)
        return 0;
    vector_size = (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
    if ((size_t)vector_size != size - 2u)
        return 0;
    offset = 2u;
    end = size;
    while (offset < end) {
        uint16_t name_size;
        if (end - offset < 2u)
            return 0;
        name_size = (uint16_t)(((uint16_t)bytes[offset] << 8) |
                               bytes[offset + 1u]);
        offset += 2u;
        if (name_size == 0u || (size_t)name_size > end - offset)
            return 0;
        offset += name_size;
    }
    return offset == end;
}

static inline int rin_requestserver_tls_client_certificate_constraints_valid(
    const uint8_t* signature_algorithms, size_t signature_algorithms_size,
    const uint8_t* signature_algorithms_cert,
    size_t signature_algorithms_cert_size,
    const uint8_t* certificate_authorities,
    size_t certificate_authorities_size)
{
    return rin_requestserver_tls_signature_vector_valid(
               signature_algorithms, signature_algorithms_size, 1) &&
           rin_requestserver_tls_signature_vector_valid(
               signature_algorithms_cert, signature_algorithms_cert_size, 0) &&
           rin_requestserver_tls_certificate_authorities_valid(
               certificate_authorities, certificate_authorities_size);
}

#define RIN_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_MAX_TRANSCRIPT_BYTES \
    RINRUNTIME_TLS_CLIENT_CERTIFICATE_TRANSCRIPT_MAX
#define RIN_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_MAX_SIGNATURE_BYTES \
    UINT32_C(512)

typedef int (*RinRequestServerTlsClientCertificateSignFunction)(
    void* context,
    const uint8_t capability[RINRUNTIME_TLS_CLIENT_CERTIFICATE_CAPABILITY_BYTES],
    uint64_t request_id, uint64_t connection_generation,
    uint16_t signature_scheme, const uint8_t* message, size_t message_size,
    uint8_t* signature, size_t signature_capacity, size_t* signature_size);

/* The key owner must authenticate the opaque capability and its exact
 * request/generation tuple before RequestServer copies a certificate list
 * into a live handshake session. This callback receives no private key or
 * certificate path. */
typedef int (*RinRequestServerTlsClientCertificateAuthorizeFunction)(
    void* context,
    const uint8_t capability[RINRUNTIME_TLS_CLIENT_CERTIFICATE_CAPABILITY_BYTES],
    uint64_t request_id, uint64_t connection_generation);

enum {
    RIN_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_IDLE = 0,
    RIN_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_BOUND = 1,
    RIN_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_HANDSHAKE_STARTED = 2,
    RIN_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_SIGNED = 3,
    RIN_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_FAILED = 4
};

/* RequestServer owns this bounded session until the TLS connection closes.
 * It copies the wire certificate_list and opaque capability before the IPC
 * buffers can be released; private-key bytes and callback pointers never
 * cross the IPC boundary. */
typedef struct RinRequestServerTlsClientCertificateSessionV1 {
    uint64_t request_id;
    uint64_t connection_generation;
    uint32_t certificate_list_size;
    uint32_t state;
    uint32_t signing;
    uint8_t certificate_list[RINRUNTIME_TLS_CLIENT_CERTIFICATE_CHAIN_MAX];
    uint8_t signer_capability[RINRUNTIME_TLS_CLIENT_CERTIFICATE_CAPABILITY_BYTES];
    RinRequestServerTlsClientCertificateSignFunction signer;
    void* signer_context;
} RinRequestServerTlsClientCertificateSessionV1;

static inline void
rin_requestserver_tls_client_certificate_session_clear_capability(
    RinRequestServerTlsClientCertificateSessionV1* session)
{
    size_t index;
    volatile uint8_t* bytes;
    if (session == NULL)
        return;
    bytes = (volatile uint8_t*)session->signer_capability;
    for (index = 0u;
         index < RINRUNTIME_TLS_CLIENT_CERTIFICATE_CAPABILITY_BYTES; ++index)
        bytes[index] = 0u;
}

static inline void rin_requestserver_tls_signature_clear(
    uint8_t* signature, size_t signature_capacity)
{
    size_t index;
    if (signature == NULL)
        return;
    if (signature_capacity >
        RIN_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_MAX_SIGNATURE_BYTES)
        signature_capacity =
            RIN_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_MAX_SIGNATURE_BYTES;
    for (index = 0u; index < signature_capacity; ++index)
        signature[index] = 0u;
}

/* The session callback receives caller-owned transcript, signature, and
 * length storage.  Do not clear or write one region while another argument
 * aliases it: an alias can otherwise change the transcript during signing or
 * overwrite the result length before the owner callback runs. */
static inline int rin_requestserver_tls_byte_ranges_overlap(
    const void* left, size_t left_size, const void* right, size_t right_size)
{
    uintptr_t left_begin;
    uintptr_t right_begin;
    uintptr_t max_value;

    if (left == NULL || right == NULL || left_size == 0u ||
        right_size == 0u)
        return 0;
    left_begin = (uintptr_t)left;
    right_begin = (uintptr_t)right;
    max_value = UINTPTR_MAX;
    if (left_begin > max_value - (uintptr_t)left_size ||
        right_begin > max_value - (uintptr_t)right_size)
        return 1;
    return left_begin < right_begin + (uintptr_t)right_size &&
           right_begin < left_begin + (uintptr_t)left_size;
}

static inline int rin_requestserver_tls_signature_scheme_supported(
    uint16_t signature_scheme)
{
    return signature_scheme == UINT16_C(0x0403) || /* ecdsa_secp256r1_sha256 */
           signature_scheme == UINT16_C(0x0503) || /* ecdsa_secp384r1_sha384 */
           signature_scheme == UINT16_C(0x0603) || /* ecdsa_secp521r1_sha512 */
           signature_scheme == UINT16_C(0x0804) || /* rsa_pss_rsae_sha256 */
           signature_scheme == UINT16_C(0x0805) || /* rsa_pss_rsae_sha384 */
           signature_scheme == UINT16_C(0x0806);   /* rsa_pss_rsae_sha512 */
}

static inline int rin_requestserver_tls_signature_scheme_offered(
    const uint8_t* signature_algorithms, size_t signature_algorithms_size,
    uint16_t signature_scheme)
{
    size_t offset;
    if (!rin_requestserver_tls_signature_scheme_supported(signature_scheme) ||
        !rin_requestserver_tls_signature_vector_valid(
            signature_algorithms, signature_algorithms_size, 1))
        return 0;
    for (offset = 2u; offset < signature_algorithms_size; offset += 2u) {
        if ((((uint16_t)signature_algorithms[offset] << 8) |
             signature_algorithms[offset + 1u]) == signature_scheme)
            return 1;
    }
    return 0;
}

static inline void rin_requestserver_tls_client_certificate_session_initialize(
    RinRequestServerTlsClientCertificateSessionV1* session)
{
    if (session != NULL) {
        rin_requestserver_tls_client_certificate_session_clear_capability(session);
        memset(session, 0, sizeof(*session));
    }
}

static inline int rin_requestserver_tls_client_certificate_session_bind(
    RinRequestServerTlsClientCertificateSessionV1* session,
    uint64_t request_id, uint64_t connection_generation,
    const uint8_t* certificate_list, size_t certificate_list_size,
    const uint8_t* signer_capability, size_t signer_capability_size,
    RinRequestServerTlsClientCertificateSignFunction signer,
    void* signer_context)
{
    if (session == NULL || signer == NULL || signer_context == NULL ||
        !rin_requestserver_tls_client_certificate_ipc_valid(
            request_id, connection_generation, certificate_list,
            certificate_list_size, signer_capability, signer_capability_size))
        return 0;
    rin_requestserver_tls_client_certificate_session_clear_capability(session);
    memset(session, 0, sizeof(*session));
    memcpy(session->certificate_list, certificate_list, certificate_list_size);
    memcpy(session->signer_capability, signer_capability,
           RINRUNTIME_TLS_CLIENT_CERTIFICATE_CAPABILITY_BYTES);
    session->request_id = request_id;
    session->connection_generation = connection_generation;
    session->certificate_list_size = (uint32_t)certificate_list_size;
    session->signer = signer;
    session->signer_context = signer_context;
    session->state = RIN_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_BOUND;
    return 1;
}

/* Production binding variant. Authorization is a separate authenticated
 * key-owner decision; a signer callback alone is not sufficient because an
 * untrusted caller could otherwise inject a borrowed callback/context. The
 * complete IPC envelope is validated before the owner callback is invoked. */
static inline int
rin_requestserver_tls_client_certificate_session_bind_authenticated(
    RinRequestServerTlsClientCertificateSessionV1* session,
    uint64_t request_id, uint64_t connection_generation,
    const uint8_t* certificate_list, size_t certificate_list_size,
    const uint8_t* signer_capability, size_t signer_capability_size,
    RinRequestServerTlsClientCertificateAuthorizeFunction authorize,
    void* authorize_context,
    RinRequestServerTlsClientCertificateSignFunction signer,
    void* signer_context)
{
    if (session == NULL || authorize == NULL || authorize_context == NULL ||
        !rin_requestserver_tls_client_certificate_ipc_valid(
            request_id, connection_generation, certificate_list,
            certificate_list_size, signer_capability, signer_capability_size))
        return 0;
    if (authorize(authorize_context, signer_capability, request_id,
                  connection_generation) != 0)
        return 0;
    return rin_requestserver_tls_client_certificate_session_bind(
        session, request_id, connection_generation, certificate_list,
        certificate_list_size, signer_capability, signer_capability_size,
        signer, signer_context);
}

static inline int rin_requestserver_tls_client_certificate_session_start(
    RinRequestServerTlsClientCertificateSessionV1* session)
{
    if (session == NULL ||
        session->state != RIN_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_BOUND)
        return 0;
    session->state = RIN_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_HANDSHAKE_STARTED;
    return 1;
}

static inline int rin_requestserver_tls_client_certificate_session_sign(
    RinRequestServerTlsClientCertificateSessionV1* session,
    uint16_t signature_scheme, const uint8_t* message, size_t message_size,
    uint8_t* signature, size_t signature_capacity, size_t* signature_size)
{
    size_t written = 0u;
    int result;
    const int aliased =
        rin_requestserver_tls_byte_ranges_overlap(
            message, message_size, signature, signature_capacity) ||
        rin_requestserver_tls_byte_ranges_overlap(
            message, message_size, signature_size, sizeof(*signature_size)) ||
        rin_requestserver_tls_byte_ranges_overlap(
            signature, signature_capacity, signature_size,
            sizeof(*signature_size));
    if (aliased) {
        if (session != NULL) {
            rin_requestserver_tls_client_certificate_session_clear_capability(
                session);
            session->state = RIN_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_FAILED;
        }
        return -1;
    }
    if (signature_size != NULL) *signature_size = 0u;
    if (session == NULL ||
        session->state != RIN_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_HANDSHAKE_STARTED ||
        session->signing != 0u ||
        !rin_requestserver_tls_signature_scheme_supported(signature_scheme) ||
        session->signer == NULL || message == NULL || message_size == 0u ||
        message_size > RIN_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_MAX_TRANSCRIPT_BYTES ||
        signature == NULL || signature_capacity == 0u ||
        signature_capacity > RIN_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_MAX_SIGNATURE_BYTES ||
        signature_size == NULL) {
        rin_requestserver_tls_signature_clear(signature, signature_capacity);
        if (session != NULL) {
            rin_requestserver_tls_client_certificate_session_clear_capability(
                session);
            session->state = RIN_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_FAILED;
        }
        return -1;
    }
    session->signing = 1u;
    result = session->signer(
        session->signer_context, session->signer_capability,
        session->request_id, session->connection_generation, signature_scheme,
        message, message_size, signature, signature_capacity, &written);
    session->signing = 0u;
    if (session->state != RIN_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_HANDSHAKE_STARTED ||
        result != 0 || written == 0u || written > signature_capacity) {
        rin_requestserver_tls_signature_clear(signature, signature_capacity);
        rin_requestserver_tls_client_certificate_session_clear_capability(
            session);
        session->state = RIN_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_FAILED;
        return -1;
    }
    *signature_size = written;
    rin_requestserver_tls_client_certificate_session_clear_capability(session);
    session->state = RIN_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_SIGNED;
    return 0;
}

static inline void rin_requestserver_tls_client_certificate_session_reset(
    RinRequestServerTlsClientCertificateSessionV1* session)
{
    if (session != NULL) {
        rin_requestserver_tls_client_certificate_session_clear_capability(session);
        memset(session, 0, sizeof(*session));
    }
}

#endif /* RIN_SHARED_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_POLICY_H */
