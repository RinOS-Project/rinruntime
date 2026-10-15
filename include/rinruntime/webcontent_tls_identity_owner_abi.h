/* SPDX-License-Identifier: MIT */
/* Private authenticated WebContent-to-Browser TLS identity owner ABI. */
#ifndef RIN_SHARED_WEBCONTENT_TLS_IDENTITY_OWNER_ABI_H
#define RIN_SHARED_WEBCONTENT_TLS_IDENTITY_OWNER_ABI_H

#include "rinruntime/webcontent_service_abi.h"
#include "requestserver_tls_client_certificate_policy.h"

#define RIN_WEBCONTENT_CMD_TLS_IDENTITY_OWNER_V1 UINT32_C(37)
#define RIN_WEBCONTENT_TLS_IDENTITY_OWNER_VERSION UINT16_C(1)
#define RIN_WEBCONTENT_TLS_IDENTITY_OWNER_PROVIDE UINT16_C(1)
#define RIN_WEBCONTENT_TLS_IDENTITY_OWNER_SIGN UINT16_C(2)
#define RIN_WEBCONTENT_TLS_IDENTITY_OWNER_ACCEPTED UINT32_C(1)
#define RIN_WEBCONTENT_TLS_IDENTITY_OWNER_MAX_URL RIN_WEBCONTENT_URL_MAX
#define RIN_WEBCONTENT_TLS_IDENTITY_OWNER_MAX_SCHEMES UINT32_C(130)
#define RIN_WEBCONTENT_TLS_IDENTITY_OWNER_MAX_AUTHORITIES UINT32_C(4098)

typedef struct RinWebContentTlsIdentityOwnerRequestV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t operation;
    uint64_t request_id;
    uint64_t connection_generation;
    uint16_t signature_scheme;
    uint16_t reserved0;
    uint32_t url_size;
    uint32_t signature_algorithms_size;
    uint32_t signature_algorithms_cert_size;
    uint32_t certificate_authorities_size;
    uint32_t message_size;
    uint8_t capability[RINRUNTIME_TLS_CLIENT_CERTIFICATE_CAPABILITY_BYTES];
    uint32_t reserved1;
} RinWebContentTlsIdentityOwnerRequestV1;

typedef struct RinWebContentTlsIdentityOwnerResponseV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t operation;
    uint32_t result;
    uint32_t reserved0;
    uint64_t request_id;
    uint64_t connection_generation;
    uint16_t signature_scheme;
    uint16_t reserved1;
    uint32_t certificate_list_size;
    uint32_t capability_size;
    uint32_t signature_size;
    uint32_t reserved2;
} RinWebContentTlsIdentityOwnerResponseV1;

static inline int rin_webcontent_tls_identity_owner_request_valid(
    const RinWebContentTlsIdentityOwnerRequestV1* request,
    const uint8_t* trailing, size_t trailing_size)
{
    uint64_t expected_size;
    if (request == NULL || request->struct_size != sizeof(*request) ||
        request->version != RIN_WEBCONTENT_TLS_IDENTITY_OWNER_VERSION ||
        request->request_id == 0u || request->request_id == UINT64_MAX ||
        request->reserved0 != 0u || request->reserved1 != 0u ||
        (trailing == NULL && trailing_size != 0u))
        return 0;
    expected_size = (uint64_t)request->url_size +
        request->signature_algorithms_size +
        request->signature_algorithms_cert_size +
        request->certificate_authorities_size + request->message_size;
    if (expected_size != trailing_size) return 0;
    if (request->operation == RIN_WEBCONTENT_TLS_IDENTITY_OWNER_PROVIDE) {
        return request->connection_generation == 0u &&
            request->signature_scheme == 0u && request->url_size != 0u &&
            request->url_size < RIN_WEBCONTENT_TLS_IDENTITY_OWNER_MAX_URL &&
            request->signature_algorithms_size <=
                RIN_WEBCONTENT_TLS_IDENTITY_OWNER_MAX_SCHEMES &&
            request->signature_algorithms_cert_size <=
                RIN_WEBCONTENT_TLS_IDENTITY_OWNER_MAX_SCHEMES &&
            request->certificate_authorities_size <=
                RIN_WEBCONTENT_TLS_IDENTITY_OWNER_MAX_AUTHORITIES &&
            request->message_size == 0u &&
            rin_requestserver_tls_client_certificate_constraints_valid(
                trailing + request->url_size,
                request->signature_algorithms_size,
                trailing + request->url_size +
                    request->signature_algorithms_size,
                request->signature_algorithms_cert_size,
                trailing + request->url_size +
                    request->signature_algorithms_size +
                    request->signature_algorithms_cert_size,
                request->certificate_authorities_size);
    }
    if (request->operation == RIN_WEBCONTENT_TLS_IDENTITY_OWNER_SIGN) {
        return request->connection_generation != 0u &&
            request->connection_generation != UINT64_MAX &&
            request->signature_scheme != 0u && request->url_size == 0u &&
            request->signature_algorithms_size == 0u &&
            request->signature_algorithms_cert_size == 0u &&
            request->certificate_authorities_size == 0u &&
            request->message_size != 0u &&
            request->message_size <=
                RIN_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_MAX_TRANSCRIPT_BYTES &&
            rinruntime_tls_client_certificate_nonzero(
                request->capability, sizeof(request->capability));
    }
    return 0;
}

static inline int rin_webcontent_tls_identity_owner_response_valid(
    const RinWebContentTlsIdentityOwnerResponseV1* response,
    const uint8_t* trailing, size_t trailing_size,
    uint16_t expected_operation, uint64_t expected_request_id)
{
    uint64_t expected_size;
    if (response == NULL ||
        response->struct_size != sizeof(*response) ||
        response->version != RIN_WEBCONTENT_TLS_IDENTITY_OWNER_VERSION ||
        response->operation != expected_operation ||
        response->request_id != expected_request_id ||
        response->reserved0 != 0u || response->reserved1 != 0u ||
        response->reserved2 != 0u ||
        response->result > RIN_WEBCONTENT_TLS_IDENTITY_OWNER_ACCEPTED ||
        (trailing == NULL && trailing_size != 0u))
        return 0;
    expected_size = (uint64_t)response->certificate_list_size +
        response->capability_size + response->signature_size;
    if (expected_size != trailing_size) return 0;
    if (response->result == 0u)
        return response->connection_generation == 0u &&
            response->signature_scheme == 0u && trailing_size == 0u;
    if (expected_operation == RIN_WEBCONTENT_TLS_IDENTITY_OWNER_PROVIDE) {
#ifdef __cplusplus
        RinRuntimeTlsClientCertificateRequestV1 certificate_request{};
#else
        RinRuntimeTlsClientCertificateRequestV1 certificate_request = { 0 };
#endif
        certificate_request.struct_size = sizeof(certificate_request);
        certificate_request.version = RINRUNTIME_TLS_CLIENT_CERTIFICATE_VERSION;
        certificate_request.request_id = response->request_id;
        certificate_request.connection_generation =
            response->connection_generation;
        certificate_request.certificate_list = trailing;
        certificate_request.certificate_list_size =
            response->certificate_list_size;
        certificate_request.signer_capability =
            trailing + response->certificate_list_size;
        certificate_request.signer_capability_size = response->capability_size;
        return response->signature_scheme != 0u &&
            response->signature_size == 0u &&
            rinruntime_tls_client_certificate_request_valid(
                &certificate_request);
    }
    return expected_operation == RIN_WEBCONTENT_TLS_IDENTITY_OWNER_SIGN &&
        response->connection_generation != 0u &&
        response->connection_generation != UINT64_MAX &&
        response->signature_scheme != 0u &&
        response->certificate_list_size == 0u &&
        response->capability_size == 0u &&
        response->signature_size != 0u &&
        response->signature_size <=
            RIN_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_MAX_SIGNATURE_BYTES;
}

#endif /* RIN_SHARED_WEBCONTENT_TLS_IDENTITY_OWNER_ABI_H */
