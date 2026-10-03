/* SPDX-License-Identifier: MIT */

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <stdexcept>

#include "../include/rinruntime/tls_client_certificate_binding.hpp"

namespace {

struct SignContext {
    std::uint8_t capability = 0u;
    std::uint64_t requestId = 0u;
    std::uint64_t generation = 0u;
};

int sign(void* opaque,
         const std::uint8_t capability[RINRUNTIME_TLS_CLIENT_CERTIFICATE_CAPABILITY_BYTES],
         std::uint64_t request_id, std::uint64_t connection_generation,
         std::uint16_t signature_scheme, const std::uint8_t* message,
         std::size_t message_length, std::uint8_t* signature,
         std::size_t signature_capacity, std::size_t* signature_length) {
    auto* context = static_cast<SignContext*>(opaque);
    if (context == nullptr || capability == nullptr ||
        capability[0] != context->capability || request_id != context->requestId ||
        connection_generation != context->generation || signature_scheme != 0x0403u ||
        message == nullptr || message_length != 3u || signature == nullptr ||
        signature_capacity < 3u || signature_length == nullptr)
        return -1;
    signature[0] = message[0] ^ 0x5au;
    signature[1] = message[1] ^ 0xa5u;
    signature[2] = message[2] ^ 0x3cu;
    *signature_length = 3u;
    return 0;
}

int stateless_sign(
    void* context,
    const std::uint8_t capability[RINRUNTIME_TLS_CLIENT_CERTIFICATE_CAPABILITY_BYTES],
    std::uint64_t, std::uint64_t, std::uint16_t signature_scheme,
    const std::uint8_t* message, std::size_t message_length,
    std::uint8_t* signature, std::size_t signature_capacity,
    std::size_t* signature_length) {
    if (context != nullptr || capability == nullptr ||
        signature_scheme != 0x0403u || message == nullptr ||
        message_length != 3u || signature == nullptr ||
        signature_capacity < 3u || signature_length == nullptr)
        return -1;
    signature[0] = message[0] ^ capability[0];
    signature[1] = message[1] ^ capability[1];
    signature[2] = message[2] ^ capability[2];
    *signature_length = 3u;
    return 0;
}

int install(void* context, const void* certificate_list,
            std::size_t certificate_list_size,
            int (*signer)(void*, std::uint16_t, const std::uint8_t*,
                          std::size_t, std::uint8_t*, std::size_t,
                          std::size_t*),
            void* signer_opaque) {
    if (context == nullptr || certificate_list == nullptr ||
        certificate_list_size != 9u || signer == nullptr ||
        signer_opaque == nullptr)
        return -1;
    return 0;
}

int throwing_sign(
    void*, const std::uint8_t[
        RINRUNTIME_TLS_CLIENT_CERTIFICATE_CAPABILITY_BYTES], std::uint64_t,
    std::uint64_t, std::uint16_t, const std::uint8_t*, std::size_t,
    std::uint8_t*, std::size_t, std::size_t*) {
    throw std::runtime_error("TLS signer callback failure");
}

int throwing_install(void*, const void*, std::size_t,
                    int (*)(void*, std::uint16_t, const std::uint8_t*,
                             std::size_t, std::uint8_t*, std::size_t,
                             std::size_t*),
                    void*) {
    throw std::runtime_error("TLS installer callback failure");
}

struct ReentrantSignContext {
    RinRuntime::TlsClientCertificateTransport* transport = nullptr;
};

int reset_from_signer(
    void* opaque,
    const std::uint8_t[
        RINRUNTIME_TLS_CLIENT_CERTIFICATE_CAPABILITY_BYTES], std::uint64_t,
    std::uint64_t, std::uint16_t, const std::uint8_t*, std::size_t,
    std::uint8_t* signature, std::size_t signature_capacity,
    std::size_t* signature_length) {
    auto* context = static_cast<ReentrantSignContext*>(opaque);
    if (context == nullptr || context->transport == nullptr ||
        signature == nullptr || signature_capacity == 0u ||
        signature_length == nullptr)
        return -1;
    context->transport->reset();
    signature[0] = 0xa5u;
    *signature_length = 1u;
    return 0;
}

} // namespace

int main() {
    const std::uint8_t certificate_list[] = {
        0u, 0u, 6u, 0u, 0u, 1u, 0x30u, 0u, 0u,
    };
    std::uint8_t capability[RINRUNTIME_TLS_CLIENT_CERTIFICATE_CAPABILITY_BYTES] = {};
    for (std::size_t index = 0u; index < sizeof(capability); ++index)
        capability[index] = static_cast<std::uint8_t>(index + 1u);
    RinRuntimeTlsClientCertificateRequestV1 request = {
        sizeof(request), 1u, 7u, 11u, certificate_list,
        sizeof(certificate_list), capability, sizeof(capability),
    };
    SignContext context { capability[0], request.request_id,
                          request.connection_generation };
    RinRuntime::TlsClientCertificateTransport transport;
    assert(transport.bind(request, sign, &context));
    assert(transport.state() ==
           RinRuntime::TlsClientCertificateTransportState::Bound);
    assert(RinRuntime::installTlsClientCertificate(
        &context, transport, install));
    assert(transport.state() ==
           RinRuntime::TlsClientCertificateTransportState::HandshakeStarted);

    const std::uint8_t transcript[] = {1u, 2u, 3u};
    std::uint8_t signature[8u] = {};
    std::size_t signature_length = 0u;
    assert(transport.sign(0x0403u, transcript, sizeof(transcript), signature,
                          sizeof(signature), &signature_length) == 0);
    assert(signature_length == 3u && signature[0] == (1u ^ 0x5au) &&
           signature[1] == (2u ^ 0xa5u) && signature[2] == (3u ^ 0x3cu));
    assert(transport.state() == RinRuntime::TlsClientCertificateTransportState::Signed);
    transport.reset();
    assert(transport.state() == RinRuntime::TlsClientCertificateTransportState::Idle);
    assert(transport.requestId() == 0u &&
           transport.connectionGeneration() == 0u &&
           transport.certificateList() == nullptr &&
           transport.certificateListSize() == 0u);

    RinRuntime::TlsClientCertificateTransport stateless_transport;
    assert(stateless_transport.bind(request, stateless_sign, nullptr));
    assert(stateless_transport.startHandshake());
    signature_length = 0u;
    assert(stateless_transport.sign(0x0403u, transcript, sizeof(transcript),
                                    signature, sizeof(signature),
                                    &signature_length) == 0);
    assert(signature_length == 3u &&
           signature[0] == (transcript[0] ^ capability[0]) &&
           signature[1] == (transcript[1] ^ capability[1]) &&
           signature[2] == (transcript[2] ^ capability[2]));

    RinRuntime::TlsClientCertificateTransport throwing_transport;
    assert(throwing_transport.bind(request, throwing_sign, &context));
    assert(!RinRuntime::installTlsClientCertificate(
        &context, throwing_transport, throwing_install));
    assert(throwing_transport.state() ==
           RinRuntime::TlsClientCertificateTransportState::Bound);
    assert(RinRuntime::installTlsClientCertificate(
        &context, throwing_transport, install));
    std::uint8_t failed_signature[8u] = {
        0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu};
    std::size_t failed_signature_length = 99u;
    assert(throwing_transport.sign(
               0x0403u, transcript, sizeof(transcript), failed_signature,
               sizeof(failed_signature), &failed_signature_length) == -1);
    assert(failed_signature_length == 0u);
    for (std::uint8_t byte : failed_signature) assert(byte == 0u);
    assert(throwing_transport.state() ==
           RinRuntime::TlsClientCertificateTransportState::Failed);

    RinRuntime::TlsClientCertificateTransport reentrant_transport;
    ReentrantSignContext reentrant_context {&reentrant_transport};
    assert(reentrant_transport.bind(request, reset_from_signer,
                                    &reentrant_context));
    assert(reentrant_transport.startHandshake());
    std::uint8_t reentrant_signature[8u] = {
        0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu};
    std::size_t reentrant_signature_length = 99u;
    assert(reentrant_transport.sign(
               0x0403u, transcript, sizeof(transcript), reentrant_signature,
               sizeof(reentrant_signature), &reentrant_signature_length) == -1);
    assert(reentrant_signature_length == 0u);
    for (std::uint8_t byte : reentrant_signature) assert(byte == 0u);
    assert(reentrant_transport.state() ==
           RinRuntime::TlsClientCertificateTransportState::Idle);
    assert(reentrant_transport.requestId() == 0u);
    return 0;
}
