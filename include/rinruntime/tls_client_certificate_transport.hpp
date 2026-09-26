/* SPDX-License-Identifier: MIT */
/* Backend-independent, pre-handshake binding for TLS client certificates. */

#ifndef RINRUNTIME_TLS_CLIENT_CERTIFICATE_TRANSPORT_HPP
#define RINRUNTIME_TLS_CLIENT_CERTIFICATE_TRANSPORT_HPP

#include <cstddef>
#include <cstdint>

#include "tls_client_certificate.h"

namespace RinRuntime {

enum class TlsClientCertificateTransportState : std::uint8_t {
    Idle = 0,
    Bound = 1,
    HandshakeStarted = 2,
    Signed = 3,
    Failed = 4,
};

/* The key owner receives only the opaque capability and authenticated request
 * identity. Private-key bytes and certificate paths are not part of this API. */
using TlsClientCertificateKeyOwnerSignFunction = int (*)(
    void* context,
    const std::uint8_t capability[RINRUNTIME_TLS_CLIENT_CERTIFICATE_CAPABILITY_BYTES],
    std::uint64_t request_id, std::uint64_t connection_generation,
    std::uint16_t signature_scheme, const std::uint8_t* message,
    std::size_t message_length, std::uint8_t* signature,
    std::size_t signature_capacity, std::size_t* signature_length);

class TlsClientCertificateTransport final {
    TlsClientCertificateTransport(const TlsClientCertificateTransport&) = delete;
    TlsClientCertificateTransport& operator=(
        const TlsClientCertificateTransport&) = delete;
    TlsClientCertificateTransport(TlsClientCertificateTransport&&) = delete;
    TlsClientCertificateTransport& operator=(
        TlsClientCertificateTransport&&) = delete;

    RinRuntimeTlsClientCertificateRequestV1 request_{};
    TlsClientCertificateKeyOwnerSignFunction signer_ = nullptr;
    void* signer_context_ = nullptr;
    std::uint8_t certificate_list_[RINRUNTIME_TLS_CLIENT_CERTIFICATE_CHAIN_MAX]{};
    std::uint8_t capability_[RINRUNTIME_TLS_CLIENT_CERTIFICATE_CAPABILITY_BYTES]{};
    TlsClientCertificateTransportState state_ =
        TlsClientCertificateTransportState::Idle;
    bool signing_ = false;

    static constexpr std::size_t kMaxTranscriptBytes =
        RINRUNTIME_TLS_CLIENT_CERTIFICATE_TRANSCRIPT_MAX;
    static constexpr std::size_t kMaxSignatureBytes = 512u;

    static void clearBytes(std::uint8_t* bytes, std::size_t size) noexcept {
        if (bytes == nullptr) return;
        volatile std::uint8_t* target = bytes;
        while (size-- != 0u) *target++ = 0u;
    }

    static bool signatureSchemeSupported(std::uint16_t scheme) {
        switch (scheme) {
        case 0x0403u:
        case 0x0503u:
        case 0x0603u:
        case 0x0804u:
        case 0x0805u:
        case 0x0806u:
            return true;
        default:
            return false;
        }
    }

public:
    TlsClientCertificateTransport() = default;

    ~TlsClientCertificateTransport() { reset(); }

    bool bind(const RinRuntimeTlsClientCertificateRequestV1& request,
              TlsClientCertificateKeyOwnerSignFunction signer,
              void* signer_context) {
        if (state_ != TlsClientCertificateTransportState::Idle ||
            !rinruntime_tls_client_certificate_request_valid(&request) ||
            signer == nullptr || signer_context == nullptr)
            return false;
        request_ = request;
        for (std::size_t index = 0u; index < request.certificate_list_size;
             ++index)
            certificate_list_[index] = request.certificate_list[index];
        request_.certificate_list = certificate_list_;
        for (std::size_t index = 0u;
             index < RINRUNTIME_TLS_CLIENT_CERTIFICATE_CAPABILITY_BYTES;
             ++index)
            capability_[index] = request.signer_capability[index];
        signer_ = signer;
        signer_context_ = signer_context;
        state_ = TlsClientCertificateTransportState::Bound;
        return true;
    }

    bool startHandshake() {
        if (state_ != TlsClientCertificateTransportState::Bound)
            return false;
        state_ = TlsClientCertificateTransportState::HandshakeStarted;
        return true;
    }

    static int signCallback(
        void* opaque, std::uint16_t signature_scheme,
        const std::uint8_t* message, std::size_t message_length,
        std::uint8_t* signature, std::size_t signature_capacity,
        std::size_t* signature_length) {
        auto* transport = static_cast<TlsClientCertificateTransport*>(opaque);
        if (transport == nullptr) return -1;
        return transport->sign(signature_scheme, message, message_length,
                               signature, signature_capacity, signature_length);
    }

    int sign(std::uint16_t signature_scheme, const std::uint8_t* message,
             std::size_t message_length, std::uint8_t* signature,
             std::size_t signature_capacity, std::size_t* signature_length) {
        if (signature_length != nullptr) *signature_length = 0u;
        if (state_ != TlsClientCertificateTransportState::HandshakeStarted ||
            signing_ || !signatureSchemeSupported(signature_scheme) ||
            signer_ == nullptr || message == nullptr || message_length == 0u ||
            message_length > kMaxTranscriptBytes || signature == nullptr ||
            signature_capacity == 0u || signature_capacity > kMaxSignatureBytes ||
            signature_length == nullptr)
            return failSign(signature, signature_capacity);

        std::size_t written = 0u;
        signing_ = true;
        const int result = signer_(
            signer_context_, capability_, request_.request_id,
            request_.connection_generation, signature_scheme, message,
            message_length, signature, signature_capacity, &written);
        signing_ = false;
        if (state_ != TlsClientCertificateTransportState::HandshakeStarted ||
            result != 0 || written == 0u || written > signature_capacity) {
            if (signature != nullptr && signature_capacity != 0u)
                for (std::size_t index = 0u; index < signature_capacity; ++index)
                    signature[index] = 0u;
            clearBytes(capability_, sizeof(capability_));
            state_ = TlsClientCertificateTransportState::Failed;
            return -1;
        }
        *signature_length = written;
        clearBytes(capability_, sizeof(capability_));
        state_ = TlsClientCertificateTransportState::Signed;
        return 0;
    }

    void reset() {
        clearBytes(certificate_list_, sizeof(certificate_list_));
        clearBytes(capability_, sizeof(capability_));
        request_ = RinRuntimeTlsClientCertificateRequestV1{};
        signer_ = nullptr;
        signer_context_ = nullptr;
        signing_ = false;
        state_ = TlsClientCertificateTransportState::Idle;
    }

    TlsClientCertificateTransportState state() const { return state_; }
    std::uint64_t requestId() const { return request_.request_id; }
    std::uint64_t connectionGeneration() const {
        return request_.connection_generation;
    }
    const std::uint8_t* certificateList() const {
        return request_.certificate_list;
    }
    std::uint32_t certificateListSize() const {
        return request_.certificate_list_size;
    }

private:
    int failSign(std::uint8_t* signature, std::size_t signature_capacity) {
        if (signature != nullptr && signature_capacity != 0u &&
            signature_capacity <= kMaxSignatureBytes)
            clearBytes(signature, signature_capacity);
        clearBytes(capability_, sizeof(capability_));
        state_ = TlsClientCertificateTransportState::Failed;
        return -1;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_TLS_CLIENT_CERTIFICATE_TRANSPORT_HPP */
