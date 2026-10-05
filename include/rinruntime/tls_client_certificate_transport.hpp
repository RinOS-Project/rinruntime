/* SPDX-License-Identifier: MIT */
/* Backend-independent, pre-handshake binding for TLS client certificates. */

#ifndef RINRUNTIME_TLS_CLIENT_CERTIFICATE_TRANSPORT_HPP
#define RINRUNTIME_TLS_CLIENT_CERTIFICATE_TRANSPORT_HPP

#include <cstddef>
#include <cstdint>
#include <limits>

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

    static bool byteRangesOverlap(const void* left, std::size_t left_size,
                                  const void* right,
                                  std::size_t right_size) noexcept {
        if (left == nullptr || right == nullptr || left_size == 0u ||
            right_size == 0u)
            return false;
        const std::uintptr_t left_begin =
            reinterpret_cast<std::uintptr_t>(left);
        const std::uintptr_t right_begin =
            reinterpret_cast<std::uintptr_t>(right);
        const std::uintptr_t max_value =
            std::numeric_limits<std::uintptr_t>::max();
        if (left_begin > max_value - static_cast<std::uintptr_t>(left_size) ||
            right_begin > max_value - static_cast<std::uintptr_t>(right_size))
            return true;
        const std::uintptr_t left_end =
            left_begin + static_cast<std::uintptr_t>(left_size);
        const std::uintptr_t right_end =
            right_begin + static_cast<std::uintptr_t>(right_size);
        return left_begin < right_end && right_begin < left_end;
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

    static int invokeSigner(
        TlsClientCertificateKeyOwnerSignFunction signer, void* context,
        const std::uint8_t capability[
            RINRUNTIME_TLS_CLIENT_CERTIFICATE_CAPABILITY_BYTES],
        std::uint64_t request_id, std::uint64_t connection_generation,
        std::uint16_t signature_scheme, const std::uint8_t* message,
        std::size_t message_length, std::uint8_t* signature,
        std::size_t signature_capacity, std::size_t* signature_length) noexcept {
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        try {
#endif
            return signer(context, capability, request_id,
                          connection_generation, signature_scheme, message,
                          message_length, signature, signature_capacity,
                          signature_length);
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        } catch (...) {
            if (signature_length != nullptr) *signature_length = 0u;
            return -1;
        }
#endif
    }

public:
    TlsClientCertificateTransport() = default;

    ~TlsClientCertificateTransport() { reset(); }

    bool bind(const RinRuntimeTlsClientCertificateRequestV1& request,
              TlsClientCertificateKeyOwnerSignFunction signer,
              void* signer_context) {
        /* The capability and request identity bind the operation.  A
         * stateless caller-owned signer may legitimately have no cookie. */
        if (state_ != TlsClientCertificateTransportState::Idle ||
            !rinruntime_tls_client_certificate_request_valid(&request) ||
            signer == nullptr)
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
        request_.signer_capability = capability_;
        request_.signer_capability_size = sizeof(capability_);
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
        if (state_ != TlsClientCertificateTransportState::HandshakeStarted ||
            signing_ || !signatureSchemeSupported(signature_scheme) ||
            signer_ == nullptr || message == nullptr || message_length == 0u ||
            message_length > kMaxTranscriptBytes || signature == nullptr ||
            signature_capacity == 0u || signature_capacity > kMaxSignatureBytes ||
            signature_length == nullptr)
            return failSign(message, message_length, signature,
                            signature_capacity, signature_length);

        /* Reject caller-owned input/output aliasing before clearing the
         * result length or invoking the private signer.  Otherwise an
         * overlapping transcript and signature buffer could be modified by
         * the callback while it is still being consumed, and an overlapping
         * length slot could corrupt either buffer before admission. */
        if (byteRangesOverlap(message, message_length, signature,
                              signature_capacity) ||
            byteRangesOverlap(message, message_length, signature_length,
                              sizeof(*signature_length)) ||
            byteRangesOverlap(signature, signature_capacity, signature_length,
                              sizeof(*signature_length))) {
            clearBytes(capability_, sizeof(capability_));
            state_ = TlsClientCertificateTransportState::Failed;
            return -1;
        }
        *signature_length = 0u;

        std::size_t written = 0u;
        signing_ = true;
        const int result = invokeSigner(
            signer_, signer_context_, capability_, request_.request_id,
            request_.connection_generation, signature_scheme, message,
            message_length, signature, signature_capacity, &written);
        signing_ = false;
        if (state_ != TlsClientCertificateTransportState::HandshakeStarted ||
            result != 0 || written == 0u || written > signature_capacity) {
            clearBytes(signature, signature_capacity);
            clearBytes(capability_, sizeof(capability_));
            if (state_ == TlsClientCertificateTransportState::HandshakeStarted)
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
    int failSign(const std::uint8_t* message, std::size_t message_length,
                 std::uint8_t* signature, std::size_t signature_capacity,
                 std::size_t* signature_length) {
        /* Clear a stale result length on ordinary rejected input, but never
         * write through a length pointer that aliases caller-owned input or
         * the signature output.  The explicit aliasing path above preserves
         * the caller's bytes and length for diagnosis. */
        if (signature_length != nullptr &&
            !byteRangesOverlap(message, message_length, signature_length,
                               sizeof(*signature_length)) &&
            !byteRangesOverlap(signature, signature_capacity,
                               signature_length,
                               sizeof(*signature_length)))
            *signature_length = 0u;
        if (signature != nullptr && signature_capacity != 0u)
            clearBytes(signature, signature_capacity < kMaxSignatureBytes
                                      ? signature_capacity
                                      : kMaxSignatureBytes);
        clearBytes(capability_, sizeof(capability_));
        state_ = TlsClientCertificateTransportState::Failed;
        return -1;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_TLS_CLIENT_CERTIFICATE_TRANSPORT_HPP */
