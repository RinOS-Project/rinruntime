/* SPDX-License-Identifier: MIT */
/* Callback adapter for a caller-owned range source. */

#ifndef RINRUNTIME_DOWNLOAD_RANGE_TRANSPORT_HPP
#define RINRUNTIME_DOWNLOAD_RANGE_TRANSPORT_HPP

#if defined(RIN_FREESTANDING) || defined(RINCXX_CSTDDEF_H) || \
    defined(RINCXX_STRING_H)
#include "../../../../libs/libcxx/cstddef.h"
#include "../../../../libs/libcxx/cstdint.h"
#include "../../../../libs/libcxx/string.h"
#else
#include <cstddef>
#include <cstdint>
#include <string>
#endif

#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
#include <new>
#endif

#include "cancellation.h"
#include "download_resume.hpp"

namespace RinRuntime {

using DownloadRangeBeginFunction = int (*)(
    void* context, const DownloadRangeRequest* request,
    DownloadRangeResponse* response);
using DownloadRangeReadFunction = int (*)(
    void* context, std::uint8_t* buffer, std::size_t capacity,
    std::size_t* bytesRead);
using DownloadRangeAbortFunction = void (*)(void* context);
using DownloadRangeCancellationFunction = RinRuntimeCancellationFunction;

struct DownloadRangeTransportOpsV1 {
    std::uint32_t structSize = 0u;
    std::uint16_t version = 1u;
    std::uint16_t reserved0 = 0u;
    void* context = nullptr;
    DownloadRangeBeginFunction begin = nullptr;
    DownloadRangeReadFunction read = nullptr;
    DownloadRangeAbortFunction abort = nullptr;
    /* Optional for callers that do not expose cancellation.  When present,
     * it must return 0 for continue, 1 for cancellation, or another value
     * for an owner failure. */
    DownloadRangeCancellationFunction cancelled = nullptr;
};

class DownloadRangeTransportAdapter final : public DownloadRangeTransport {
public:
    static constexpr std::uint16_t kVersion = 1u;
    static constexpr std::size_t kMaxChunkBytes = 64u * 1024u;

    enum class State : std::uint8_t {
        Idle = 0,
        Streaming = 1,
        Failed = 2,
        Cancelled = 3,
    };

private:
    DownloadRangeTransportOpsV1 ops_{};
    DownloadRangeRequest request_{};
    std::uint64_t remaining_ = 0u;
    bool rangeExhausted_ = false;
    State state_ = State::Idle;

    static void scrubBuffer(std::uint8_t* buffer, std::size_t capacity) {
        if (buffer == nullptr || capacity == 0u ||
            capacity > kMaxChunkBytes)
            return;
        for (std::size_t index = 0u; index != capacity; ++index)
            buffer[index] = 0u;
    }

    static void scrubBufferTail(std::uint8_t* buffer, std::size_t begin,
                                std::size_t capacity) {
        if (buffer == nullptr || begin >= capacity ||
            capacity > kMaxChunkBytes)
            return;
        for (std::size_t index = begin; index != capacity; ++index)
            buffer[index] = 0u;
    }

    static bool requestEquivalent(const DownloadRangeRequest& first,
                                  const DownloadRangeRequest& second) {
        return first.requestId == second.requestId &&
               first.generation == second.generation &&
               first.offset == second.offset &&
               first.totalBytes == second.totalBytes &&
               first.validator == second.validator;
    }

    static bool opsValid(const DownloadRangeTransportOpsV1& ops) {
        /* `cancelled` was appended to the v1 callback table after the
         * original public release.  Accept the original prefix and only
         * inspect the optional field when the caller's declared size covers
         * it.  Reject future larger tables until a new version is published.
         */
        constexpr std::size_t kBaseSize =
            offsetof(DownloadRangeTransportOpsV1, cancelled);
        return (ops.structSize == kBaseSize ||
                ops.structSize == sizeof(DownloadRangeTransportOpsV1)) &&
               ops.version == kVersion && ops.reserved0 == 0u &&
               ops.begin != nullptr && ops.read != nullptr &&
               ops.abort != nullptr;
    }

    static DownloadRangeTransportOpsV1 normalizeOps(
        const DownloadRangeTransportOpsV1& ops) {
        DownloadRangeTransportOpsV1 normalized{};
        normalized.structSize = sizeof(DownloadRangeTransportOpsV1);
        normalized.version = ops.version;
        normalized.reserved0 = ops.reserved0;
        normalized.context = ops.context;
        normalized.begin = ops.begin;
        normalized.read = ops.read;
        normalized.abort = ops.abort;
        if (ops.structSize == sizeof(DownloadRangeTransportOpsV1))
            normalized.cancelled = ops.cancelled;
        return normalized;
    }

    int cancellationStatus() const noexcept {
        if (ops_.cancelled == nullptr) return 0;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        try {
#endif
            return ops_.cancelled(ops_.context);
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        } catch (...) {
            /* A public C callback must not let an owner exception escape the
             * runtime boundary.  Treat it as an owner failure. */
            return -1;
        }
#endif
    }

    void abortOwner() noexcept {
        if (state_ != State::Streaming || ops_.abort == nullptr) return;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        try {
#endif
            ops_.abort(ops_.context);
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        } catch (...) {
            /* Abort is best effort after the public adapter has already
             * decided to fail.  Do not leak an owner exception to the caller. */
        }
#endif
    }

    void cancelAndAbort() noexcept {
        abortOwner();
        request_.clear();
        remaining_ = 0u;
        rangeExhausted_ = false;
        state_ = State::Cancelled;
    }

    void failAndAbort() noexcept {
        abortOwner();
        request_.clear();
        remaining_ = 0u;
        rangeExhausted_ = false;
        state_ = State::Failed;
    }

public:
    bool bind(const DownloadRangeTransportOpsV1& ops) {
        if (state_ != State::Idle || !opsValid(ops)) return false;
        ops_ = normalizeOps(ops);
        return true;
    }

    void unbind() {
        if (state_ == State::Streaming) return;
        ops_ = DownloadRangeTransportOpsV1{};
        request_.clear();
        remaining_ = 0u;
        rangeExhausted_ = false;
        state_ = State::Idle;
    }

    bool begin(const DownloadRangeRequest& request,
               DownloadRangeResponse& response) override {
        response = DownloadRangeResponse{};
        if (state_ != State::Idle || !opsValid(ops_) || !request.valid())
            return false;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        try {
#endif
        request_ = request;
        state_ = State::Streaming;
        const int beforeBegin = cancellationStatus();
        if (beforeBegin == 1) {
            request_.clear();
            state_ = State::Cancelled;
            return false;
        }
        if (beforeBegin != 0) {
            failAndAbort();
            state_ = State::Idle;
            return false;
        }
        const DownloadRangeRequest requestBaseline = request_;
        DownloadRangeResponse candidate{};
        const int result = ops_.begin(ops_.context, &request_, &candidate);
        if (result != 0 || !requestEquivalent(request_, requestBaseline) ||
            !candidate.validFor(requestBaseline)) {
            abortOwner();
            request_.clear();
            remaining_ = 0u;
            rangeExhausted_ = false;
            state_ = State::Idle;
            return false;
        }
        const int afterBegin = cancellationStatus();
        if (afterBegin == 1) {
            cancelAndAbort();
            return false;
        }
        if (afterBegin != 0) {
            failAndAbort();
            state_ = State::Idle;
            return false;
        }
        remaining_ = candidate.contentLength;
        rangeExhausted_ = false;
        response = candidate;
        return true;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        } catch (...) {
            abortOwner();
            request_.clear();
            remaining_ = 0u;
            rangeExhausted_ = false;
            state_ = State::Idle;
            response = DownloadRangeResponse{};
            return false;
        }
#endif
    }

    bool read(std::uint8_t* buffer, std::size_t capacity,
              std::size_t& bytesRead) override {
        bytesRead = 0u;
        if (state_ != State::Streaming) {
            /* A caller may reuse a buffer after a terminal read, cancellation,
             * or explicit abort.  Do not leave bytes from the previous range
             * visible through that direct read path. */
            scrubBuffer(buffer, capacity);
            return false;
        }
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        try {
#endif
        const int beforeRead = cancellationStatus();
        if (beforeRead == 1) {
            scrubBuffer(buffer, capacity);
            cancelAndAbort();
            return false;
        }
        if (beforeRead != 0) {
            scrubBuffer(buffer, capacity);
            failAndAbort();
            return false;
        }
        if (!opsValid(ops_) || buffer == nullptr || capacity == 0u ||
            capacity > kMaxChunkBytes) {
            failAndAbort();
            return false;
        }
        /* Do not let an owner inspect or fetch bytes beyond the admitted
         * range merely because the caller supplied a larger buffer.  The
         * final zero-byte EOF probe still uses the caller's capacity. */
        std::size_t readCapacity = capacity;
        if (remaining_ != 0u &&
            remaining_ < static_cast<std::uint64_t>(readCapacity)) {
            readCapacity = static_cast<std::size_t>(remaining_);
        }
        std::size_t candidate = 0u;
        const int readResult = ops_.read(ops_.context, buffer, readCapacity,
                                         &candidate);
        const int afterRead = cancellationStatus();
        if (afterRead == 1) {
            scrubBuffer(buffer, capacity);
            cancelAndAbort();
            return false;
        }
        if (afterRead != 0) {
            scrubBuffer(buffer, capacity);
            failAndAbort();
            return false;
        }
        if (readResult == 0) {
            if (candidate == 0u) {
                if (!rangeExhausted_) {
                    scrubBuffer(buffer, capacity);
                    failAndAbort();
                    return false;
                }
                scrubBuffer(buffer, capacity);
                request_.clear();
                remaining_ = 0u;
                rangeExhausted_ = false;
                state_ = State::Idle;
                return true;
            }
            if (candidate > capacity ||
                static_cast<std::uint64_t>(candidate) > remaining_) {
                scrubBuffer(buffer, capacity);
                failAndAbort();
                return false;
            }
            /* The callback owns only the reported prefix.  Clear the
             * remainder even when the owner accidentally wrote beyond that
             * prefix, so a direct public read cannot expose unreported bytes
             * through a caller-reused buffer. */
            scrubBufferTail(buffer, candidate, capacity);
            remaining_ -= static_cast<std::uint64_t>(candidate);
            if (remaining_ == 0u) rangeExhausted_ = true;
            bytesRead = candidate;
            return true;
        }
        scrubBuffer(buffer, capacity);
        failAndAbort();
        return false;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        } catch (...) {
            scrubBuffer(buffer, capacity);
            failAndAbort();
            return false;
        }
#endif
    }

    void abort() override {
        abortOwner();
        request_.clear();
        remaining_ = 0u;
        rangeExhausted_ = false;
        state_ = State::Idle;
    }

    State state() const { return state_; }
    bool wasCancelled() const override { return state_ == State::Cancelled; }
    std::uint64_t remaining() const { return remaining_; }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_DOWNLOAD_RANGE_TRANSPORT_HPP */
