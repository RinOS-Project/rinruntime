/* SPDX-License-Identifier: MIT */
/* Callback adapter for an authenticated HTTP range owner. */

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

    static bool requestEquivalent(const DownloadRangeRequest& first,
                                  const DownloadRangeRequest& second) {
        return first.requestId == second.requestId &&
               first.generation == second.generation &&
               first.offset == second.offset &&
               first.totalBytes == second.totalBytes &&
               first.validator == second.validator;
    }

    static bool opsValid(const DownloadRangeTransportOpsV1& ops) {
        return ops.structSize == sizeof(DownloadRangeTransportOpsV1) &&
               ops.version == kVersion && ops.reserved0 == 0u &&
               ops.context != nullptr && ops.begin != nullptr &&
               ops.read != nullptr && ops.abort != nullptr;
    }

    int cancellationStatus() const {
        if (ops_.cancelled == nullptr) return 0;
        return ops_.cancelled(ops_.context);
    }

    void cancelAndAbort() {
        if (state_ == State::Streaming && ops_.abort != nullptr)
            ops_.abort(ops_.context);
        request_.clear();
        remaining_ = 0u;
        rangeExhausted_ = false;
        state_ = State::Cancelled;
    }

    void failAndAbort() {
        if (state_ == State::Streaming && ops_.abort != nullptr)
            ops_.abort(ops_.context);
        request_.clear();
        remaining_ = 0u;
        rangeExhausted_ = false;
        state_ = State::Failed;
    }

public:
    bool bind(const DownloadRangeTransportOpsV1& ops) {
        if (state_ != State::Idle || !opsValid(ops)) return false;
        ops_ = ops;
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
            ops_.abort(ops_.context);
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
    }

    bool read(std::uint8_t* buffer, std::size_t capacity,
              std::size_t& bytesRead) override {
        bytesRead = 0u;
        if (state_ != State::Streaming) return false;
        const int beforeRead = cancellationStatus();
        if (beforeRead == 1) {
            cancelAndAbort();
            return false;
        }
        if (beforeRead != 0) {
            failAndAbort();
            return false;
        }
        if (!opsValid(ops_) || buffer == nullptr || capacity == 0u ||
            capacity > kMaxChunkBytes) {
            failAndAbort();
            return false;
        }
        std::size_t candidate = 0u;
        const int readResult = ops_.read(ops_.context, buffer, capacity,
                                         &candidate);
        const int afterRead = cancellationStatus();
        if (afterRead == 1) {
            cancelAndAbort();
            return false;
        }
        if (afterRead != 0) {
            failAndAbort();
            return false;
        }
        if (readResult == 0) {
            if (candidate == 0u) {
                if (!rangeExhausted_) {
                    failAndAbort();
                    return false;
                }
                request_.clear();
                remaining_ = 0u;
                rangeExhausted_ = false;
                state_ = State::Idle;
                return true;
            }
            if (candidate > capacity ||
                static_cast<std::uint64_t>(candidate) > remaining_) {
                failAndAbort();
                return false;
            }
            remaining_ -= static_cast<std::uint64_t>(candidate);
            if (remaining_ == 0u) rangeExhausted_ = true;
            bytesRead = candidate;
            return true;
        }
        failAndAbort();
        return false;
    }

    void abort() override {
        if (state_ == State::Streaming && ops_.abort != nullptr)
            ops_.abort(ops_.context);
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
