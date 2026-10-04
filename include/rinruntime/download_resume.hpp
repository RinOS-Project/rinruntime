/* SPDX-License-Identifier: MIT */
/* Bounded, renderer-independent durable partial-download receipt. */

#ifndef RINRUNTIME_DOWNLOAD_RESUME_HPP
#define RINRUNTIME_DOWNLOAD_RESUME_HPP

#if defined(RIN_FREESTANDING) || defined(RINCXX_CSTDDEF_H) || \
    defined(RINCXX_STRING_H)
#include "../../../../libs/libcxx/cstddef.h"
#include "../../../../libs/libcxx/cstdint.h"
#include "../../../../libs/libcxx/limits.h"
#include "../../../../libs/libcxx/string.h"
#else
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <cstring>
#endif

#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
#include <new>
#endif

namespace RinRuntime {

namespace detail {

inline bool downloadRangesOverlap(const void* left, std::size_t leftSize,
                                  const void* right, std::size_t rightSize) {
    if (left == nullptr || right == nullptr || leftSize == 0u ||
        rightSize == 0u)
        return false;
    const std::uintptr_t leftBegin =
        reinterpret_cast<std::uintptr_t>(left);
    const std::uintptr_t rightBegin =
        reinterpret_cast<std::uintptr_t>(right);
    const std::uintptr_t maxValue =
        std::numeric_limits<std::uintptr_t>::max();
    if (leftBegin > maxValue - static_cast<std::uintptr_t>(leftSize) ||
        rightBegin > maxValue - static_cast<std::uintptr_t>(rightSize))
        return true;
    const std::uintptr_t leftEnd =
        leftBegin + static_cast<std::uintptr_t>(leftSize);
    const std::uintptr_t rightEnd =
        rightBegin + static_cast<std::uintptr_t>(rightSize);
    return leftBegin < rightEnd && rightBegin < leftEnd;
}

} // namespace detail

/*
 * A receipt is metadata only: it does not contain a pathname, descriptor, or
 * portal handle.  The authenticated HTTP owner supplies requestId,
 * generation, and validator (for example an ETag) when it creates the
 * receipt.  A resumed range is accepted only when every identity field and
 * the exact ordered byte offset match the durable record.  Authentication,
 * authorization, and the storage location of the partial bytes are outside
 * this public metadata contract and remain caller-owned.
 */
struct DownloadPartialReceipt {
    static constexpr std::uint32_t kMagic = 0x31504452u; /* "RDP1" */
    static constexpr std::uint16_t kVersion = 1u;
    static constexpr std::size_t kMaxValidatorBytes = 127u;
    static constexpr std::uint64_t kMaxBytes = 128u * 1024u * 1024u;
    static constexpr std::size_t kWireSize = 172u;

    std::uint64_t requestId = 0u;
    std::uint64_t totalBytes = 0u;
    std::uint64_t committedBytes = 0u;
    std::uint64_t generation = 0u;
    std::string validator;

    bool valid() const {
        return requestId != 0u && generation != 0u && totalBytes != 0u &&
               totalBytes <= kMaxBytes && committedBytes <= totalBytes &&
               committedBytes != totalBytes && validValidator(validator);
    }

    bool matches(std::uint64_t request, std::uint64_t generationValue,
                 const std::string& validatorValue,
                 std::uint64_t offset) const {
        return valid() && requestId == request &&
               generation == generationValue && validator == validatorValue &&
               committedBytes == offset;
    }

    bool advance(std::uint64_t nextOffset) {
        if (!valid() || nextOffset < committedBytes ||
            nextOffset > totalBytes || nextOffset == totalBytes)
            return false;
        committedBytes = nextOffset;
        return true;
    }

    void clear() {
        requestId = 0u;
        totalBytes = 0u;
        committedBytes = 0u;
        generation = 0u;
        validator.clear();
    }

    bool encode(std::uint8_t* output, std::size_t capacity,
                std::size_t& outputSize) const {
        if (overlapsStorage(output, capacity) ||
            overlapsStorage(&outputSize, sizeof(outputSize)) ||
            detail::downloadRangesOverlap(output, capacity, &outputSize,
                                          sizeof(outputSize)))
            return false;
        outputSize = 0u;
        if (output == nullptr || capacity < kWireSize || !valid()) {
            if (output != nullptr && capacity != 0u)
                ::memset(output, 0, capacity < kWireSize ? capacity : kWireSize);
            return false;
        }
        ::memset(output, 0, kWireSize);
        put32(output + 0u, kMagic);
        put16(output + 4u, kVersion);
        put16(output + 6u, 0u);
        put64(output + 8u, requestId);
        put64(output + 16u, totalBytes);
        put64(output + 24u, committedBytes);
        put64(output + 32u, generation);
        put16(output + 40u, static_cast<std::uint16_t>(validator.size()));
        if (!validator.empty())
            ::memcpy(output + 44u, validator.data(), validator.size());
        outputSize = kWireSize;
        return true;
    }

    static bool decode(const std::uint8_t* input, std::size_t inputSize,
                       DownloadPartialReceipt& output) {
        if (output.overlapsStorage(input, inputSize)) return false;
        output.clear();
        if (input == nullptr || inputSize != kWireSize ||
            get32(input + 0u) != kMagic || get16(input + 4u) != kVersion ||
            get16(input + 6u) != 0u ||
            get16(input + 42u) != 0u ||
            get16(input + 40u) > kMaxValidatorBytes)
            return false;
        const std::size_t validatorSize = get16(input + 40u);
        for (std::size_t index = 44u + validatorSize; index < kWireSize;
             ++index) {
            if (input[index] != 0u) return false;
        }
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        try {
#endif
            DownloadPartialReceipt candidate;
            candidate.requestId = get64(input + 8u);
            candidate.totalBytes = get64(input + 16u);
            candidate.committedBytes = get64(input + 24u);
            candidate.generation = get64(input + 32u);
            candidate.validator.assign(
                reinterpret_cast<const char*>(input + 44u), validatorSize);
            if (!candidate.valid()) return false;
            output.requestId = candidate.requestId;
            output.totalBytes = candidate.totalBytes;
            output.committedBytes = candidate.committedBytes;
            output.generation = candidate.generation;
            output.validator.swap(candidate.validator);
            return true;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        } catch (const std::bad_alloc&) {
            output.clear();
            return false;
        } catch (...) {
            output.clear();
            return false;
        }
#endif
    }

private:
    bool overlapsStorage(const void* address, std::size_t size) const {
        return detail::downloadRangesOverlap(address, size, this,
                                             sizeof(*this)) ||
               detail::downloadRangesOverlap(address, size, validator.data(),
                                             validator.capacity());
    }

    static bool validValidator(const std::string& value) {
        if (value.empty() || value.size() > kMaxValidatorBytes) return false;
        for (unsigned char byte : value)
            if (byte < 0x21u || byte > 0x7eu) return false;
        return true;
    }

    static void put16(std::uint8_t* output, std::uint16_t value) {
        output[0] = static_cast<std::uint8_t>(value);
        output[1] = static_cast<std::uint8_t>(value >> 8u);
    }

    static void put32(std::uint8_t* output, std::uint32_t value) {
        for (unsigned index = 0u; index < 4u; ++index)
            output[index] = static_cast<std::uint8_t>(value >> (index * 8u));
    }

    static void put64(std::uint8_t* output, std::uint64_t value) {
        for (unsigned index = 0u; index < 8u; ++index)
            output[index] = static_cast<std::uint8_t>(value >> (index * 8u));
    }

    static std::uint16_t get16(const std::uint8_t* input) {
        return static_cast<std::uint16_t>(input[0]) |
               static_cast<std::uint16_t>(input[1]) << 8u;
    }

    static std::uint32_t get32(const std::uint8_t* input) {
        std::uint32_t value = 0u;
        for (unsigned index = 0u; index < 4u; ++index)
            value |= static_cast<std::uint32_t>(input[index]) << (index * 8u);
        return value;
    }

    static std::uint64_t get64(const std::uint8_t* input) {
        std::uint64_t value = 0u;
        for (unsigned index = 0u; index < 8u; ++index)
            value |= static_cast<std::uint64_t>(input[index]) << (index * 8u);
        return value;
    }
};

struct DownloadRangeRequest {
    static constexpr std::size_t kMaxRangeHeaderBytes = 64u;

    std::uint64_t requestId = 0u;
    std::uint64_t generation = 0u;
    std::uint64_t offset = 0u;
    std::uint64_t totalBytes = 0u;
    std::string validator;

    void clear() {
        requestId = 0u;
        generation = 0u;
        offset = 0u;
        totalBytes = 0u;
        validator.clear();
    }

    bool valid() const {
        return requestId != 0u && generation != 0u && totalBytes != 0u &&
               totalBytes <= DownloadPartialReceipt::kMaxBytes &&
               offset < totalBytes && validValidator(validator);
    }

    bool prepare(const DownloadPartialReceipt& receipt,
                 std::uint64_t expectedRequestId,
                 std::uint64_t expectedGeneration,
                 const std::string& expectedValidator) {
        if (!receipt.matches(expectedRequestId, expectedGeneration,
                             expectedValidator, receipt.committedBytes)) {
            clear();
            return false;
        }
        clear();
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        try {
#else
        {
#endif
            DownloadRangeRequest candidate;
            candidate.requestId = receipt.requestId;
            candidate.generation = receipt.generation;
            candidate.offset = receipt.committedBytes;
            candidate.totalBytes = receipt.totalBytes;
            candidate.validator = receipt.validator;
            if (!candidate.valid()) return false;
            requestId = candidate.requestId;
            generation = candidate.generation;
            offset = candidate.offset;
            totalBytes = candidate.totalBytes;
            validator.swap(candidate.validator);
            return true;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        } catch (const std::bad_alloc&) {
            clear();
            return false;
        } catch (...) {
            clear();
            return false;
        }
#else
        }
#endif
    }

    bool makeRangeHeader(std::string& output) const {
        if (&output == &validator) return false;
        output.clear();
        if (!valid()) return false;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        try {
#endif
            std::string candidate = "bytes=";
            candidate += std::to_string(offset);
            candidate += '-';
            if (candidate.size() >= kMaxRangeHeaderBytes) return false;
            output.swap(candidate);
            return true;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        } catch (const std::bad_alloc&) {
            output.clear();
            return false;
        } catch (...) {
            output.clear();
            return false;
        }
#endif
    }

private:
    static bool validValidator(const std::string& value) {
        if (value.empty() ||
            value.size() > DownloadPartialReceipt::kMaxValidatorBytes)
            return false;
        for (unsigned char byte : value)
            if (byte < 0x21u || byte > 0x7eu) return false;
        return true;
    }
};

struct DownloadRangeResponse {
    std::uint16_t statusCode = 0u;
    std::uint64_t contentRangeStart = 0u;
    std::uint64_t contentRangeEnd = 0u;
    std::uint64_t contentRangeTotal = 0u;
    std::uint64_t contentLength = 0u;
    std::uint64_t generation = 0u;
    std::string validator;

    bool validFor(const DownloadRangeRequest& request) const {
        if (!request.valid() || statusCode != 206u ||
            generation != request.generation ||
            validator != request.validator ||
            contentRangeStart != request.offset ||
            contentRangeTotal != request.totalBytes || contentLength == 0u ||
            contentLength != request.totalBytes - request.offset ||
            contentRangeEnd < contentRangeStart ||
            contentRangeEnd >= request.totalBytes ||
            contentRangeEnd - contentRangeStart + 1u != contentLength)
            return false;
        return true;
    }
};

class DownloadRangeTransport {
public:
    virtual ~DownloadRangeTransport() = default;
    virtual bool begin(const DownloadRangeRequest& request,
                       DownloadRangeResponse& response) = 0;
    virtual bool read(std::uint8_t* buffer, std::size_t capacity,
                      std::size_t& bytesRead) = 0;
    virtual void abort() = 0;
    virtual bool wasCancelled() const { return false; }
};

/* Read one admitted range into caller-owned storage.  This is a convenience
 * layer over the public transport contract, not an authentication or storage
 * owner.  It keeps reads bounded, requires the response length to match the
 * request, rejects early EOF and trailing bytes, and scrubs bytes written
 * before a failure is reported. */
inline bool readDownloadRangeToBuffer(DownloadRangeTransport& transport,
                                      const DownloadRangeRequest& request,
                                      std::uint8_t* output,
                                      std::size_t capacity,
                                      std::size_t& outputSize) {
    const bool outputAliasesRequest =
        detail::downloadRangesOverlap(output, capacity, &request,
                                      sizeof(request)) ||
        detail::downloadRangesOverlap(output, capacity, request.validator.data(),
                                      request.validator.capacity());
    const bool sizeAliasesRequest =
        detail::downloadRangesOverlap(&outputSize, sizeof(outputSize),
                                      &request, sizeof(request)) ||
        detail::downloadRangesOverlap(&outputSize, sizeof(outputSize),
                                      request.validator.data(),
                                      request.validator.capacity());
    if (outputAliasesRequest || sizeAliasesRequest ||
        detail::downloadRangesOverlap(output, capacity, &outputSize,
                                      sizeof(outputSize)))
        return false;
    outputSize = 0u;
    const auto scrubOutput = [&]() noexcept {
        if (output == nullptr || capacity == 0u) return;
        const std::size_t bounded =
            capacity < DownloadPartialReceipt::kMaxBytes
                ? capacity
                : static_cast<std::size_t>(DownloadPartialReceipt::kMaxBytes);
        for (std::size_t index = 0u; index < bounded; ++index)
            output[index] = 0u;
    };
    if (!request.valid() || output == nullptr || capacity == 0u) {
        scrubOutput();
        return false;
    }
    bool beginEntered = false;
    bool settled = false;
#if !defined(__cpp_exceptions) && !defined(__EXCEPTIONS) && \
    !defined(_CPPUNWIND)
    (void)beginEntered;
    (void)settled;
#endif
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
    const auto scrubOnOwnerFailure = [&]() noexcept {
        const std::size_t bounded =
            capacity < DownloadPartialReceipt::kMaxBytes
                ? capacity
                : static_cast<std::size_t>(DownloadPartialReceipt::kMaxBytes);
        for (std::size_t index = 0u; index < bounded; ++index)
            output[index] = 0u;
        outputSize = 0u;
    };
    const auto abortAfterOwnerFailure = [&]() noexcept {
        if (!beginEntered || settled) return;
        bool cancelled = false;
        try {
            cancelled = transport.wasCancelled();
        } catch (...) {
            /* An owner failure while querying cancellation cannot justify
             * exposing the transport's partially-owned state. */
        }
        if (!cancelled) {
            try {
                transport.abort();
            } catch (...) {
                /* Abort is best effort after the public helper failed. */
            }
        }
        settled = true;
    };
    try {
#endif
    DownloadRangeResponse response{};
    /* A failed begin() is already terminal for the transport.  In
     * particular, do not call abort() here: a public adapter may preserve a
     * distinct cancellation state for the caller to inspect. */
    beginEntered = true;
    if (!transport.begin(request, response)) {
        scrubOutput();
        settled = true;
        return false;
    }
    /* A transport may re-enter its own public abort/cancel path while
     * begin() is executing and still return a syntactically valid response.
     * Observe the terminal cancellation before admitting that response. */
    if (transport.wasCancelled()) {
        scrubOutput();
        settled = true;
        return false;
    }
    if (!response.validFor(request) || response.contentLength > capacity) {
        scrubOutput();
        settled = true;
        transport.abort();
        return false;
    }
    const std::size_t expected =
        static_cast<std::size_t>(response.contentLength);
    while (outputSize < expected) {
        const std::size_t remaining = expected - outputSize;
        const std::size_t chunk = remaining > 64u * 1024u
                                      ? 64u * 1024u : remaining;
        std::size_t bytesRead = 0u;
        if (!transport.read(output + outputSize, chunk, bytesRead) ||
            bytesRead == 0u || bytesRead > chunk) {
            scrubOutput();
            outputSize = 0u;
            /* A public transport may already have transitioned to its
             * terminal cancellation state and performed the upstream abort.
             * Preserve that state so callers can distinguish cancellation
             * from an ordinary read failure via wasCancelled(). */
            const bool cancelled = transport.wasCancelled();
            if (!cancelled) {
                settled = true;
                transport.abort();
            } else {
                settled = true;
            }
            return false;
        }
        outputSize += bytesRead;
        /* A successful callback return must not resurrect a transport that
         * cancelled itself reentrantly after producing a byte. */
        if (transport.wasCancelled()) {
            scrubOutput();
            outputSize = 0u;
            settled = true;
            return false;
        }
    }
    std::uint8_t trailingByte = 0u;
    std::size_t trailingBytes = 0u;
    if (!transport.read(&trailingByte, 1u, trailingBytes) ||
        trailingBytes != 0u) {
        scrubOutput();
        outputSize = 0u;
        const bool cancelled = transport.wasCancelled();
        if (!cancelled) {
            settled = true;
            transport.abort();
        } else {
            settled = true;
        }
        return false;
    }
    if (transport.wasCancelled()) {
        scrubOutput();
        outputSize = 0u;
        settled = true;
        return false;
    }
    settled = true;
    return true;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
    } catch (...) {
        scrubOnOwnerFailure();
        abortAfterOwnerFailure();
        return false;
    }
#endif
}

inline bool parseDownloadContentRange(const std::string& value,
                                      std::uint64_t& start,
                                      std::uint64_t& end,
                                      std::uint64_t& total);
inline bool parseDownloadContentLength(const std::string& value,
                                       std::uint64_t& length);

inline bool makeDownloadRangeResponse(
    const DownloadRangeRequest& request, std::uint16_t statusCode,
    const std::string& contentRange, const std::string& contentLength,
    std::uint64_t generation, const std::string& validator,
    DownloadRangeResponse& output) {
    if (&output.validator == &contentRange ||
        &output.validator == &contentLength ||
        &output.validator == &validator)
        return false;
    output = DownloadRangeResponse{};
    std::uint64_t start = 0u;
    std::uint64_t end = 0u;
    std::uint64_t total = 0u;
    std::uint64_t length = 0u;
    if (!request.valid() ||
        !parseDownloadContentRange(contentRange, start, end, total) ||
        !parseDownloadContentLength(contentLength, length))
        return false;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
    try {
#endif
        DownloadRangeResponse candidate;
        candidate.statusCode = statusCode;
        candidate.contentRangeStart = start;
        candidate.contentRangeEnd = end;
        candidate.contentRangeTotal = total;
        candidate.contentLength = length;
        candidate.generation = generation;
        candidate.validator = validator;
        if (!candidate.validFor(request)) return false;
        output.statusCode = candidate.statusCode;
        output.contentRangeStart = candidate.contentRangeStart;
        output.contentRangeEnd = candidate.contentRangeEnd;
        output.contentRangeTotal = candidate.contentRangeTotal;
        output.contentLength = candidate.contentLength;
        output.generation = candidate.generation;
        output.validator.swap(candidate.validator);
        return true;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
    } catch (const std::bad_alloc&) {
        output = DownloadRangeResponse{};
        return false;
    } catch (...) {
        output = DownloadRangeResponse{};
        return false;
    }
#endif
}

inline bool parseDownloadContentRange(const std::string& value,
                                      std::uint64_t& start,
                                      std::uint64_t& end,
                                      std::uint64_t& total) {
    start = 0u;
    end = 0u;
    total = 0u;
    std::uint64_t parsedStart = 0u;
    std::uint64_t parsedEnd = 0u;
    std::uint64_t parsedTotal = 0u;
    const std::string prefix = "bytes ";
    if (value.size() <= prefix.size() ||
        value.size() > DownloadRangeRequest::kMaxRangeHeaderBytes ||
        value.compare(0u, prefix.size(), prefix) != 0)
        return false;
    std::size_t index = prefix.size();
    auto parse = [&](std::uint64_t& output, char terminator) {
        if (index >= value.size() || value[index] < '0' ||
            value[index] > '9')
            return false;
        output = 0u;
        while (index < value.size() && value[index] >= '0' &&
               value[index] <= '9') {
            const std::uint64_t digit =
                static_cast<std::uint64_t>(value[index] - '0');
            if (output > (UINT64_MAX - digit) / 10u) return false;
            output = output * 10u + digit;
            ++index;
        }
        if (index >= value.size() || value[index] != terminator) return false;
        ++index;
        return true;
    };
    if (!parse(parsedStart, '-') || !parse(parsedEnd, '/')) return false;
    if (index >= value.size() || value[index] < '0' ||
        value[index] > '9')
        return false;
    while (index < value.size() && value[index] >= '0' &&
           value[index] <= '9') {
        const std::uint64_t digit =
            static_cast<std::uint64_t>(value[index] - '0');
        if (parsedTotal > (UINT64_MAX - digit) / 10u) return false;
        parsedTotal = parsedTotal * 10u + digit;
        ++index;
    }
    if (index != value.size() || parsedStart > parsedEnd ||
        parsedTotal == 0u || parsedEnd >= parsedTotal)
        return false;
    start = parsedStart;
    end = parsedEnd;
    total = parsedTotal;
    return true;
}

inline bool parseDownloadContentLength(const std::string& value,
                                       std::uint64_t& length) {
    length = 0u;
    if (value.empty() ||
        value.size() > DownloadRangeRequest::kMaxRangeHeaderBytes)
        return false;
    std::uint64_t parsedLength = 0u;
    for (char character : value) {
        if (character < '0' || character > '9') return false;
        const std::uint64_t digit =
            static_cast<std::uint64_t>(character - '0');
        if (parsedLength > (UINT64_MAX - digit) / 10u) return false;
        parsedLength = parsedLength * 10u + digit;
    }
    if (parsedLength == 0u || parsedLength > DownloadPartialReceipt::kMaxBytes)
        return false;
    length = parsedLength;
    return true;
}

} // namespace RinRuntime

#endif /* RINRUNTIME_DOWNLOAD_RESUME_HPP */
