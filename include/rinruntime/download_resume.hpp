/* SPDX-License-Identifier: MIT */
/* Bounded, renderer-independent durable partial-download receipt. */

#ifndef RINRUNTIME_DOWNLOAD_RESUME_HPP
#define RINRUNTIME_DOWNLOAD_RESUME_HPP

#if defined(RIN_FREESTANDING) || defined(RINCXX_CSTDDEF_H) || \
    defined(RINCXX_STRING_H)
#include "../../../../libs/libcxx/cstddef.h"
#include "../../../../libs/libcxx/cstdint.h"
#include "../../../../libs/libcxx/string.h"
#else
#include <cstddef>
#include <cstdint>
#include <string>
#include <cstring>
#endif

namespace RinRuntime {

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
        outputSize = 0u;
        if (output == nullptr || capacity < kWireSize || !valid()) return false;
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
        output.requestId = get64(input + 8u);
        output.totalBytes = get64(input + 16u);
        output.committedBytes = get64(input + 24u);
        output.generation = get64(input + 32u);
        output.validator.assign(reinterpret_cast<const char*>(input + 44u),
                                validatorSize);
        if (!output.valid()) {
            output.clear();
            return false;
        }
        return true;
    }

private:
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
        clear();
        if (!receipt.matches(expectedRequestId, expectedGeneration,
                             expectedValidator, receipt.committedBytes))
            return false;
        requestId = receipt.requestId;
        generation = receipt.generation;
        offset = receipt.committedBytes;
        totalBytes = receipt.totalBytes;
        validator = receipt.validator;
        return valid();
    }

    bool makeRangeHeader(std::string& output) const {
        output.clear();
        if (!valid()) return false;
        output = "bytes=" + std::to_string(offset) + "-";
        return output.size() < kMaxRangeHeaderBytes;
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
    output = DownloadRangeResponse{};
    std::uint64_t start = 0u;
    std::uint64_t end = 0u;
    std::uint64_t total = 0u;
    std::uint64_t length = 0u;
    if (!request.valid() ||
        !parseDownloadContentRange(contentRange, start, end, total) ||
        !parseDownloadContentLength(contentLength, length))
        return false;
    output.statusCode = statusCode;
    output.contentRangeStart = start;
    output.contentRangeEnd = end;
    output.contentRangeTotal = total;
    output.contentLength = length;
    output.generation = generation;
    output.validator = validator;
    if (!output.validFor(request)) {
        output = DownloadRangeResponse{};
        return false;
    }
    return true;
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
    if (value.empty()) return false;
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
