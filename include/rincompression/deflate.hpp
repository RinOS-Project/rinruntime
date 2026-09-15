/* SPDX-License-Identifier: MIT */
/* Backend-independent, bounded raw DEFLATE encoder for public consumers. */

#ifndef RINCOMPRESSION_DEFLATE_HPP
#define RINCOMPRESSION_DEFLATE_HPP

#include <cstddef>
#include <cstdint>
#include <vector>

namespace RinCompression {

using CancellationFunction = bool (*)(void* context);

enum class DeflateResult : int {
    Ok = 0,
    InvalidArgument = -1,
    Limit = -2,
    Cancelled = -5,
};

/* The generic codec has a bounded, format-independent content budget.  An
 * archive/container owner may impose a smaller limit before calling it. */
static constexpr std::size_t kMaximumBytes = 268435456u;

/*
 * Emit one deterministic raw DEFLATE stream using stored blocks.  This is a
 * public interoperability codec, not an archive/filesystem API: it consumes
 * caller-owned bytes, performs no I/O, and has no archive or service
 * dependency.  Archive writers may wrap it or choose a denser private
 * strategy without changing this contract.
 */
class DeflateEncoder final {
public:
    DeflateResult encode(const std::uint8_t* input,
                         std::size_t inputSize,
                         std::vector<std::uint8_t>& output) const
    {
        return encode(input, inputSize, output, nullptr, nullptr);
    }

    DeflateResult encode(const std::uint8_t* input, std::size_t inputSize,
                         std::vector<std::uint8_t>& output,
                         CancellationFunction cancellation,
                         void* cancellationContext) const
    {
        constexpr std::size_t kStoredBlockPayload = 65535u;
        output.clear();
        if (input == nullptr && inputSize != 0u)
            return DeflateResult::InvalidArgument;
        if (inputSize > kMaximumBytes ||
            inputSize > static_cast<std::size_t>(UINT32_MAX))
            return DeflateResult::Limit;

        std::size_t offset = 0u;
        do {
            if (cancellation != nullptr && cancellation(cancellationContext)) {
                output.clear();
                return DeflateResult::Cancelled;
            }
            const std::size_t remaining = inputSize - offset;
            const std::size_t blockSize = remaining > kStoredBlockPayload
                ? kStoredBlockPayload : remaining;
            const bool finalBlock = blockSize == remaining;
            if (output.size() > kMaximumBytes ||
                kMaximumBytes - output.size() < blockSize + 5u) {
                output.clear();
                return DeflateResult::Limit;
            }

            /* BFINAL plus BTYPE=00, followed by zero padding to the byte. */
            output.push_back(finalBlock ? 0x01u : 0x00u);
            const std::uint16_t length = static_cast<std::uint16_t>(blockSize);
            const std::uint16_t inverse = static_cast<std::uint16_t>(~length);
            output.push_back(static_cast<std::uint8_t>(length));
            output.push_back(static_cast<std::uint8_t>(length >> 8u));
            output.push_back(static_cast<std::uint8_t>(inverse));
            output.push_back(static_cast<std::uint8_t>(inverse >> 8u));
            if (blockSize != 0u)
                output.insert(output.end(), input + offset,
                              input + offset + blockSize);
            offset += blockSize;
        } while (offset < inputSize || inputSize == 0u);

        if (cancellation != nullptr && cancellation(cancellationContext)) {
            output.clear();
            return DeflateResult::Cancelled;
        }
        return DeflateResult::Ok;
    }
};

} // namespace RinCompression

#endif /* RINCOMPRESSION_DEFLATE_HPP */
