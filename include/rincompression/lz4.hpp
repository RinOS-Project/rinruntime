/* SPDX-License-Identifier: MIT */
/* Backend-independent, bounded LZ4 block decoder for public consumers. */

#ifndef RINCOMPRESSION_LZ4_HPP
#define RINCOMPRESSION_LZ4_HPP

#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

namespace RinCompression {

using Lz4CancellationFunction = bool (*)(void* context);

enum class Lz4Result : int {
    Ok = 0,
    InvalidArgument = -1,
    Malformed = -3,
    Limit = -4,
    Cancelled = -5,
};

/* This is the raw LZ4 block format, not the LZ4 frame/container format.  The
 * caller owns the compressed bytes and receives a failure-atomic output.  A
 * frame header, checksum, content-size field, and filesystem destination are
 * intentionally outside this reusable codec contract. */
static constexpr std::size_t kLz4MaximumBytes = 268435456u;

class Lz4BlockDecoder final {
    static Lz4Result fail(std::vector<std::uint8_t>& output,
                          Lz4Result result) {
        output.clear();
        return result;
    }

    static bool cancelled(Lz4CancellationFunction function, void* context) {
        return function != nullptr && function(context);
    }

public:
    Lz4Result decode(const std::uint8_t* compressed,
                     std::size_t compressedSize,
                     std::vector<std::uint8_t>& output) const {
        return decode(compressed, compressedSize, output,
                      kLz4MaximumBytes, nullptr, nullptr);
    }

    Lz4Result decode(const std::uint8_t* compressed,
                     std::size_t compressedSize,
                     std::vector<std::uint8_t>& output,
                     std::size_t maximumOutputBytes,
                     Lz4CancellationFunction cancellation,
                     void* cancellationContext) const {
        std::size_t position = 0u;
        output.clear();
        if (compressed == nullptr && compressedSize != 0u)
            return Lz4Result::InvalidArgument;
        if (compressedSize > kLz4MaximumBytes ||
            maximumOutputBytes > kLz4MaximumBytes)
            return Lz4Result::Limit;

        while (position < compressedSize) {
            if (cancelled(cancellation, cancellationContext))
                return fail(output, Lz4Result::Cancelled);

            const std::uint8_t token = compressed[position++];
            std::size_t literalLength = token >> 4u;
            if (literalLength == 15u) {
                for (;;) {
                    if (position >= compressedSize)
                        return fail(output, Lz4Result::Malformed);
                    const std::size_t extension = compressed[position++];
                    if (literalLength >
                        std::numeric_limits<std::size_t>::max() - extension)
                        return fail(output, Lz4Result::Limit);
                    literalLength += extension;
                    if (extension != 255u) break;
                }
            }
            if (literalLength > compressedSize - position)
                return fail(output, Lz4Result::Malformed);
            if (literalLength > maximumOutputBytes - output.size())
                return fail(output, Lz4Result::Limit);
            output.insert(output.end(), compressed + position,
                          compressed + position + literalLength);
            position += literalLength;

            /* The final sequence contains literals only. */
            if (position == compressedSize) break;
            if (compressedSize - position < 2u)
                return fail(output, Lz4Result::Malformed);
            const std::size_t offset =
                static_cast<std::size_t>(compressed[position]) |
                static_cast<std::size_t>(compressed[position + 1u]) << 8u;
            position += 2u;
            if (offset == 0u || offset > output.size())
                return fail(output, Lz4Result::Malformed);

            std::size_t matchLength = (token & 0x0fu) + 4u;
            if ((token & 0x0fu) == 15u) {
                for (;;) {
                    if (position >= compressedSize)
                        return fail(output, Lz4Result::Malformed);
                    const std::size_t extension = compressed[position++];
                    if (matchLength >
                        std::numeric_limits<std::size_t>::max() - extension)
                        return fail(output, Lz4Result::Limit);
                    matchLength += extension;
                    if (extension != 255u) break;
                }
            }
            if (matchLength > maximumOutputBytes - output.size())
                return fail(output, Lz4Result::Limit);
            for (std::size_t index = 0u; index < matchLength; ++index) {
                if ((index & 0xffu) == 0u &&
                    cancelled(cancellation, cancellationContext))
                    return fail(output, Lz4Result::Cancelled);
                const std::size_t source = output.size() - offset;
                output.push_back(output[source]);
            }
            /* LZ4 requires another final literal sequence after a match. */
            if (position == compressedSize)
                return fail(output, Lz4Result::Malformed);
        }

        if (cancelled(cancellation, cancellationContext))
            return fail(output, Lz4Result::Cancelled);
        return Lz4Result::Ok;
    }
};

} // namespace RinCompression

#endif /* RINCOMPRESSION_LZ4_HPP */
