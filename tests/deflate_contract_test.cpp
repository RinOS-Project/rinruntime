/* SPDX-License-Identifier: MIT */
/* Contract test for the standalone public compression entry point. */

#include "../include/rincompression/deflate.hpp"
#include "../include/rinruntime/archive_deflate.hpp"

#include <cassert>
#include <cstdint>
#include <string>
#include <stdexcept>
#include <vector>

static bool cancelNow(void* context)
{
    return context != nullptr &&
           *static_cast<const std::uint32_t*>(context) != 0u;
}

static bool throwingCancel(void*)
{
    throw std::runtime_error("cancellation callback failure");
}

int main()
{
    const std::uint8_t payload[] = {'h', 'e', 'l', 'l', 'o'};
    std::vector<std::uint8_t> encoded;
    RinCompression::DeflateEncoder encoder;
    assert(encoder.encode(payload, sizeof(payload), encoded) ==
           RinCompression::DeflateResult::Ok);
    assert(!encoded.empty());

    std::string decoded;
    RinRuntime::ArchiveDeflateDecoder decoder;
    assert(decoder.decode(encoded.data(), encoded.size(), sizeof(payload),
                          RinRuntime::rinruntime_archive_crc32(
                              payload, sizeof(payload)),
                          decoded) == RinRuntime::ArchiveDeflateResult::Ok);
    assert(decoded == "hello");

    std::uint32_t cancelled = 1u;
    assert(encoder.encode(payload, sizeof(payload), encoded, cancelNow,
                          &cancelled) == RinCompression::DeflateResult::Cancelled);
    assert(encoded.empty());
    encoded.assign(1u, 0xa5u);
    assert(encoder.encode(payload, sizeof(payload), encoded, throwingCancel,
                          nullptr) == RinCompression::DeflateResult::Cancelled);
    assert(encoded.empty());
    assert(encoder.encode(nullptr, 1u, encoded) ==
           RinCompression::DeflateResult::InvalidArgument);

    return 0;
}
