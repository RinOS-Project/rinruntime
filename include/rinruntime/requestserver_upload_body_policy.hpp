/* SPDX-License-Identifier: MIT */
#ifndef RIN_SHARED_REQUESTSERVER_UPLOAD_BODY_POLICY_HPP
#define RIN_SHARED_REQUESTSERVER_UPLOAD_BODY_POLICY_HPP

#include <stdint.h>

namespace RinRequestServerUploadPolicy {

inline constexpr uint64_t max_body_bytes = UINT64_C(128) * UINT64_C(1024) * UINT64_C(1024);
inline constexpr uint32_t max_chunk_bytes = UINT32_C(64) * UINT32_C(1024);

inline constexpr bool admission_valid(uint64_t expected_length, bool has_source)
{
    return expected_length <= max_body_bytes && (expected_length == 0 || has_source);
}

inline constexpr bool chunk_request_valid(uint32_t maximum_bytes)
{
    return maximum_bytes != 0 && maximum_bytes <= max_chunk_bytes;
}

inline constexpr bool chunk_result_valid(uint64_t delivered, uint64_t expected_length,
                                         uint32_t maximum_bytes, uint64_t count)
{
    if (!chunk_request_valid(maximum_bytes) || delivered > expected_length || count == 0 || count > maximum_bytes)
        return false;
    return count <= expected_length - delivered;
}

inline constexpr bool eof_result_valid(uint64_t delivered, uint64_t expected_length)
{
    return delivered == expected_length;
}

inline constexpr bool trailing_bytes_rejected(uint64_t delivered, uint64_t expected_length,
                                              uint64_t count)
{
    return delivered == expected_length && count != 0;
}

}

#endif
