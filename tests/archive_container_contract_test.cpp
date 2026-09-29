/* SPDX-License-Identifier: MIT */

#include "../include/rinruntime/archive_container.hpp"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

static void put16(std::vector<std::uint8_t>& bytes, std::size_t offset,
                  std::uint16_t value)
{
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1u] = static_cast<std::uint8_t>(value >> 8u);
}

static void put32(std::vector<std::uint8_t>& bytes, std::size_t offset,
                  std::uint32_t value)
{
    for (unsigned index = 0u; index != 4u; ++index)
        bytes[offset + index] = static_cast<std::uint8_t>(value >> (index * 8u));
}

static void put64(std::vector<std::uint8_t>& bytes, std::size_t offset,
                  std::uint64_t value)
{
    for (unsigned index = 0u; index != 8u; ++index)
        bytes[offset + index] =
            static_cast<std::uint8_t>(value >> (index * 8u));
}

static void put7zUInt64(std::vector<std::uint8_t>& bytes,
                        std::uint64_t value)
{
    if (value < 0x80u) {
        bytes.push_back(static_cast<std::uint8_t>(value));
        return;
    }
    assert(value < 0x4000u);
    bytes.push_back(static_cast<std::uint8_t>(0x80u | (value >> 8u)));
    bytes.push_back(static_cast<std::uint8_t>(value));
}

static void putOctal(std::uint8_t* field, std::size_t size,
                     std::uint64_t value)
{
    std::memset(field, '0', size);
    if (size != 0u) field[size - 1u] = '\0';
    for (std::size_t index = size - 1u; index != 0u && value != 0u; --index) {
        field[index - 1u] = static_cast<std::uint8_t>('0' + (value & 7u));
        value >>= 3u;
    }
}

static bool stopImmediately(void*) { return true; }

struct DeadlineOnce {
    bool fired = false;
};

static bool stopOnce(void* context)
{
    auto* state = static_cast<DeadlineOnce*>(context);
    if (state == nullptr || state->fired)
        return false;
    state->fired = true;
    return true;
}

static std::vector<std::uint8_t> makeTar()
{
    std::vector<std::uint8_t> bytes(2048u, 0u);
    std::uint8_t* header = bytes.data();
    std::memcpy(header, "docs/readme.txt", 15u);
    putOctal(header + 100u, 8u, 0644u);
    putOctal(header + 124u, 12u, 5u);
    std::memcpy(header + 257u, "ustar", 5u);
    std::memset(header + 148u, ' ', 8u);
    std::uint64_t checksum = 0u;
    for (std::size_t index = 0u; index != 512u; ++index)
        checksum += header[index];
    putOctal(header + 148u, 8u, checksum);
    std::memcpy(bytes.data() + 512u, "hello", 5u);
    return bytes;
}

static std::vector<std::uint8_t> makeZip()
{
    const std::uint8_t payload[] = {'h', 'e', 'l', 'l', 'o'};
    const char name[] = "a.txt";
    constexpr std::size_t local = 0u;
    constexpr std::size_t central = 40u;
    constexpr std::size_t eocd = 91u;
    std::vector<std::uint8_t> bytes(eocd + 22u, 0u);
    const std::uint32_t crc = RinRuntime::rinruntime_archive_crc32(
        payload, sizeof(payload));

    put32(bytes, local, 0x04034b50u);
    put16(bytes, local + 4u, 20u);
    put16(bytes, local + 8u, 0u);
    put32(bytes, local + 14u, crc);
    put32(bytes, local + 18u, sizeof(payload));
    put32(bytes, local + 22u, sizeof(payload));
    put16(bytes, local + 26u, sizeof(name) - 1u);
    std::memcpy(bytes.data() + local + 30u, name, sizeof(name) - 1u);
    std::memcpy(bytes.data() + local + 35u, payload, sizeof(payload));

    put32(bytes, central, 0x02014b50u);
    put16(bytes, central + 4u, 20u);
    put16(bytes, central + 6u, 20u);
    put32(bytes, central + 16u, crc);
    put32(bytes, central + 20u, sizeof(payload));
    put32(bytes, central + 24u, sizeof(payload));
    put16(bytes, central + 28u, sizeof(name) - 1u);
    put32(bytes, central + 42u, 0u);
    std::memcpy(bytes.data() + central + 46u, name, sizeof(name) - 1u);

    put32(bytes, eocd, 0x06054b50u);
    put16(bytes, eocd + 8u, 1u);
    put16(bytes, eocd + 10u, 1u);
    put32(bytes, eocd + 12u, 51u);
    put32(bytes, eocd + 16u, central);
    return bytes;
}

static std::vector<std::uint8_t> makeGzip(const std::uint8_t* payload,
                                          std::size_t payloadSize)
{
    const std::size_t rawSize = payloadSize + 5u;
    std::vector<std::uint8_t> bytes(10u + rawSize + 8u, 0u);
    bytes[0] = 0x1fu;
    bytes[1] = 0x8bu;
    bytes[2] = 8u;
    bytes[9] = 255u;
    bytes[10] = 0x01u;
    bytes[11] = static_cast<std::uint8_t>(payloadSize);
    bytes[12] = static_cast<std::uint8_t>(payloadSize >> 8u);
    bytes[13] = static_cast<std::uint8_t>(~payloadSize);
    bytes[14] = static_cast<std::uint8_t>(~payloadSize >> 8u);
    std::memcpy(bytes.data() + 15u, payload, payloadSize);
    const std::uint32_t crc = RinRuntime::rinruntime_archive_crc32(
        payload, payloadSize);
    for (unsigned index = 0u; index != 4u; ++index) {
        bytes[15u + payloadSize + index] =
            static_cast<std::uint8_t>(crc >> (index * 8u));
        bytes[19u + payloadSize + index] =
            static_cast<std::uint8_t>(payloadSize >> (index * 8u));
    }
    return bytes;
}

static std::vector<std::uint8_t> make7zStored(bool copy_chain = false,
                                              bool lzma2 = false,
                                              bool multi_entry = false)
{
    assert(!(copy_chain && lzma2) && (!multi_entry || (!copy_chain && !lzma2)));
    const std::uint8_t signature[] = {
        0x37u, 0x7au, 0xbcu, 0xafu, 0x27u, 0x1cu};
    const std::uint8_t payload[] = {'h', 'e', 'l', 'l', 'o'};
    const std::uint8_t multi_payload[] = {
        'h', 'e', 'l', 'l', 'o', 'w', 'o', 'r', 'l', 'd', '!'};
    const std::uint8_t lzma2_payload[] = {
        0x01u, 0x04u, 0x00u, 'h', 'e', 'l', 'l', 'o', 0x00u};
    const std::uint8_t* packed = multi_entry
        ? multi_payload
        : lzma2 ? lzma2_payload : payload;
    const std::size_t packed_size =
        multi_entry ? sizeof(multi_payload)
                    : lzma2 ? sizeof(lzma2_payload) : sizeof(payload);
    std::vector<std::uint8_t> header;
    header.push_back(0x01u); /* Header */
    header.push_back(0x04u); /* MainStreamsInfo */
    header.push_back(0x06u); /* PackInfo */
    put7zUInt64(header, 0u); /* PackPos */
    put7zUInt64(header, 1u); /* NumPackStreams */
    header.push_back(0x09u); /* Size */
    put7zUInt64(header, packed_size);
    header.push_back(0x0au); /* Pack CRC */
    header.push_back(1u);
    header.resize(header.size() + 4u);
    put32(header, header.size() - 4u,
          RinRuntime::rinruntime_archive_crc32(packed, packed_size));
    header.push_back(0x00u); /* PackInfo end */
    header.push_back(0x07u); /* UnPackInfo */
    header.push_back(0x0bu); /* Folder */
    put7zUInt64(header, 1u); /* NumFolders */
    header.push_back(0u); /* folders are in this header */
    put7zUInt64(header, copy_chain ? 2u : 1u); /* NumCoders */
    if (lzma2) {
        header.push_back(0x21u); /* one-byte LZMA2 method ID + properties */
        header.push_back(0x21u);
        header.push_back(0x01u); /* one dictionary-property byte */
        header.push_back(0x00u); /* 4 KiB dictionary */
    } else {
        header.push_back(0x01u); /* one-byte method ID, no properties */
        header.push_back(0x00u); /* Copy coder */
    }
    if (copy_chain) {
        header.push_back(0x01u); /* second one-byte Copy method ID */
        header.push_back(0x00u);
        put7zUInt64(header, 1u); /* second coder input <- first output */
        put7zUInt64(header, 0u);
    }
    header.push_back(0x0cu); /* CodersUnpackSize */
    put7zUInt64(header, multi_entry ? sizeof(multi_payload) : sizeof(payload));
    if (copy_chain)
        put7zUInt64(header, sizeof(payload));
    header.push_back(0x0au); /* Folder CRC */
    header.push_back(1u);
    header.resize(header.size() + 4u);
    put32(header, header.size() - 4u,
          RinRuntime::rinruntime_archive_crc32(
              multi_entry ? multi_payload : payload,
              multi_entry ? sizeof(multi_payload) : sizeof(payload)));
    header.push_back(0x00u); /* UnPackInfo end */
    if (multi_entry) {
        header.push_back(0x08u); /* SubStreamsInfo */
        header.push_back(0x0du); /* NumUnpackStream */
        put7zUInt64(header, 2u);
        header.push_back(0x09u); /* Size */
        put7zUInt64(header, sizeof(payload));
        header.push_back(0x0au); /* Substream CRCs */
        header.push_back(1u);
        header.resize(header.size() + 4u);
        put32(header, header.size() - 4u,
              RinRuntime::rinruntime_archive_crc32(payload, sizeof(payload)));
        header.resize(header.size() + 4u);
        put32(header, header.size() - 4u,
              RinRuntime::rinruntime_archive_crc32(
                  multi_payload + sizeof(payload),
                  sizeof(multi_payload) - sizeof(payload)));
        header.push_back(0x00u); /* SubStreamsInfo end */
    }
    header.push_back(0x00u); /* MainStreamsInfo end */
    header.push_back(0x05u); /* FilesInfo */
    put7zUInt64(header, multi_entry ? 2u : 1u); /* NumFiles */
    header.push_back(0x00u); /* FilesInfo properties end */
    header.push_back(0x00u); /* Header end */

    std::vector<std::uint8_t> bytes(32u + packed_size + header.size(), 0u);
    std::memcpy(bytes.data(), signature, sizeof(signature));
    bytes[7u] = 4u;
    std::memcpy(bytes.data() + 32u, packed, packed_size);
    const std::size_t headerOffset = 32u + packed_size;
    std::memcpy(bytes.data() + headerOffset, header.data(), header.size());
    put64(bytes, 12u, packed_size);
    put64(bytes, 20u, header.size());
    put32(bytes, 28u,
          RinRuntime::rinruntime_archive_crc32(bytes.data() + headerOffset,
                                                header.size()));
    put32(bytes, 8u,
          RinRuntime::rinruntime_archive_crc32(bytes.data() + 12u, 20u));
    return bytes;
}

static std::vector<std::uint8_t> make7zMultiFolderCopy()
{
    const std::uint8_t signature[] = {
        0x37u, 0x7au, 0xbcu, 0xafu, 0x27u, 0x1cu};
    const std::uint8_t first[] = {'h', 'e', 'l', 'l', 'o'};
    const std::uint8_t second[] = {'w', 'o', 'r', 'l', 'd'};
    std::vector<std::uint8_t> header;
    header.push_back(0x01u); /* Header */
    header.push_back(0x04u); /* MainStreamsInfo */
    header.push_back(0x06u); /* PackInfo */
    put7zUInt64(header, 0u); /* PackPos */
    put7zUInt64(header, 2u); /* NumPackStreams */
    header.push_back(0x09u); /* Size */
    put7zUInt64(header, sizeof(first));
    put7zUInt64(header, sizeof(second));
    header.push_back(0x0au); /* Pack CRC */
    header.push_back(1u);
    header.resize(header.size() + 8u);
    put32(header, header.size() - 8u,
          RinRuntime::rinruntime_archive_crc32(first, sizeof(first)));
    put32(header, header.size() - 4u,
          RinRuntime::rinruntime_archive_crc32(second, sizeof(second)));
    header.push_back(0x00u); /* PackInfo end */
    header.push_back(0x07u); /* UnPackInfo */
    header.push_back(0x0bu); /* Folder */
    put7zUInt64(header, 2u); /* NumFolders */
    header.push_back(0u); /* folders are in this header */
    for (unsigned folder = 0u; folder != 2u; ++folder) {
        header.push_back(1u); /* NumCoders */
        header.push_back(0x01u); /* one-byte Copy method ID */
        header.push_back(0x00u); /* Copy */
    }
    header.push_back(0x0cu); /* CodersUnpackSize */
    put7zUInt64(header, sizeof(first));
    put7zUInt64(header, sizeof(second));
    header.push_back(0x0au); /* Folder CRC */
    header.push_back(1u);
    header.resize(header.size() + 8u);
    put32(header, header.size() - 8u,
          RinRuntime::rinruntime_archive_crc32(first, sizeof(first)));
    put32(header, header.size() - 4u,
          RinRuntime::rinruntime_archive_crc32(second, sizeof(second)));
    header.push_back(0x00u); /* UnPackInfo end */
    header.push_back(0x00u); /* MainStreamsInfo end */
    header.push_back(0x05u); /* FilesInfo */
    put7zUInt64(header, 2u); /* NumFiles */
    header.push_back(0x00u); /* FilesInfo properties end */
    header.push_back(0x00u); /* Header end */

    const std::size_t packed_size = sizeof(first) + sizeof(second);
    std::vector<std::uint8_t> bytes(32u + packed_size + header.size(), 0u);
    std::memcpy(bytes.data(), signature, sizeof(signature));
    bytes[7u] = 4u;
    std::memcpy(bytes.data() + 32u, first, sizeof(first));
    std::memcpy(bytes.data() + 32u + sizeof(first), second, sizeof(second));
    const std::size_t header_offset = 32u + packed_size;
    std::memcpy(bytes.data() + header_offset, header.data(), header.size());
    put64(bytes, 12u, packed_size);
    put64(bytes, 20u, header.size());
    put32(bytes, 28u,
          RinRuntime::rinruntime_archive_crc32(bytes.data() + header_offset,
                                                header.size()));
    put32(bytes, 8u,
          RinRuntime::rinruntime_archive_crc32(bytes.data() + 12u, 20u));
    return bytes;
}

static std::vector<std::uint8_t> make7zMultiFolderCopySubstreams()
{
    const std::uint8_t signature[] = {
        0x37u, 0x7au, 0xbcu, 0xafu, 0x27u, 0x1cu};
    const std::uint8_t first[] = {'h', 'e', 'l', 'l', 'o', '!'};
    const std::uint8_t second[] = {'w', 'o', 'r', 'l', 'd', '?'};
    const std::uint8_t first_substream[] = {'h', 'e', 'l', 'l', 'o'};
    const std::uint8_t second_substream[] = {'w', 'o', 'r', 'l', 'd'};
    std::vector<std::uint8_t> header;
    header.push_back(0x01u); /* Header */
    header.push_back(0x04u); /* MainStreamsInfo */
    header.push_back(0x06u); /* PackInfo */
    put7zUInt64(header, 0u); /* PackPos */
    put7zUInt64(header, 2u); /* NumPackStreams */
    header.push_back(0x09u); /* Size */
    put7zUInt64(header, sizeof(first));
    put7zUInt64(header, sizeof(second));
    header.push_back(0x0au); /* Pack CRC */
    header.push_back(1u);
    header.resize(header.size() + 8u);
    put32(header, header.size() - 8u,
          RinRuntime::rinruntime_archive_crc32(first, sizeof(first)));
    put32(header, header.size() - 4u,
          RinRuntime::rinruntime_archive_crc32(second, sizeof(second)));
    header.push_back(0x00u); /* PackInfo end */
    header.push_back(0x07u); /* UnPackInfo */
    header.push_back(0x0bu); /* Folder */
    put7zUInt64(header, 2u); /* NumFolders */
    header.push_back(0u); /* folders are in this header */
    for (unsigned folder = 0u; folder != 2u; ++folder) {
        header.push_back(1u); /* NumCoders */
        header.push_back(0x01u); /* one-byte Copy method ID */
        header.push_back(0x00u); /* Copy */
    }
    header.push_back(0x0cu); /* CodersUnpackSize */
    put7zUInt64(header, sizeof(first));
    put7zUInt64(header, sizeof(second));
    header.push_back(0x00u); /* UnPackInfo end, no folder CRC */
    header.push_back(0x08u); /* SubStreamsInfo */
    header.push_back(0x0du); /* NumUnpackStream */
    put7zUInt64(header, 2u);
    put7zUInt64(header, 2u);
    header.push_back(0x09u); /* Size */
    put7zUInt64(header, sizeof(first_substream));
    put7zUInt64(header, sizeof(second_substream));
    header.push_back(0x0au); /* Substream CRCs */
    header.push_back(1u);
    header.resize(header.size() + 16u);
    put32(header, header.size() - 16u,
          RinRuntime::rinruntime_archive_crc32(first_substream,
                                                sizeof(first_substream)));
    put32(header, header.size() - 12u,
          RinRuntime::rinruntime_archive_crc32(first + sizeof(first_substream),
                                                1u));
    put32(header, header.size() - 8u,
          RinRuntime::rinruntime_archive_crc32(second_substream,
                                                sizeof(second_substream)));
    put32(header, header.size() - 4u,
          RinRuntime::rinruntime_archive_crc32(second + sizeof(second_substream),
                                                1u));
    header.push_back(0x00u); /* SubStreamsInfo end */
    header.push_back(0x00u); /* MainStreamsInfo end */
    header.push_back(0x05u); /* FilesInfo */
    put7zUInt64(header, 4u); /* NumFiles */
    header.push_back(0x00u); /* FilesInfo properties end */
    header.push_back(0x00u); /* Header end */

    const std::size_t packed_size = sizeof(first) + sizeof(second);
    std::vector<std::uint8_t> bytes(32u + packed_size + header.size(), 0u);
    std::memcpy(bytes.data(), signature, sizeof(signature));
    bytes[7u] = 4u;
    std::memcpy(bytes.data() + 32u, first, sizeof(first));
    std::memcpy(bytes.data() + 32u + sizeof(first), second, sizeof(second));
    const std::size_t header_offset = 32u + packed_size;
    std::memcpy(bytes.data() + header_offset, header.data(), header.size());
    put64(bytes, 12u, packed_size);
    put64(bytes, 20u, header.size());
    put32(bytes, 28u,
          RinRuntime::rinruntime_archive_crc32(bytes.data() + header_offset,
                                                header.size()));
    put32(bytes, 8u,
          RinRuntime::rinruntime_archive_crc32(bytes.data() + 12u, 20u));
    return bytes;
}

static std::vector<std::uint8_t> make7zMultiFolderDelta()
{
    const std::uint8_t signature[] = {
        0x37u, 0x7au, 0xbcu, 0xafu, 0x27u, 0x1cu};
    const std::uint8_t first[] = {0x68u, 0xfdu, 0x07u,
                                  0x00u, 0x03u, 0xb2u};
    const std::uint8_t second[] = {0x77u, 0xf8u, 0x03u,
                                   0xfau, 0xf8u, 0xdbu};
    const std::uint8_t first_decoded[] = {'h', 'e', 'l', 'l', 'o', '!'};
    const std::uint8_t second_decoded[] = {'w', 'o', 'r', 'l', 'd', '?'};
    std::vector<std::uint8_t> header;
    header.push_back(0x01u); /* Header */
    header.push_back(0x04u); /* MainStreamsInfo */
    header.push_back(0x06u); /* PackInfo */
    put7zUInt64(header, 0u); /* PackPos */
    put7zUInt64(header, 2u); /* NumPackStreams */
    header.push_back(0x09u); /* Size */
    put7zUInt64(header, sizeof(first));
    put7zUInt64(header, sizeof(second));
    header.push_back(0x0au); /* Pack CRC */
    header.push_back(1u);
    header.resize(header.size() + 8u);
    put32(header, header.size() - 8u,
          RinRuntime::rinruntime_archive_crc32(first, sizeof(first)));
    put32(header, header.size() - 4u,
          RinRuntime::rinruntime_archive_crc32(second, sizeof(second)));
    header.push_back(0x00u); /* PackInfo end */
    header.push_back(0x07u); /* UnPackInfo */
    header.push_back(0x0bu); /* Folder */
    put7zUInt64(header, 2u); /* NumFolders */
    header.push_back(0u); /* folders are in this header */
    for (unsigned folder = 0u; folder != 2u; ++folder) {
        header.push_back(1u); /* NumCoders */
        header.push_back(0x21u); /* one-byte Delta method + property */
        header.push_back(0x03u); /* Delta */
        header.push_back(1u); /* one property byte */
        header.push_back(0u); /* distance 1 */
    }
    header.push_back(0x0cu); /* CodersUnpackSize */
    put7zUInt64(header, sizeof(first_decoded));
    put7zUInt64(header, sizeof(second_decoded));
    header.push_back(0x0au); /* decoded folder CRC */
    header.push_back(1u);
    header.resize(header.size() + 8u);
    put32(header, header.size() - 8u,
          RinRuntime::rinruntime_archive_crc32(first_decoded,
                                                sizeof(first_decoded)));
    put32(header, header.size() - 4u,
          RinRuntime::rinruntime_archive_crc32(second_decoded,
                                                sizeof(second_decoded)));
    header.push_back(0x00u); /* UnPackInfo end */
    header.push_back(0x00u); /* MainStreamsInfo end */
    header.push_back(0x05u); /* FilesInfo */
    put7zUInt64(header, 2u); /* NumFiles */
    header.push_back(0x00u); /* FilesInfo properties end */
    header.push_back(0x00u); /* Header end */

    const std::size_t packed_size = sizeof(first) + sizeof(second);
    std::vector<std::uint8_t> bytes(32u + packed_size + header.size(), 0u);
    std::memcpy(bytes.data(), signature, sizeof(signature));
    bytes[7u] = 4u;
    std::memcpy(bytes.data() + 32u, first, sizeof(first));
    std::memcpy(bytes.data() + 32u + sizeof(first), second, sizeof(second));
    const std::size_t header_offset = 32u + packed_size;
    std::memcpy(bytes.data() + header_offset, header.data(), header.size());
    put64(bytes, 12u, packed_size);
    put64(bytes, 20u, header.size());
    put32(bytes, 28u,
          RinRuntime::rinruntime_archive_crc32(bytes.data() + header_offset,
                                                header.size()));
    put32(bytes, 8u,
          RinRuntime::rinruntime_archive_crc32(bytes.data() + 12u, 20u));
    return bytes;
}

static std::vector<std::uint8_t> make7zMultiFolderCopyChain()
{
    const std::uint8_t signature[] = {
        0x37u, 0x7au, 0xbcu, 0xafu, 0x27u, 0x1cu};
    const std::uint8_t first[] = {'h', 'e', 'l', 'l', 'o'};
    const std::uint8_t second[] = {'w', 'o', 'r', 'l', 'd'};
    std::vector<std::uint8_t> header;
    header.push_back(0x01u); /* Header */
    header.push_back(0x04u); /* MainStreamsInfo */
    header.push_back(0x06u); /* PackInfo */
    put7zUInt64(header, 0u); /* PackPos */
    put7zUInt64(header, 2u); /* NumPackStreams */
    header.push_back(0x09u); /* Size */
    put7zUInt64(header, sizeof(first));
    put7zUInt64(header, sizeof(second));
    header.push_back(0x0au); /* Pack CRC */
    header.push_back(1u);
    header.resize(header.size() + 8u);
    put32(header, header.size() - 8u,
          RinRuntime::rinruntime_archive_crc32(first, sizeof(first)));
    put32(header, header.size() - 4u,
          RinRuntime::rinruntime_archive_crc32(second, sizeof(second)));
    header.push_back(0x00u); /* PackInfo end */
    header.push_back(0x07u); /* UnPackInfo */
    header.push_back(0x0bu); /* Folder */
    put7zUInt64(header, 2u); /* NumFolders */
    header.push_back(0u); /* folders are in this header */
    for (unsigned folder = 0u; folder != 2u; ++folder) {
        put7zUInt64(header, 2u); /* NumCoders */
        for (unsigned coder = 0u; coder != 2u; ++coder) {
            header.push_back(0x01u); /* one-byte Copy method ID */
            header.push_back(0x00u); /* Copy */
        }
        put7zUInt64(header, 1u); /* second coder input */
        put7zUInt64(header, 0u); /* first coder output */
    }
    header.push_back(0x0cu); /* CodersUnpackSize */
    put7zUInt64(header, sizeof(first));
    put7zUInt64(header, sizeof(first));
    put7zUInt64(header, sizeof(second));
    put7zUInt64(header, sizeof(second));
    header.push_back(0x0au); /* decoded folder CRC */
    header.push_back(1u);
    header.resize(header.size() + 8u);
    put32(header, header.size() - 8u,
          RinRuntime::rinruntime_archive_crc32(first, sizeof(first)));
    put32(header, header.size() - 4u,
          RinRuntime::rinruntime_archive_crc32(second, sizeof(second)));
    header.push_back(0x00u); /* UnPackInfo end */
    header.push_back(0x00u); /* MainStreamsInfo end */
    header.push_back(0x05u); /* FilesInfo */
    put7zUInt64(header, 2u); /* NumFiles */
    header.push_back(0x00u); /* FilesInfo properties end */
    header.push_back(0x00u); /* Header end */

    const std::size_t packed_size = sizeof(first) + sizeof(second);
    std::vector<std::uint8_t> bytes(32u + packed_size + header.size(), 0u);
    std::memcpy(bytes.data(), signature, sizeof(signature));
    bytes[7u] = 4u;
    std::memcpy(bytes.data() + 32u, first, sizeof(first));
    std::memcpy(bytes.data() + 32u + sizeof(first), second, sizeof(second));
    const std::size_t header_offset = 32u + packed_size;
    std::memcpy(bytes.data() + header_offset, header.data(), header.size());
    put64(bytes, 12u, packed_size);
    put64(bytes, 20u, header.size());
    put32(bytes, 28u,
          RinRuntime::rinruntime_archive_crc32(bytes.data() + header_offset,
                                                header.size()));
    put32(bytes, 8u,
          RinRuntime::rinruntime_archive_crc32(bytes.data() + 12u, 20u));
    return bytes;
}

static std::vector<std::uint8_t> make7zBcj2()
{
    const std::uint8_t signature[] = {
        0x37u, 0x7au, 0xbcu, 0xafu, 0x27u, 0x1cu};
    const std::uint8_t main_stream[] = {0xe8u, 0x00u, 0x00u, 0x00u,
                                        0x00u};
    const std::uint8_t rc_stream[] = {0x00u, 0x00u, 0x00u, 0x00u, 0x01u};
    std::vector<std::uint8_t> header;
    header.push_back(0x01u); /* Header */
    header.push_back(0x04u); /* MainStreamsInfo */
    header.push_back(0x06u); /* PackInfo */
    put7zUInt64(header, 0u); /* PackPos */
    put7zUInt64(header, 4u); /* NumPackStreams */
    header.push_back(0x09u); /* Size */
    put7zUInt64(header, sizeof(main_stream));
    put7zUInt64(header, 0u);
    put7zUInt64(header, 0u);
    put7zUInt64(header, sizeof(rc_stream));
    header.push_back(0x00u); /* PackInfo end */
    header.push_back(0x07u); /* UnPackInfo */
    header.push_back(0x0bu); /* Folder */
    put7zUInt64(header, 1u); /* NumFolders */
    header.push_back(0u); /* folders are in this header */
    put7zUInt64(header, 1u); /* NumCoders */
    header.push_back(0x14u); /* four-input BCJ2 coder, no properties */
    header.push_back(0x03u);
    header.push_back(0x03u);
    header.push_back(0x01u);
    header.push_back(0x1bu);
    put7zUInt64(header, 4u); /* NumInStreams */
    put7zUInt64(header, 1u); /* NumOutStreams */
    put7zUInt64(header, 0u);
    put7zUInt64(header, 1u);
    put7zUInt64(header, 2u);
    put7zUInt64(header, 3u);
    header.push_back(0x0cu); /* CodersUnpackSize */
    put7zUInt64(header, sizeof(main_stream));
    header.push_back(0x0au); /* Folder CRC */
    header.push_back(1u);
    header.resize(header.size() + 4u);
    put32(header, header.size() - 4u,
          RinRuntime::rinruntime_archive_crc32(main_stream,
                                                sizeof(main_stream)));
    header.push_back(0x00u); /* UnPackInfo end */
    header.push_back(0x00u); /* MainStreamsInfo end */
    header.push_back(0x05u); /* FilesInfo */
    put7zUInt64(header, 1u); /* NumFiles */
    header.push_back(0x00u); /* FilesInfo properties end */
    header.push_back(0x00u); /* Header end */

    std::vector<std::uint8_t> bytes(32u + sizeof(main_stream) +
                                        sizeof(rc_stream) + header.size(),
                                    0u);
    std::memcpy(bytes.data(), signature, sizeof(signature));
    bytes[7u] = 4u;
    std::memcpy(bytes.data() + 32u, main_stream, sizeof(main_stream));
    std::memcpy(bytes.data() + 32u + sizeof(main_stream), rc_stream,
                sizeof(rc_stream));
    const std::size_t header_offset =
        32u + sizeof(main_stream) + sizeof(rc_stream);
    std::memcpy(bytes.data() + header_offset, header.data(), header.size());
    put64(bytes, 12u, sizeof(main_stream) + sizeof(rc_stream));
    put64(bytes, 20u, header.size());
    put32(bytes, 28u,
          RinRuntime::rinruntime_archive_crc32(bytes.data() + header_offset,
                                                header.size()));
    put32(bytes, 8u,
          RinRuntime::rinruntime_archive_crc32(bytes.data() + 12u, 20u));
    return bytes;
}

static std::vector<std::uint8_t> make7zEmpty()
{
    const std::uint8_t signature[] = {
        0x37u, 0x7au, 0xbcu, 0xafu, 0x27u, 0x1cu};
    std::vector<std::uint8_t> header;
    header.push_back(0x01u); /* Header */
    header.push_back(0x04u); /* MainStreamsInfo */
    header.push_back(0x00u); /* no packed streams */
    header.push_back(0x05u); /* FilesInfo */
    put7zUInt64(header, 1u); /* NumFiles */
    header.push_back(0x0eu); /* EmptyStream */
    put7zUInt64(header, 1u);
    header.push_back(0x01u); /* file 0 has no packed stream */
    header.push_back(0x0fu); /* EmptyFile */
    put7zUInt64(header, 1u);
    header.push_back(0x01u); /* file 0 is a regular empty file */
    header.push_back(0x00u); /* FilesInfo end */
    header.push_back(0x00u); /* Header end */

    std::vector<std::uint8_t> bytes(32u + header.size(), 0u);
    std::memcpy(bytes.data(), signature, sizeof(signature));
    bytes[7u] = 4u;
    std::memcpy(bytes.data() + 32u, header.data(), header.size());
    put64(bytes, 12u, 0u);
    put64(bytes, 20u, header.size());
    put32(bytes, 28u, RinRuntime::rinruntime_archive_crc32(
                              bytes.data() + 32u, header.size()));
    put32(bytes, 8u, RinRuntime::rinruntime_archive_crc32(
                             bytes.data() + 12u, 20u));
    return bytes;
}

static std::vector<std::uint8_t> make7zEmptyEntries()
{
    const std::uint8_t signature[] = {
        0x37u, 0x7au, 0xbcu, 0xafu, 0x27u, 0x1cu};
    std::vector<std::uint8_t> header;
    header.push_back(0x01u); /* Header */
    header.push_back(0x04u); /* MainStreamsInfo */
    header.push_back(0x00u); /* no packed streams */
    header.push_back(0x05u); /* FilesInfo */
    put7zUInt64(header, 2u); /* NumFiles */
    header.push_back(0x0eu); /* EmptyStream */
    put7zUInt64(header, 1u);
    header.push_back(0x03u); /* both files have no packed stream */
    header.push_back(0x0fu); /* EmptyFile */
    put7zUInt64(header, 1u);
    header.push_back(0x02u); /* file 0 is a directory, file 1 is regular */
    header.push_back(0x00u); /* FilesInfo end */
    header.push_back(0x00u); /* Header end */

    std::vector<std::uint8_t> bytes(32u + header.size(), 0u);
    std::memcpy(bytes.data(), signature, sizeof(signature));
    bytes[7u] = 4u;
    std::memcpy(bytes.data() + 32u, header.data(), header.size());
    put64(bytes, 12u, 0u);
    put64(bytes, 20u, header.size());
    put32(bytes, 28u, RinRuntime::rinruntime_archive_crc32(
                              bytes.data() + 32u, header.size()));
    put32(bytes, 8u, RinRuntime::rinruntime_archive_crc32(
                             bytes.data() + 12u, 20u));
    return bytes;
}

static std::vector<std::uint8_t> make7zMixedEmptyEntries(bool directory = false)
{
    const std::uint8_t signature[] = {
        0x37u, 0x7au, 0xbcu, 0xafu, 0x27u, 0x1cu};
    const std::uint8_t payload[] = {'h', 'e', 'l', 'l', 'o'};
    std::vector<std::uint8_t> header;
    header.push_back(0x01u); /* Header */
    header.push_back(0x04u); /* MainStreamsInfo */
    header.push_back(0x06u); /* PackInfo */
    put7zUInt64(header, 0u); /* PackPos */
    put7zUInt64(header, 1u); /* NumPackStreams */
    header.push_back(0x09u); /* Size */
    put7zUInt64(header, sizeof(payload));
    header.push_back(0x0au); /* Pack CRC */
    header.push_back(1u);
    header.resize(header.size() + 4u);
    put32(header, header.size() - 4u,
          RinRuntime::rinruntime_archive_crc32(payload, sizeof(payload)));
    header.push_back(0x00u); /* PackInfo end */
    header.push_back(0x07u); /* UnPackInfo */
    header.push_back(0x0bu); /* Folder */
    put7zUInt64(header, 1u); /* NumFolders */
    header.push_back(0u); /* folders are in this header */
    put7zUInt64(header, 1u); /* NumCoders */
    header.push_back(0x01u); /* Copy coder */
    header.push_back(0x00u);
    header.push_back(0x0cu); /* CodersUnpackSize */
    put7zUInt64(header, sizeof(payload));
    header.push_back(0x0au); /* Folder CRC */
    header.push_back(1u);
    header.resize(header.size() + 4u);
    put32(header, header.size() - 4u,
          RinRuntime::rinruntime_archive_crc32(payload, sizeof(payload)));
    header.push_back(0x00u); /* UnPackInfo end */
    header.push_back(0x00u); /* MainStreamsInfo end */
    header.push_back(0x05u); /* FilesInfo */
    put7zUInt64(header, 2u); /* NumFiles */
    header.push_back(0x0eu); /* EmptyStream */
    put7zUInt64(header, 1u);
    header.push_back(0x01u); /* file 0 has no packed stream */
    header.push_back(0x0fu); /* EmptyFile */
    put7zUInt64(header, 1u);
    header.push_back(directory ? 0u : 1u); /* file 0 is empty regular/dir */
    header.push_back(0x00u); /* FilesInfo end */
    header.push_back(0x00u); /* Header end */

    std::vector<std::uint8_t> bytes(32u + sizeof(payload) + header.size(), 0u);
    std::memcpy(bytes.data(), signature, sizeof(signature));
    bytes[7u] = 4u;
    std::memcpy(bytes.data() + 32u, payload, sizeof(payload));
    const std::size_t header_offset = 32u + sizeof(payload);
    std::memcpy(bytes.data() + header_offset, header.data(), header.size());
    put64(bytes, 12u, sizeof(payload));
    put64(bytes, 20u, header.size());
    put32(bytes, 28u, RinRuntime::rinruntime_archive_crc32(
                              bytes.data() + header_offset, header.size()));
    put32(bytes, 8u, RinRuntime::rinruntime_archive_crc32(
                             bytes.data() + 12u, 20u));
    return bytes;
}

static std::vector<std::uint8_t> make7zLzma(std::string& expected)
{
    const std::uint8_t signature[] = {
        0x37u, 0x7au, 0xbcu, 0xafu, 0x27u, 0x1cu};
    const std::uint8_t properties[] = {
        0x5du, 0x00u, 0x00u, 0x04u, 0x00u};
    const std::uint8_t packed[] = {
        0x00u, 0x34u, 0x19u, 0x49u, 0xdbu, 0x85u, 0x5cu, 0x63u,
        0xadu, 0x3eu, 0xf9u, 0x63u, 0x73u, 0xe5u, 0x4fu, 0x1cu,
        0x74u, 0x7bu, 0xd4u, 0x27u, 0xaeu, 0x92u, 0xc5u, 0xf4u,
        0x54u, 0x43u, 0xdcu, 0xffu, 0xffu, 0xf2u, 0xcbu, 0x80u,
        0x00u};
    expected.clear();
    for (unsigned index = 0u; index != 100u; ++index)
        expected += "hello world! ";

    std::vector<std::uint8_t> header;
    header.push_back(0x01u); /* Header */
    header.push_back(0x04u); /* MainStreamsInfo */
    header.push_back(0x06u); /* PackInfo */
    put7zUInt64(header, 0u); /* PackPos */
    put7zUInt64(header, 1u); /* NumPackStreams */
    header.push_back(0x09u); /* Size */
    put7zUInt64(header, sizeof(packed));
    header.push_back(0x0au); /* Pack CRC */
    header.push_back(1u);
    header.resize(header.size() + 4u);
    put32(header, header.size() - 4u,
          RinRuntime::rinruntime_archive_crc32(packed, sizeof(packed)));
    header.push_back(0x00u); /* PackInfo end */
    header.push_back(0x07u); /* UnPackInfo */
    header.push_back(0x0bu); /* Folder */
    put7zUInt64(header, 1u); /* NumFolders */
    header.push_back(0u); /* folders are in this header */
    put7zUInt64(header, 1u); /* NumCoders */
    header.push_back(0x23u); /* 3-byte LZMA method ID + properties */
    header.push_back(0x03u);
    header.push_back(0x01u);
    header.push_back(0x01u);
    header.push_back(0x05u); /* LZMA properties size */
    header.insert(header.end(), properties,
                  properties + sizeof(properties));
    header.push_back(0x0cu); /* CodersUnpackSize */
    put7zUInt64(header, expected.size());
    header.push_back(0x0au); /* Folder CRC */
    header.push_back(1u);
    header.resize(header.size() + 4u);
    put32(header, header.size() - 4u,
          RinRuntime::rinruntime_archive_crc32(
              reinterpret_cast<const std::uint8_t*>(expected.data()),
              expected.size()));
    header.push_back(0x00u); /* UnPackInfo end */
    header.push_back(0x00u); /* MainStreamsInfo end */
    header.push_back(0x05u); /* FilesInfo */
    put7zUInt64(header, 1u); /* NumFiles */
    header.push_back(0x00u); /* properties end */
    header.push_back(0x00u); /* Header end */

    const std::size_t headerOffset = 32u + sizeof(packed);
    std::vector<std::uint8_t> bytes(headerOffset + header.size(), 0u);
    std::memcpy(bytes.data(), signature, sizeof(signature));
    bytes[7u] = 4u;
    std::memcpy(bytes.data() + 32u, packed, sizeof(packed));
    std::memcpy(bytes.data() + headerOffset, header.data(), header.size());
    put64(bytes, 12u, sizeof(packed));
    put64(bytes, 20u, header.size());
    put32(bytes, 28u,
          RinRuntime::rinruntime_archive_crc32(bytes.data() + headerOffset,
                                                header.size()));
    put32(bytes, 8u,
          RinRuntime::rinruntime_archive_crc32(bytes.data() + 12u, 20u));
    return bytes;
}

static std::vector<std::uint8_t> makeXzStoredLzma2()
{
    const char payload[] = "hello";
    std::vector<std::uint8_t> bytes(56u, 0u);
    const std::uint8_t magic[] = {
        0xfdu, 0x37u, 0x7au, 0x58u, 0x5au, 0x00u};
    std::memcpy(bytes.data(), magic, sizeof(magic));
    bytes[7u] = 0u; /* None check */
    put32(bytes, 8u,
          RinRuntime::rinruntime_archive_crc32(bytes.data() + 6u, 2u));

    const std::size_t block = 12u;
    bytes[block] = 0x02u;
    bytes[block + 1u] = 0xc0u;
    bytes[block + 2u] = 0x09u;
    bytes[block + 3u] = 0x05u;
    bytes[block + 4u] = 0x21u;
    bytes[block + 5u] = 0x01u;
    bytes[block + 6u] = 0x00u;
    put32(bytes, block + 8u,
          RinRuntime::rinruntime_archive_crc32(bytes.data() + block, 8u));

    bytes[24u] = 0x01u;
    bytes[25u] = 0x04u;
    bytes[26u] = 0x00u;
    std::memcpy(bytes.data() + 27u, payload, 5u);
    bytes[32u] = 0x00u;

    const std::size_t index = 36u;
    bytes[index] = 0x00u;
    bytes[index + 1u] = 0x01u;
    bytes[index + 2u] = 0x15u;
    bytes[index + 3u] = 0x05u;
    put32(bytes, index + 4u,
          RinRuntime::rinruntime_archive_crc32(bytes.data() + index, 4u));

    const std::size_t footer = index + 8u;
    bytes[footer + 4u] = 0x01u;
    bytes[footer + 9u] = 0u;
    bytes[footer + 10u] = static_cast<std::uint8_t>('Y');
    bytes[footer + 11u] = static_cast<std::uint8_t>('Z');
    put32(bytes, footer,
          RinRuntime::rinruntime_archive_crc32(bytes.data() + footer + 4u,
                                                6u));
    return bytes;
}

static std::vector<std::uint8_t> makeXzDeltaStoredLzma2()
{
    std::vector<std::uint8_t> bytes(60u, 0u);
    const std::uint8_t magic[] = {
        0xfdu, 0x37u, 0x7au, 0x58u, 0x5au, 0x00u};
    std::memcpy(bytes.data(), magic, sizeof(magic));
    put32(bytes, 8u,
          RinRuntime::rinruntime_archive_crc32(bytes.data() + 6u, 2u));

    bytes[12u] = 0x03u;
    bytes[13u] = 0xc1u;
    bytes[14u] = 0x09u;
    bytes[15u] = 0x05u;
    bytes[16u] = 0x03u;
    bytes[17u] = 0x01u;
    bytes[18u] = 0x00u;
    bytes[19u] = 0x21u;
    bytes[20u] = 0x01u;
    bytes[21u] = 0x00u;
    put32(bytes, 24u,
          RinRuntime::rinruntime_archive_crc32(bytes.data() + 12u, 12u));

    bytes[28u] = 0x01u;
    bytes[29u] = 0x04u;
    bytes[30u] = 0x00u;
    const std::uint8_t deltaPayload[] = {
        static_cast<std::uint8_t>('h'), 0xfdu, 0x07u, 0x00u, 0x03u};
    std::memcpy(bytes.data() + 31u, deltaPayload, sizeof(deltaPayload));
    bytes[36u] = 0x00u;

    bytes[40u] = 0x00u;
    bytes[41u] = 0x01u;
    bytes[42u] = 0x19u;
    bytes[43u] = 0x05u;
    put32(bytes, 44u,
          RinRuntime::rinruntime_archive_crc32(bytes.data() + 40u, 4u));
    bytes[52u] = 0x01u;
    bytes[58u] = static_cast<std::uint8_t>('Y');
    bytes[59u] = static_cast<std::uint8_t>('Z');
    put32(bytes, 48u,
          RinRuntime::rinruntime_archive_crc32(bytes.data() + 52u, 6u));
    return bytes;
}

int main()
{
    RinRuntime::ArchiveContainerReader reader;
    std::string output = "stale";
    const std::vector<std::uint8_t> zip = makeZip();
    assert(reader.parse(zip.data(), zip.size()) ==
           RinRuntime::ArchiveContainerResult::Ok);
    assert(reader.kind() == RinRuntime::ArchiveContainerKind::Zip &&
           reader.size() == 1u && reader.entries()[0].name == "a.txt");
    assert(reader.readEntry(0u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output == "hello");
    output = "poison";
    assert(reader.readEntryWithCancellation(0u, output, stopImmediately,
                                            nullptr) ==
           RinRuntime::ArchiveContainerResult::Cancelled);
    assert(output.empty());

    const std::vector<std::uint8_t> tar = makeTar();
    assert(reader.parse(tar.data(), tar.size()) ==
           RinRuntime::ArchiveContainerResult::Ok);
    assert(reader.kind() == RinRuntime::ArchiveContainerKind::Tar &&
           reader.readEntry(0u, output) ==
               RinRuntime::ArchiveContainerResult::Ok && output == "hello");
    output = "poison";
    assert(reader.readEntryWithCancellation(0u, output, stopImmediately,
                                            nullptr) ==
           RinRuntime::ArchiveContainerResult::Cancelled);
    assert(output.empty());

    const std::vector<std::uint8_t> targz = makeGzip(tar.data(), tar.size());
    assert(reader.parse(targz.data(), targz.size()) ==
           RinRuntime::ArchiveContainerResult::Ok);
    assert(reader.kind() == RinRuntime::ArchiveContainerKind::TarGzip &&
           reader.readEntry(0u, output) ==
               RinRuntime::ArchiveContainerResult::Ok && output == "hello");
    DeadlineOnce deadlineOnce{};
    assert(reader.parseWithDeadline(targz.data(), targz.size(), stopOnce,
                                    &deadlineOnce) ==
           RinRuntime::ArchiveContainerResult::Deadline);
    assert(reader.empty() && reader.kind() ==
           RinRuntime::ArchiveContainerKind::Unknown);

    const std::uint8_t streamPayload[] = {'s', 't', 'r', 'e', 'a', 'm'};
    const std::vector<std::uint8_t> gzip = makeGzip(
        streamPayload, sizeof(streamPayload));
    assert(reader.parse(gzip.data(), gzip.size()) ==
           RinRuntime::ArchiveContainerResult::Ok);
    assert(reader.kind() == RinRuntime::ArchiveContainerKind::Gzip &&
           reader.size() == 1u && reader.entries()[0].name == "<stream>" &&
           reader.entries()[0].size == sizeof(streamPayload));
    assert(reader.readEntry(0u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output == "stream");
    output = "poison";
    assert(reader.readEntryWithCancellation(0u, output, stopImmediately,
                                            nullptr) ==
           RinRuntime::ArchiveContainerResult::Cancelled);
    assert(output.empty());

    const std::uint8_t unknown[] = {'x'};
    assert(reader.parse(unknown, sizeof(unknown)) ==
           RinRuntime::ArchiveContainerResult::Unsupported);
    assert(reader.empty() && reader.kind() ==
           RinRuntime::ArchiveContainerKind::Unknown);
    assert(reader.readEntry(0u, output) ==
           RinRuntime::ArchiveContainerResult::InvalidArgument);

    const std::vector<std::uint8_t> sevenZip = make7zStored();
    assert(reader.parse(sevenZip.data(), sevenZip.size()) ==
           RinRuntime::ArchiveContainerResult::Ok);
    assert(reader.kind() == RinRuntime::ArchiveContainerKind::SevenZip &&
           reader.size() == 1u && reader.entries()[0].name == "<stream>" &&
           reader.entries()[0].size == 5u);
    assert(reader.readEntry(0u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output == "hello");
    output = "poison";
    assert(reader.readEntryWithCancellation(0u, output, stopImmediately,
                                            nullptr) ==
           RinRuntime::ArchiveContainerResult::Cancelled);
    assert(output.empty());

    const std::vector<std::uint8_t> sevenZipMulti =
        make7zStored(false, false, true);
    assert(reader.parse(sevenZipMulti.data(), sevenZipMulti.size()) ==
           RinRuntime::ArchiveContainerResult::Ok);
    assert(reader.kind() == RinRuntime::ArchiveContainerKind::SevenZip &&
           reader.size() == 2u &&
           reader.entries()[0].name == "<stream:0>" &&
           reader.entries()[0].size == 5u &&
           reader.entries()[1].name == "<stream:1>" &&
           reader.entries()[1].size == 6u);
    assert(reader.readEntry(0u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output == "hello");
    assert(reader.readEntry(1u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output == "world!");
    output = "poison";
    assert(reader.readEntryWithCancellation(1u, output, stopImmediately,
                                            nullptr) ==
           RinRuntime::ArchiveContainerResult::Cancelled);
    assert(output.empty());

    const std::vector<std::uint8_t> sevenZipFolders =
        make7zMultiFolderCopy();
    assert(reader.parse(sevenZipFolders.data(), sevenZipFolders.size()) ==
           RinRuntime::ArchiveContainerResult::Ok);
    assert(reader.kind() == RinRuntime::ArchiveContainerKind::SevenZip &&
           reader.size() == 2u && reader.entries()[0].size == 5u &&
           reader.entries()[1].size == 5u);
    assert(reader.readEntry(0u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output == "hello");
    assert(reader.readEntry(1u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output == "world");

    const std::vector<std::uint8_t> sevenZipFolderSubstreams =
        make7zMultiFolderCopySubstreams();
    assert(reader.parse(sevenZipFolderSubstreams.data(),
                        sevenZipFolderSubstreams.size()) ==
           RinRuntime::ArchiveContainerResult::Ok);
    assert(reader.kind() == RinRuntime::ArchiveContainerKind::SevenZip &&
           reader.size() == 4u && reader.entries()[0].size == 5u &&
           reader.entries()[1].size == 1u &&
           reader.entries()[2].size == 5u &&
           reader.entries()[3].size == 1u);
    assert(reader.readEntry(0u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output == "hello");
    assert(reader.readEntry(1u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output == "!");
    assert(reader.readEntry(2u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output == "world");
    assert(reader.readEntry(3u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output == "?");

    const std::vector<std::uint8_t> sevenZipFolderDelta =
        make7zMultiFolderDelta();
    assert(reader.parse(sevenZipFolderDelta.data(),
                        sevenZipFolderDelta.size()) ==
           RinRuntime::ArchiveContainerResult::Ok);
    assert(reader.kind() == RinRuntime::ArchiveContainerKind::SevenZip &&
           reader.size() == 2u && reader.entries()[0].size == 6u &&
           reader.entries()[1].size == 6u);
    assert(reader.readEntry(0u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output == "hello!");
    assert(reader.readEntry(1u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output == "world?");

    const std::vector<std::uint8_t> sevenZipFolderCopyChain =
        make7zMultiFolderCopyChain();
    assert(reader.parse(sevenZipFolderCopyChain.data(),
                        sevenZipFolderCopyChain.size()) ==
           RinRuntime::ArchiveContainerResult::Ok);
    assert(reader.kind() == RinRuntime::ArchiveContainerKind::SevenZip &&
           reader.size() == 2u && reader.entries()[0].size == 5u &&
           reader.entries()[1].size == 5u);
    assert(reader.readEntry(0u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output == "hello");
    assert(reader.readEntry(1u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output == "world");

    const std::vector<std::uint8_t> sevenZipCopyChain = make7zStored(true);
    assert(reader.parse(sevenZipCopyChain.data(), sevenZipCopyChain.size()) ==
           RinRuntime::ArchiveContainerResult::Ok);
    assert(reader.kind() == RinRuntime::ArchiveContainerKind::SevenZip &&
           reader.size() == 1u && reader.entries()[0].size == 5u);
    output = "poison";
    assert(reader.readEntry(0u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output == "hello");

    const std::vector<std::uint8_t> sevenZipLzma2 =
        make7zStored(false, true);
    assert(reader.parse(sevenZipLzma2.data(), sevenZipLzma2.size()) ==
           RinRuntime::ArchiveContainerResult::Ok);
    assert(reader.kind() == RinRuntime::ArchiveContainerKind::SevenZip &&
           reader.size() == 1u && reader.entries()[0].size == 5u);
    output = "poison";
    assert(reader.readEntry(0u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output == "hello");

    const std::vector<std::uint8_t> sevenZipBcj2 = make7zBcj2();
    assert(reader.parse(sevenZipBcj2.data(), sevenZipBcj2.size()) ==
           RinRuntime::ArchiveContainerResult::Ok);
    assert(reader.kind() == RinRuntime::ArchiveContainerKind::SevenZip &&
           reader.size() == 1u && reader.entries()[0].size == 5u);
    output = "poison";
    assert(reader.readEntry(0u, output) ==
           RinRuntime::ArchiveContainerResult::Ok &&
           output == std::string({static_cast<char>(0xe8), '\0', '\0', '\0',
                                  '\0'}));

    const std::vector<std::uint8_t> emptySevenZip = make7zEmpty();
    assert(reader.parse(emptySevenZip.data(), emptySevenZip.size()) ==
           RinRuntime::ArchiveContainerResult::Ok);
    assert(reader.kind() == RinRuntime::ArchiveContainerKind::SevenZip &&
           reader.size() == 1u && reader.entries()[0].name == "<stream>" &&
           reader.entries()[0].size == 0u);
    output = "poison";
    assert(reader.readEntry(0u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output.empty());

    const std::vector<std::uint8_t> emptySevenZipEntries =
        make7zEmptyEntries();
    assert(reader.parse(emptySevenZipEntries.data(),
                        emptySevenZipEntries.size()) ==
           RinRuntime::ArchiveContainerResult::Ok);
    assert(reader.kind() == RinRuntime::ArchiveContainerKind::SevenZip &&
           reader.size() == 2u && reader.entries()[0].directory &&
           !reader.entries()[1].directory && reader.entries()[0].size == 0u &&
           reader.entries()[1].size == 0u);
    output = "poison";
    assert(reader.readEntry(0u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output.empty());
    output = "poison";
    assert(reader.readEntryWithDeadline(1u, output, nullptr, nullptr) ==
           RinRuntime::ArchiveContainerResult::Ok && output.empty());

    const std::vector<std::uint8_t> mixedEmptySevenZip =
        make7zMixedEmptyEntries();
    assert(reader.parse(mixedEmptySevenZip.data(),
                        mixedEmptySevenZip.size()) ==
           RinRuntime::ArchiveContainerResult::Ok);
    assert(reader.kind() == RinRuntime::ArchiveContainerKind::SevenZip &&
           reader.size() == 2u && !reader.entries()[0].directory &&
           !reader.entries()[1].directory && reader.entries()[0].size == 0u &&
           reader.entries()[1].size == 5u);
    output = "poison";
    assert(reader.readEntry(0u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output.empty());
    assert(reader.readEntry(1u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output == "hello");

    const std::vector<std::uint8_t> mixedDirectorySevenZip =
        make7zMixedEmptyEntries(true);
    assert(reader.parse(mixedDirectorySevenZip.data(),
                        mixedDirectorySevenZip.size()) ==
           RinRuntime::ArchiveContainerResult::Ok);
    assert(reader.size() == 2u && reader.entries()[0].directory &&
           !reader.entries()[1].directory);
    output = "poison";
    assert(reader.readEntry(0u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output.empty());
    assert(reader.readEntry(1u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output == "hello");

    std::string lzmaExpected;
    const std::vector<std::uint8_t> lzma = make7zLzma(lzmaExpected);
    assert(reader.parse(lzma.data(), lzma.size()) ==
           RinRuntime::ArchiveContainerResult::Ok);
    assert(reader.kind() == RinRuntime::ArchiveContainerKind::SevenZip &&
           reader.size() == 1u &&
           reader.entries()[0].size == lzmaExpected.size());
    assert(reader.readEntry(0u, output) ==
           RinRuntime::ArchiveContainerResult::Ok &&
           output == lzmaExpected);
    output = "poison";
    assert(reader.readEntryWithCancellation(0u, output, stopImmediately,
                                            nullptr) ==
           RinRuntime::ArchiveContainerResult::Cancelled);
    assert(output.empty());

    const std::vector<std::uint8_t> xz = makeXzStoredLzma2();
    assert(reader.parse(xz.data(), xz.size()) ==
           RinRuntime::ArchiveContainerResult::Ok);
    assert(reader.kind() == RinRuntime::ArchiveContainerKind::Xz &&
           reader.size() == 1u && reader.entries()[0].name == "<stream>" &&
           reader.entries()[0].size == 5u);
    assert(reader.readEntry(0u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output == "hello");
    output = "poison";
    assert(reader.readEntryWithCancellation(0u, output, stopImmediately,
                                            nullptr) ==
           RinRuntime::ArchiveContainerResult::Cancelled);
    assert(output.empty());

    const std::vector<std::uint8_t> deltaXz = makeXzDeltaStoredLzma2();
    assert(reader.parse(deltaXz.data(), deltaXz.size()) ==
           RinRuntime::ArchiveContainerResult::Ok);
    assert(reader.kind() == RinRuntime::ArchiveContainerKind::Xz &&
           reader.size() == 1u && reader.entries()[0].size == 5u);
    output = "poison";
    assert(reader.readEntry(0u, output) ==
           RinRuntime::ArchiveContainerResult::Ok && output == "hello");

    std::vector<std::uint8_t> unsupportedXz = xz;
    unsupportedXz[24u] = 0x80u; /* truncated range-coded control */
    assert(reader.parse(unsupportedXz.data(), unsupportedXz.size()) ==
           RinRuntime::ArchiveContainerResult::Malformed);
    assert(reader.empty() && reader.kind() ==
           RinRuntime::ArchiveContainerKind::Unknown);
    return 0;
}
