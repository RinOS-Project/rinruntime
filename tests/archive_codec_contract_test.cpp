/* SPDX-License-Identifier: MIT */

#include "../include/rinruntime/archive_deflate.hpp"
#include "../include/rinruntime/archive_7z.hpp"
#include "../include/rinruntime/archive_gzip.hpp"
#include "../include/rinruntime/archive_tar.hpp"
#include "../include/rinruntime/archive_targz.hpp"
#include "../include/rinruntime/archive_zip.hpp"
#include "../include/rinruntime/archive_xz.hpp"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static bool cancelNow(void* context)
{
    return context != nullptr &&
           *static_cast<const std::uint32_t*>(context) != 0u;
}

static bool deadlineNow(void* context)
{
    return context != nullptr &&
           *static_cast<const std::uint32_t*>(context) != 0u;
}

static bool collectTar(void* context, const std::uint8_t* bytes,
                       std::size_t size)
{
    if (context == nullptr || bytes == nullptr || size == 0u) return false;
    static_cast<std::string*>(context)->append(
        reinterpret_cast<const char*>(bytes), size);
    return true;
}

static bool rejectTar(void*, const std::uint8_t*, std::size_t)
{
    return false;
}

static void put16(std::vector<std::uint8_t>& bytes, std::uint16_t value)
{
    bytes.push_back(static_cast<std::uint8_t>(value));
    bytes.push_back(static_cast<std::uint8_t>(value >> 8u));
}

static void put32(std::vector<std::uint8_t>& bytes, std::uint32_t value)
{
    for (unsigned index = 0u; index != 4u; ++index)
        bytes.push_back(static_cast<std::uint8_t>(value >> (index * 8u)));
}

static std::vector<std::uint8_t> makeStoredZip()
{
    const char name[] = "docs/readme.txt";
    const char payload[] = "hello";
    const std::size_t nameSize = sizeof(name) - 1u;
    const std::size_t payloadSize = sizeof(payload) - 1u;
    std::vector<std::uint8_t> bytes;
    put32(bytes, 0x04034b50u);
    put16(bytes, 20u); put16(bytes, 0u); put16(bytes, 0u);
    put16(bytes, 0u); put16(bytes, 0u); put32(bytes, 0x3610a686u);
    put32(bytes, 5u); put32(bytes, 5u);
    put16(bytes, static_cast<std::uint16_t>(nameSize)); put16(bytes, 0u);
    bytes.insert(bytes.end(), name, name + nameSize);
    bytes.insert(bytes.end(), payload, payload + payloadSize);
    const std::uint32_t centralOffset = static_cast<std::uint32_t>(bytes.size());
    put32(bytes, 0x02014b50u);
    put16(bytes, 20u); put16(bytes, 20u); put16(bytes, 0u); put16(bytes, 0u);
    put16(bytes, 0u); put16(bytes, 0u); put32(bytes, 0x3610a686u);
    put32(bytes, 5u); put32(bytes, 5u);
    put16(bytes, static_cast<std::uint16_t>(nameSize));
    put16(bytes, 0u); put16(bytes, 0u); put16(bytes, 0u); put16(bytes, 0u);
    put32(bytes, 0u); put32(bytes, 0u);
    bytes.insert(bytes.end(), name, name + nameSize);
    const std::uint32_t centralSize =
        static_cast<std::uint32_t>(bytes.size()) - centralOffset;
    put32(bytes, 0x06054b50u);
    put16(bytes, 0u); put16(bytes, 0u); put16(bytes, 1u); put16(bytes, 1u);
    put32(bytes, centralSize); put32(bytes, centralOffset); put16(bytes, 0u);
    return bytes;
}

static void putOctal(std::uint8_t* field, std::size_t capacity,
                     std::uint64_t value)
{
    std::memset(field, ' ', capacity);
    std::snprintf(reinterpret_cast<char*>(field), capacity, "%06llo",
                  static_cast<unsigned long long>(value));
    field[capacity - 2u] = 0u;
    field[capacity - 1u] = static_cast<std::uint8_t>(' ');
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

static std::vector<std::uint8_t> makeGzip(const std::uint8_t* payload,
                                          std::size_t payloadSize)
{
    const std::size_t rawSize = payloadSize + 5u;
    std::vector<std::uint8_t> bytes(10u + rawSize + 8u, 0u);
    bytes[0] = 0x1fu; bytes[1] = 0x8bu; bytes[2] = 8u; bytes[9] = 255u;
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

static void writeLe32(std::vector<std::uint8_t>& bytes, std::size_t offset,
                      std::uint32_t value)
{
    for (unsigned index = 0u; index != 4u; ++index)
        bytes[offset + index] =
            static_cast<std::uint8_t>(value >> (index * 8u));
}

static void writeLe64(std::vector<std::uint8_t>& bytes, std::size_t offset,
                      std::uint64_t value)
{
    for (unsigned index = 0u; index != 8u; ++index)
        bytes[offset + index] =
            static_cast<std::uint8_t>(value >> (index * 8u));
}

static std::uint64_t xzCrc64(const std::uint8_t* bytes, std::size_t size)
{
    constexpr std::uint64_t polynomial = UINT64_C(0xc96c5795d7870f42);
    std::uint64_t crc = UINT64_MAX;
    for (std::size_t index = 0u; index != size; ++index) {
        crc ^= static_cast<std::uint64_t>(bytes[index]);
        for (unsigned bit = 0u; bit != 8u; ++bit)
            crc = (crc & 1u) != 0u ? (crc >> 1u) ^ polynomial
                                   : crc >> 1u;
    }
    return ~crc;
}

static std::vector<std::uint8_t> make7zStructure()
{
    const std::uint8_t signature[] = {
        0x37u, 0x7au, 0xbcu, 0xafu, 0x27u, 0x1cu};
    const std::uint8_t nextHeader[] = {0x01u, 0x02u, 0x00u, 0x00u};
    std::vector<std::uint8_t> bytes(32u + sizeof(nextHeader), 0u);
    std::memcpy(bytes.data(), signature, sizeof(signature));
    bytes[6u] = 0u;
    bytes[7u] = 4u;
    writeLe64(bytes, 12u, 0u);
    writeLe64(bytes, 20u, sizeof(nextHeader));
    std::memcpy(bytes.data() + 32u, nextHeader, sizeof(nextHeader));
    writeLe32(bytes, 28u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 32u,
                                                   sizeof(nextHeader)));
    writeLe32(bytes, 8u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 12u, 20u));
    return bytes;
}

static void put7zUInt64(std::vector<std::uint8_t>& bytes,
                        std::uint64_t value)
{
    if (value < 0x80u) {
        bytes.push_back(static_cast<std::uint8_t>(value));
        return;
    }
    /* The contract fixture only needs the two-byte form. */
    assert(value < 0x4000u);
    bytes.push_back(static_cast<std::uint8_t>(0x80u | (value >> 8u)));
    bytes.push_back(static_cast<std::uint8_t>(value));
}

static std::vector<std::uint8_t> make7zStored()
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
    header.push_back(1u); /* all defined */
    put32(header, RinRuntime::rinruntime_archive_crc32(
                        payload, sizeof(payload)));
    header.push_back(0x00u); /* PackInfo end */
    header.push_back(0x07u); /* UnPackInfo */
    header.push_back(0x0bu); /* Folder */
    put7zUInt64(header, 1u); /* NumFolders */
    header.push_back(0u); /* folders are in this header */
    put7zUInt64(header, 1u); /* NumCoders */
    header.push_back(0x01u); /* one-byte method ID, no properties */
    header.push_back(0x00u); /* Copy coder */
    header.push_back(0x0cu); /* CodersUnpackSize */
    put7zUInt64(header, sizeof(payload));
    header.push_back(0x0au); /* Folder CRC */
    header.push_back(1u); /* all defined */
    put32(header, RinRuntime::rinruntime_archive_crc32(
                        payload, sizeof(payload)));
    header.push_back(0x00u); /* UnPackInfo end */
    header.push_back(0x00u); /* MainStreamsInfo end */
    header.push_back(0x05u); /* FilesInfo */
    put7zUInt64(header, 1u); /* NumFiles */
    header.push_back(0x00u); /* FilesInfo properties end */
    header.push_back(0x00u); /* Header end */

    std::vector<std::uint8_t> bytes(32u + sizeof(payload) + header.size(), 0u);
    std::memcpy(bytes.data(), signature, sizeof(signature));
    bytes[7u] = 4u;
    std::memcpy(bytes.data() + 32u, payload, sizeof(payload));
    const std::size_t header_offset = 32u + sizeof(payload);
    std::memcpy(bytes.data() + header_offset, header.data(), header.size());
    writeLe64(bytes, 12u, sizeof(payload));
    writeLe64(bytes, 20u, header.size());
    writeLe32(bytes, 28u, RinRuntime::rinruntime_archive_crc32(
                              bytes.data() + header_offset, header.size()));
    writeLe32(bytes, 8u, RinRuntime::rinruntime_archive_crc32(
                             bytes.data() + 12u, 20u));
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
    writeLe64(bytes, 12u, 0u);
    writeLe64(bytes, 20u, header.size());
    writeLe32(bytes, 28u, RinRuntime::rinruntime_archive_crc32(
                              bytes.data() + 32u, header.size()));
    writeLe32(bytes, 8u, RinRuntime::rinruntime_archive_crc32(
                             bytes.data() + 12u, 20u));
    return bytes;
}

static std::vector<std::uint8_t> makeXzStructure()
{
    /* One bounded block with an LZMA2 filter.  The public inspector validates
     * the envelope and sizes; it intentionally does not decode this payload. */
    std::vector<std::uint8_t> bytes(48u, 0u);
    const std::uint8_t magic[] = {0xfdu, 0x37u, 0x7au, 0x58u, 0x5au, 0x00u};
    std::memcpy(bytes.data(), magic, sizeof(magic));
    writeLe32(bytes, 8u, RinRuntime::rinruntime_archive_crc32(bytes.data() + 6u,
                                                               2u));

    const std::size_t block = 12u;
    bytes[block] = 0x02u;     /* twelve-byte block header */
    bytes[block + 1u] = 0xc0u; /* compressed and uncompressed sizes present */
    bytes[block + 2u] = 0x01u;
    bytes[block + 3u] = 0x00u;
    bytes[block + 4u] = 0x21u; /* LZMA2 filter ID */
    bytes[block + 5u] = 0x01u;
    bytes[block + 6u] = 0x00u;
    writeLe32(bytes, block + 8u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + block, 8u));
    bytes[24u] = 0x00u; /* opaque payload byte */

    const std::size_t index = 28u;
    bytes[index] = 0x00u;
    bytes[index + 1u] = 0x01u; /* one record */
    bytes[index + 2u] = 0x0du; /* unpadded block size: 12 + 1 */
    bytes[index + 3u] = 0x00u; /* uncompressed size */
    writeLe32(bytes, index + 4u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + index, 4u));

    const std::size_t footer = 36u;
    bytes[footer + 4u] = 0x01u; /* backward size: 8 / 4 - 1 */
    bytes[footer + 10u] = static_cast<std::uint8_t>('Y');
    bytes[footer + 11u] = static_cast<std::uint8_t>('Z');
    writeLe32(bytes, footer,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + footer + 4u,
                                                   6u));
    return bytes;
}

static std::vector<std::uint8_t> makeXzNonCanonicalVli()
{
    /* The compressed-size VLI encodes 1 as 0x81 0x00 instead of the
     * required one-byte 0x01 representation. */
    std::vector<std::uint8_t> bytes(52u, 0u);
    const std::uint8_t magic[] = {0xfdu, 0x37u, 0x7au, 0x58u, 0x5au, 0x00u};
    std::memcpy(bytes.data(), magic, sizeof(magic));
    writeLe32(bytes, 8u, RinRuntime::rinruntime_archive_crc32(bytes.data() + 6u,
                                                               2u));

    const std::size_t block = 12u;
    bytes[block] = 0x03u;     /* sixteen-byte block header */
    bytes[block + 1u] = 0xc0u; /* compressed and uncompressed sizes present */
    bytes[block + 2u] = 0x81u;
    bytes[block + 3u] = 0x00u;
    bytes[block + 4u] = 0x00u; /* uncompressed size */
    bytes[block + 5u] = 0x21u; /* LZMA2 filter ID */
    bytes[block + 6u] = 0x01u;
    bytes[block + 7u] = 0x00u;
    writeLe32(bytes, block + 12u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + block, 12u));
    bytes[28u] = 0x00u; /* opaque payload byte */

    const std::size_t index = 32u;
    bytes[index] = 0x00u;
    bytes[index + 1u] = 0x01u; /* one record */
    bytes[index + 2u] = 0x1du; /* unpadded block size: 28 + 1 */
    bytes[index + 3u] = 0x00u; /* uncompressed size */
    writeLe32(bytes, index + 4u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + index, 4u));

    const std::size_t footer = 40u;
    bytes[footer + 4u] = 0x01u; /* backward size: 8 / 4 - 1 */
    bytes[footer + 10u] = static_cast<std::uint8_t>('Y');
    bytes[footer + 11u] = static_cast<std::uint8_t>('Z');
    writeLe32(bytes, footer,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + footer + 4u,
                                                   6u));
    return bytes;
}

static std::vector<std::uint8_t> makeXzStoredLzma2(std::uint8_t checkType)
{
    const char payload[] = "hello";
    const std::size_t checkSize =
        checkType == 0u ? 0u : (checkType == 1u ? 4u : 8u);
    std::vector<std::uint8_t> bytes(56u + checkSize, 0u);
    const std::uint8_t magic[] = {0xfdu, 0x37u, 0x7au, 0x58u, 0x5au, 0x00u};
    std::memcpy(bytes.data(), magic, sizeof(magic));
    bytes[7u] = checkType;
    writeLe32(bytes, 8u, RinRuntime::rinruntime_archive_crc32(bytes.data() + 6u,
                                                               2u));

    const std::size_t block = 12u;
    bytes[block] = 0x02u;
    bytes[block + 1u] = 0xc0u;
    bytes[block + 2u] = 0x09u;
    bytes[block + 3u] = 0x05u;
    bytes[block + 4u] = 0x21u;
    bytes[block + 5u] = 0x01u;
    bytes[block + 6u] = 0x00u;
    writeLe32(bytes, block + 8u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + block, 8u));

    bytes[24u] = 0x01u;
    bytes[25u] = 0x04u;
    bytes[26u] = 0x00u;
    std::memcpy(bytes.data() + 27u, payload, 5u);
    bytes[32u] = 0x00u;
    const std::size_t checkOffset = 36u;
    if (checkType == 1u)
        writeLe32(bytes, checkOffset,
                  RinRuntime::rinruntime_archive_crc32(
                      bytes.data() + 27u, 5u));
    else if (checkType == 4u)
        writeLe64(bytes, checkOffset, xzCrc64(bytes.data() + 27u, 5u));

    const std::size_t index = checkOffset + checkSize;
    bytes[index] = 0x00u;
    bytes[index + 1u] = 0x01u;
    bytes[index + 2u] = static_cast<std::uint8_t>(0x15u + checkSize);
    bytes[index + 3u] = 0x05u;
    writeLe32(bytes, index + 4u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + index, 4u));

    const std::size_t actualFooter = index + 8u;
    bytes[actualFooter + 4u] = 0x01u;
    bytes[actualFooter + 9u] = checkType;
    bytes[actualFooter + 10u] = static_cast<std::uint8_t>('Y');
    bytes[actualFooter + 11u] = static_cast<std::uint8_t>('Z');
    writeLe32(bytes, actualFooter,
              RinRuntime::rinruntime_archive_crc32(
                  bytes.data() + actualFooter + 4u, 6u));
    return bytes;
}

static std::vector<std::uint8_t> makeXzDeltaStoredLzma2()
{
    std::vector<std::uint8_t> bytes(60u, 0u);
    const std::uint8_t magic[] = {
        0xfdu, 0x37u, 0x7au, 0x58u, 0x5au, 0x00u};
    std::memcpy(bytes.data(), magic, sizeof(magic));
    writeLe32(bytes, 8u,
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
    writeLe32(bytes, 24u,
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
    writeLe32(bytes, 44u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 40u, 4u));
    bytes[52u] = 0x01u;
    bytes[58u] = static_cast<std::uint8_t>('Y');
    bytes[59u] = static_cast<std::uint8_t>('Z');
    writeLe32(bytes, 48u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 52u, 6u));
    return bytes;
}

static std::vector<std::uint8_t> makeXzX86StoredLzma2()
{
    /* The stored payload is an x86 CALL whose filtered displacement is five;
     * x86 BCJ decoding subtracts the instruction position plus five and
     * restores a zero displacement. */
    std::vector<std::uint8_t> bytes(64u, 0u);
    const std::uint8_t magic[] = {
        0xfdu, 0x37u, 0x7au, 0x58u, 0x5au, 0x00u};
    std::memcpy(bytes.data(), magic, sizeof(magic));
    writeLe32(bytes, 8u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 6u, 2u));

    bytes[12u] = 0x04u; /* twenty-byte block header */
    bytes[13u] = 0xc1u; /* x86 BCJ followed by LZMA2 */
    bytes[14u] = 0x09u;
    bytes[15u] = 0x05u;
    bytes[16u] = 0x04u; /* x86 BCJ */
    bytes[17u] = 0x04u;
    bytes[18u] = 0x00u;
    bytes[19u] = 0x00u;
    bytes[20u] = 0x00u;
    bytes[21u] = 0x00u; /* start offset = 0 */
    bytes[22u] = 0x21u; /* LZMA2 */
    bytes[23u] = 0x01u;
    bytes[24u] = 0x00u; /* dictionary property */
    writeLe32(bytes, 28u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 12u, 16u));

    bytes[32u] = 0x01u;
    bytes[33u] = 0x04u;
    bytes[34u] = 0x00u;
    const std::uint8_t filteredCall[] = {0xe8u, 0x05u, 0x00u, 0x00u, 0x00u};
    std::memcpy(bytes.data() + 35u, filteredCall, sizeof(filteredCall));
    bytes[40u] = 0x00u;

    bytes[44u] = 0x00u;
    bytes[45u] = 0x01u;
    bytes[46u] = 0x1du; /* twenty-byte header + nine-byte payload */
    bytes[47u] = 0x05u;
    writeLe32(bytes, 48u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 44u, 4u));
    bytes[56u] = 0x01u;
    bytes[62u] = static_cast<std::uint8_t>('Y');
    bytes[63u] = static_cast<std::uint8_t>('Z');
    writeLe32(bytes, 52u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 56u, 6u));
    return bytes;
}

static std::vector<std::uint8_t> makeXzArmStoredLzma2()
{
    /* The stored payload is an ARM B instruction whose filtered immediate is
     * two; ARM BCJ decoding subtracts PC+8 and restores a zero immediate. */
    std::vector<std::uint8_t> bytes(56u, 0u);
    const std::uint8_t magic[] = {
        0xfdu, 0x37u, 0x7au, 0x58u, 0x5au, 0x00u};
    std::memcpy(bytes.data(), magic, sizeof(magic));
    writeLe32(bytes, 8u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 6u, 2u));

    bytes[12u] = 0x03u; /* sixteen-byte block header */
    bytes[13u] = 0xc1u; /* ARM BCJ followed by LZMA2 */
    bytes[14u] = 0x08u;
    bytes[15u] = 0x04u;
    bytes[16u] = 0x07u; /* ARM BCJ */
    bytes[17u] = 0x00u;
    bytes[18u] = 0x21u; /* LZMA2 */
    bytes[19u] = 0x01u;
    bytes[20u] = 0x00u; /* dictionary property */
    writeLe32(bytes, 24u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 12u, 12u));

    bytes[28u] = 0x01u;
    bytes[29u] = 0x03u;
    bytes[30u] = 0x00u;
    const std::uint8_t filteredBranch[] = {0x02u, 0x00u, 0x00u, 0xebu};
    std::memcpy(bytes.data() + 31u, filteredBranch, sizeof(filteredBranch));
    bytes[35u] = 0x00u;

    bytes[36u] = 0x00u;
    bytes[37u] = 0x01u;
    bytes[38u] = 0x18u; /* sixteen-byte header + eight-byte payload */
    bytes[39u] = 0x04u;
    writeLe32(bytes, 40u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 36u, 4u));
    bytes[48u] = 0x01u;
    bytes[54u] = static_cast<std::uint8_t>('Y');
    bytes[55u] = static_cast<std::uint8_t>('Z');
    writeLe32(bytes, 44u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 48u, 6u));
    return bytes;
}

static std::vector<std::uint8_t> makeXzArmThumbStoredLzma2()
{
    /* The stored payload is an ARM Thumb BL whose filtered immediate is two;
     * ARM Thumb BCJ decoding subtracts PC+4 and restores zero. */
    std::vector<std::uint8_t> bytes(56u, 0u);
    const std::uint8_t magic[] = {
        0xfdu, 0x37u, 0x7au, 0x58u, 0x5au, 0x00u};
    std::memcpy(bytes.data(), magic, sizeof(magic));
    writeLe32(bytes, 8u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 6u, 2u));

    bytes[12u] = 0x03u;
    bytes[13u] = 0xc1u;
    bytes[14u] = 0x08u;
    bytes[15u] = 0x04u;
    bytes[16u] = 0x08u; /* ARM Thumb BCJ */
    bytes[17u] = 0x00u;
    bytes[18u] = 0x21u; /* LZMA2 */
    bytes[19u] = 0x01u;
    bytes[20u] = 0x00u;
    writeLe32(bytes, 24u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 12u, 12u));

    bytes[28u] = 0x01u;
    bytes[29u] = 0x03u;
    bytes[30u] = 0x00u;
    const std::uint8_t filteredBranch[] = {0x00u, 0xf0u, 0x02u, 0xf8u};
    std::memcpy(bytes.data() + 31u, filteredBranch, sizeof(filteredBranch));
    bytes[35u] = 0x00u;

    bytes[36u] = 0x00u;
    bytes[37u] = 0x01u;
    bytes[38u] = 0x18u;
    bytes[39u] = 0x04u;
    writeLe32(bytes, 40u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 36u, 4u));
    bytes[48u] = 0x01u;
    bytes[54u] = static_cast<std::uint8_t>('Y');
    bytes[55u] = static_cast<std::uint8_t>('Z');
    writeLe32(bytes, 44u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 48u, 6u));
    return bytes;
}

static std::vector<std::uint8_t> makeXzArm64StoredLzma2()
{
    /* The second block starts at stream offset four.  Its filtered ARM64 BL
     * immediate is one; subtracting PC/4 restores the zero immediate. */
    std::vector<std::uint8_t> bytes(84u, 0u);
    const std::uint8_t magic[] = {
        0xfdu, 0x37u, 0x7au, 0x58u, 0x5au, 0x00u};
    std::memcpy(bytes.data(), magic, sizeof(magic));
    writeLe32(bytes, 8u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 6u, 2u));

    for (std::size_t block = 12u; block <= 36u; block += 24u) {
        bytes[block] = 0x03u;
        bytes[block + 1u] = 0xc1u;
        bytes[block + 2u] = 0x08u;
        bytes[block + 3u] = 0x04u;
        bytes[block + 4u] = 0x0au; /* ARM64 BCJ */
        bytes[block + 5u] = 0x00u;
        bytes[block + 6u] = 0x21u; /* LZMA2 */
        bytes[block + 7u] = 0x01u;
        bytes[block + 8u] = 0x00u;
        writeLe32(bytes, block + 12u,
                  RinRuntime::rinruntime_archive_crc32(bytes.data() + block,
                                                        12u));
    }

    bytes[28u] = 0x01u;
    bytes[29u] = 0x03u;
    bytes[30u] = 0x00u;
    const std::uint8_t firstBlock[] = {0x00u, 0x00u, 0x00u, 0x00u};
    std::memcpy(bytes.data() + 31u, firstBlock, sizeof(firstBlock));
    bytes[35u] = 0x00u;

    bytes[52u] = 0x01u;
    bytes[53u] = 0x03u;
    bytes[54u] = 0x00u;
    const std::uint8_t filteredBranch[] = {0x01u, 0x00u, 0x00u, 0x94u};
    std::memcpy(bytes.data() + 55u, filteredBranch, sizeof(filteredBranch));
    bytes[59u] = 0x00u;

    bytes[60u] = 0x00u;
    bytes[61u] = 0x02u;
    bytes[62u] = 0x18u;
    bytes[63u] = 0x04u;
    bytes[64u] = 0x18u;
    bytes[65u] = 0x04u;
    writeLe32(bytes, 68u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 60u, 8u));
    bytes[76u] = 0x02u;
    bytes[82u] = static_cast<std::uint8_t>('Y');
    bytes[83u] = static_cast<std::uint8_t>('Z');
    writeLe32(bytes, 72u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 76u, 6u));
    return bytes;
}

static std::vector<std::uint8_t> makeXzPowerPcStoredLzma2()
{
    /* The second block starts at stream offset four.  Its filtered big-endian
     * PowerPC branch target is absolute; BCJ decoding restores a zero
     * PC-relative displacement. */
    std::vector<std::uint8_t> bytes(84u, 0u);
    const std::uint8_t magic[] = {
        0xfdu, 0x37u, 0x7au, 0x58u, 0x5au, 0x00u};
    std::memcpy(bytes.data(), magic, sizeof(magic));
    writeLe32(bytes, 8u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 6u, 2u));

    for (std::size_t block = 12u; block <= 36u; block += 24u) {
        bytes[block] = 0x03u;
        bytes[block + 1u] = 0xc1u;
        bytes[block + 2u] = 0x08u;
        bytes[block + 3u] = 0x04u;
        bytes[block + 4u] = 0x05u; /* PowerPC BCJ */
        bytes[block + 5u] = 0x00u;
        bytes[block + 6u] = 0x21u;
        bytes[block + 7u] = 0x01u;
        bytes[block + 8u] = 0x00u;
        writeLe32(bytes, block + 12u,
                  RinRuntime::rinruntime_archive_crc32(bytes.data() + block,
                                                        12u));
    }

    bytes[28u] = 0x01u;
    bytes[29u] = 0x03u;
    bytes[30u] = 0x00u;
    const std::uint8_t firstBlock[] = {0x00u, 0x00u, 0x00u, 0x00u};
    std::memcpy(bytes.data() + 31u, firstBlock, sizeof(firstBlock));
    bytes[35u] = 0x00u;

    bytes[52u] = 0x01u;
    bytes[53u] = 0x03u;
    bytes[54u] = 0x00u;
    const std::uint8_t filteredBranch[] = {0x48u, 0x00u, 0x00u, 0x05u};
    std::memcpy(bytes.data() + 55u, filteredBranch, sizeof(filteredBranch));
    bytes[59u] = 0x00u;

    bytes[60u] = 0x00u;
    bytes[61u] = 0x02u;
    bytes[62u] = 0x18u;
    bytes[63u] = 0x04u;
    bytes[64u] = 0x18u;
    bytes[65u] = 0x04u;
    writeLe32(bytes, 68u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 60u, 8u));
    bytes[76u] = 0x02u;
    bytes[82u] = static_cast<std::uint8_t>('Y');
    bytes[83u] = static_cast<std::uint8_t>('Z');
    writeLe32(bytes, 72u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 76u, 6u));
    return bytes;
}

static std::vector<std::uint8_t> makeXzSparcStoredLzma2()
{
    /* The second block starts at stream offset four.  Its filtered SPARC CALL
     * target is absolute; BCJ decoding restores a zero PC-relative offset. */
    std::vector<std::uint8_t> bytes(84u, 0u);
    const std::uint8_t magic[] = {
        0xfdu, 0x37u, 0x7au, 0x58u, 0x5au, 0x00u};
    std::memcpy(bytes.data(), magic, sizeof(magic));
    writeLe32(bytes, 8u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 6u, 2u));

    for (std::size_t block = 12u; block <= 36u; block += 24u) {
        bytes[block] = 0x03u;
        bytes[block + 1u] = 0xc1u;
        bytes[block + 2u] = 0x08u;
        bytes[block + 3u] = 0x04u;
        bytes[block + 4u] = 0x09u; /* SPARC BCJ */
        bytes[block + 5u] = 0x00u;
        bytes[block + 6u] = 0x21u;
        bytes[block + 7u] = 0x01u;
        bytes[block + 8u] = 0x00u;
        writeLe32(bytes, block + 12u,
                  RinRuntime::rinruntime_archive_crc32(bytes.data() + block,
                                                        12u));
    }

    bytes[28u] = 0x01u;
    bytes[29u] = 0x03u;
    bytes[30u] = 0x00u;
    const std::uint8_t firstBlock[] = {0x00u, 0x00u, 0x00u, 0x00u};
    std::memcpy(bytes.data() + 31u, firstBlock, sizeof(firstBlock));
    bytes[35u] = 0x00u;
    bytes[52u] = 0x01u;
    bytes[53u] = 0x03u;
    bytes[54u] = 0x00u;
    const std::uint8_t filteredCall[] = {0x40u, 0x00u, 0x00u, 0x01u};
    std::memcpy(bytes.data() + 55u, filteredCall, sizeof(filteredCall));
    bytes[59u] = 0x00u;

    bytes[60u] = 0x00u;
    bytes[61u] = 0x02u;
    bytes[62u] = 0x18u;
    bytes[63u] = 0x04u;
    bytes[64u] = 0x18u;
    bytes[65u] = 0x04u;
    writeLe32(bytes, 68u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 60u, 8u));
    bytes[76u] = 0x02u;
    bytes[82u] = static_cast<std::uint8_t>('Y');
    bytes[83u] = static_cast<std::uint8_t>('Z');
    writeLe32(bytes, 72u,
              RinRuntime::rinruntime_archive_crc32(bytes.data() + 76u, 6u));
    return bytes;
}

int main()
{
    const std::uint8_t stored[] = {
        0x01u, 0x05u, 0x00u, 0xfau, 0xffu, 'h', 'e', 'l', 'l', 'o'};
    RinRuntime::ArchiveDeflateDecoder deflate;
    std::string output;
    assert(deflate.decode(stored, sizeof(stored), 5u, 0x3610a686u,
                          output) == RinRuntime::ArchiveDeflateResult::Ok);
    assert(output == "hello");

    RinRuntime::ArchiveDeflateEncoder encoder;
    std::vector<std::uint8_t> encoded;
    assert(encoder.encode(reinterpret_cast<const std::uint8_t*>("hello"), 5u,
                          encoded) == RinRuntime::ArchiveDeflateResult::Ok);
    output.clear();
    assert(deflate.decode(encoded.data(), encoded.size(), 5u, 0x3610a686u,
                          output) == RinRuntime::ArchiveDeflateResult::Ok &&
           output == "hello");
    std::uint32_t cancellationRequested = 1u;
    assert(encoder.encode(reinterpret_cast<const std::uint8_t*>("hello"), 5u,
                          encoded, cancelNow, &cancellationRequested) ==
           RinRuntime::ArchiveDeflateResult::Cancelled && encoded.empty());
    std::uint32_t deadlineExpired = 1u;
    output = "poison";
    assert(deflate.decodeWithDeadline(
               stored, sizeof(stored), 5u, 0x3610a686u, output,
               deadlineNow, &deadlineExpired) ==
           RinRuntime::ArchiveDeflateResult::Deadline);
    assert(output.empty());

    std::vector<std::uint8_t> gzip = makeGzip(
        reinterpret_cast<const std::uint8_t*>("hello"), 5u);
    RinRuntime::ArchiveGzipReader gzipReader;
    assert(gzipReader.decode(gzip.data(), gzip.size(), output) ==
           RinRuntime::ArchiveGzipResult::Ok && output == "hello");
    deadlineExpired = 1u;
    output = "poison";
    assert(gzipReader.decodeWithDeadline(
               gzip.data(), gzip.size(), output, deadlineNow,
               &deadlineExpired) == RinRuntime::ArchiveGzipResult::Deadline);
    assert(output.empty());
    std::string gzipStreamed;
    assert(gzipReader.decodeToSinkWithDeadline(
               gzip.data(), gzip.size(), &collectTar, &gzipStreamed,
               deadlineNow, &deadlineExpired) ==
           RinRuntime::ArchiveGzipResult::Deadline);
    assert(gzipStreamed.empty());
    std::vector<std::uint8_t> gzipCompressed(gzip.size(), 0u);
    RinRuntime::ArchiveGzipSource gzipSource{
        [](void* context, std::uint8_t* bytes, std::size_t capacity,
           std::size_t* bytesRead) -> bool {
            auto* source = static_cast<std::vector<std::uint8_t>*>(context);
            if (source == nullptr || bytes == nullptr || bytesRead == nullptr ||
                capacity < source->size())
                return false;
            std::memcpy(bytes, source->data(), source->size());
            *bytesRead = source->size();
            return true;
        },
        &gzip, gzip.size()};
    output = "poison";
    assert(gzipReader.decodeWithDeadline(
               gzipSource, gzipCompressed.data(), gzipCompressed.size(),
               output, deadlineNow, &deadlineExpired) ==
           RinRuntime::ArchiveGzipResult::Deadline);
    assert(output.empty());

    const std::vector<std::uint8_t> tar = makeTar();
    RinRuntime::ArchiveTarReader tarReader;
    assert(tarReader.parse(tar.data(), tar.size()) ==
           RinRuntime::ArchiveTarResult::Ok);
    assert(tarReader.size() == 1u && tarReader.entries()[0].name ==
           "docs/readme.txt");
    std::string streamed;
    assert(tarReader.readEntryToSink(0u, &collectTar, &streamed) ==
           RinRuntime::ArchiveTarResult::Ok && streamed == "hello");
    deadlineExpired = 1u;
    assert(tarReader.parseWithDeadline(tar.data(), tar.size(), deadlineNow,
                                       &deadlineExpired) ==
           RinRuntime::ArchiveTarResult::Deadline);
    assert(tarReader.empty());
    assert(tarReader.parse(tar.data(), tar.size()) ==
           RinRuntime::ArchiveTarResult::Ok);
    output = "poison";
    assert(tarReader.readEntryWithDeadline(0u, output, deadlineNow,
                                           &deadlineExpired) ==
           RinRuntime::ArchiveTarResult::Deadline);
    assert(output.empty());
    streamed.clear();
    assert(tarReader.readEntryToSinkWithDeadline(
               0u, &collectTar, &streamed, deadlineNow, &deadlineExpired) ==
           RinRuntime::ArchiveTarResult::Deadline);
    assert(streamed.empty());
    assert(tarReader.readEntryToSink(0u, &rejectTar, &streamed) ==
           RinRuntime::ArchiveTarResult::Malformed);

    const std::vector<std::uint8_t> tarGzip = makeGzip(tar.data(), tar.size());
    RinRuntime::ArchiveTarGzipReader tarGzipReader;
    assert(tarGzipReader.parse(tarGzip.data(), tarGzip.size()) ==
           RinRuntime::ArchiveTarGzipResult::Ok);
    assert(tarGzipReader.size() == 1u && tarGzipReader.totalContent() == 5u);
    streamed.clear();
    assert(tarGzipReader.readEntryToSink(0u, &collectTar, &streamed) ==
           RinRuntime::ArchiveTarGzipResult::Ok && streamed == "hello");
    deadlineExpired = 1u;
    assert(tarGzipReader.parseWithDeadline(tarGzip.data(), tarGzip.size(),
                                           deadlineNow, &deadlineExpired) ==
           RinRuntime::ArchiveTarGzipResult::Deadline);
    assert(tarGzipReader.empty());
    assert(tarGzipReader.parse(tarGzip.data(), tarGzip.size()) ==
           RinRuntime::ArchiveTarGzipResult::Ok);
    streamed.clear();
    assert(tarGzipReader.readEntryToSinkWithDeadline(
               0u, &collectTar, &streamed, deadlineNow, &deadlineExpired) ==
           RinRuntime::ArchiveTarGzipResult::Deadline);
    assert(streamed.empty());

    const std::vector<std::uint8_t> zip = makeStoredZip();
    RinRuntime::ArchiveZipReader zipReader;
    assert(zipReader.parse(zip.data(), zip.size()) ==
           RinRuntime::ArchiveZipResult::Ok);
    assert(zipReader.size() == 1u && zipReader.entries()[0].name ==
           "docs/readme.txt");
    assert(zipReader.readEntry(0u, output) ==
           RinRuntime::ArchiveZipResult::Ok && output == "hello");
    deadlineExpired = 1u;
    output = "poison";
    assert(zipReader.readEntryWithDeadline(0u, output, deadlineNow,
                                           &deadlineExpired) ==
           RinRuntime::ArchiveZipResult::Deadline);
    assert(output.empty());
    streamed.clear();
    assert(zipReader.readEntryToSinkWithDeadline(
               0u, &collectTar, &streamed, deadlineNow, &deadlineExpired) ==
           RinRuntime::ArchiveZipResult::Deadline);
    assert(streamed.empty());
    assert(zipReader.parseWithDeadline(zip.data(), zip.size(), deadlineNow,
                                       &deadlineExpired) ==
           RinRuntime::ArchiveZipResult::Deadline);

    std::vector<std::uint8_t> traversal = zip;
    const std::size_t nameOffset = 30u;
    traversal[nameOffset] = '.';
    traversal[nameOffset + 1u] = '.';
    assert(zipReader.parse(traversal.data(), traversal.size()) ==
           RinRuntime::ArchiveZipResult::Malformed);

    const std::vector<std::uint8_t> xz = makeXzStructure();
    RinRuntime::ArchiveXzReader xzReader;
    RinRuntime::ArchiveXzSummary xzSummary;
    xzSummary.uncompressedSize = 99u;
    assert(xzReader.inspect(xz.data(), xz.size(), xzSummary) ==
           RinRuntime::ArchiveXzResult::Ok);
    assert(xzSummary.streamSize == xz.size() && xzSummary.indexOffset == 28u &&
           xzSummary.indexSize == 8u && xzSummary.blockCount == 1u &&
           xzSummary.uncompressedSize == 0u && xzSummary.compressedSize == 1u &&
           xzSummary.checkType == 0u);
    std::vector<std::uint8_t> badXz = xz;
    badXz[20u] ^= 0x01u;
    assert(xzReader.inspect(badXz.data(), badXz.size(), xzSummary) ==
           RinRuntime::ArchiveXzResult::CrcMismatch &&
           xzSummary.streamSize == 0u);
    badXz = xz;
    badXz[7u] = 0x02u; /* SHA-256 check is recognized as unsupported. */
    writeLe32(badXz, 8u,
              RinRuntime::rinruntime_archive_crc32(badXz.data() + 6u, 2u));
    assert(xzReader.inspect(badXz.data(), badXz.size(), xzSummary) ==
           RinRuntime::ArchiveXzResult::Unsupported);
    assert(xzReader.inspect(nullptr, xz.size(), xzSummary) ==
           RinRuntime::ArchiveXzResult::InvalidArgument);
    assert(xzReader.inspect(xz.data(), 23u, xzSummary) ==
           RinRuntime::ArchiveXzResult::Malformed);
    const std::vector<std::uint8_t> nonCanonicalXz = makeXzNonCanonicalVli();
    assert(xzReader.inspect(nonCanonicalXz.data(), nonCanonicalXz.size(),
                            xzSummary) == RinRuntime::ArchiveXzResult::Malformed);

    const std::vector<std::uint8_t> storedXz = makeXzStoredLzma2(0u);
    std::string xzOutput = "poison";
    assert(xzReader.decodeStoredLzma2(storedXz.data(), storedXz.size(),
                                      xzOutput) == RinRuntime::ArchiveXzResult::Ok);
    assert(xzOutput == "hello");
    std::vector<std::uint8_t> compressedXz = storedXz;
    compressedXz[24u] = 0x80u;
    xzOutput = "poison";
    assert(xzReader.decodeStoredLzma2(compressedXz.data(), compressedXz.size(),
                                      xzOutput) ==
           RinRuntime::ArchiveXzResult::Malformed);
    assert(xzOutput == "poison");
    const std::vector<std::uint8_t> crcXz = makeXzStoredLzma2(1u);
    xzOutput = "poison";
    assert(xzReader.decodeStoredLzma2(crcXz.data(), crcXz.size(), xzOutput) ==
           RinRuntime::ArchiveXzResult::Ok);
    assert(xzOutput == "hello");
    const std::vector<std::uint8_t> crc64Xz = makeXzStoredLzma2(4u);
    assert(xzCrc64(reinterpret_cast<const std::uint8_t*>("hello"), 5u) ==
           UINT64_C(0x9b1edae5dbb937b1));
    xzOutput = "poison";
    assert(xzReader.decodeStoredLzma2(crc64Xz.data(), crc64Xz.size(),
                                      xzOutput) ==
           RinRuntime::ArchiveXzResult::Ok);
    assert(xzOutput == "hello");
    const std::vector<std::uint8_t> deltaXz = makeXzDeltaStoredLzma2();
    xzOutput = "poison";
    assert(xzReader.decodeStoredLzma2(deltaXz.data(), deltaXz.size(),
                                      xzOutput) ==
           RinRuntime::ArchiveXzResult::Ok);
    assert(xzOutput == "hello");
    const std::vector<std::uint8_t> x86Xz = makeXzX86StoredLzma2();
    xzOutput = "poison";
    assert(xzReader.decodeStoredLzma2(x86Xz.data(), x86Xz.size(), xzOutput) ==
           RinRuntime::ArchiveXzResult::Ok);
    assert(xzOutput == std::string({static_cast<char>(0xe8), '\0', '\0',
                                    '\0', '\0'}));
    const std::vector<std::uint8_t> armXz = makeXzArmStoredLzma2();
    xzOutput = "poison";
    assert(xzReader.decodeStoredLzma2(armXz.data(), armXz.size(), xzOutput) ==
           RinRuntime::ArchiveXzResult::Ok);
    assert(xzOutput == std::string({'\0', '\0', '\0',
                                    static_cast<char>(0xeb)}));
    const std::vector<std::uint8_t> armThumbXz =
        makeXzArmThumbStoredLzma2();
    xzOutput = "poison";
    assert(xzReader.decodeStoredLzma2(armThumbXz.data(), armThumbXz.size(),
                                      xzOutput) ==
           RinRuntime::ArchiveXzResult::Ok);
    assert(xzOutput == std::string({'\0', static_cast<char>(0xf0), '\0',
                                    static_cast<char>(0xf8)}));
    const std::vector<std::uint8_t> arm64Xz = makeXzArm64StoredLzma2();
    xzOutput = "poison";
    assert(xzReader.decodeStoredLzma2(arm64Xz.data(), arm64Xz.size(), xzOutput) ==
           RinRuntime::ArchiveXzResult::Ok);
    assert(xzOutput == std::string({'\0', '\0', '\0', '\0', '\0', '\0',
                                    '\0', static_cast<char>(0x94)}));
    const std::vector<std::uint8_t> powerPcXz =
        makeXzPowerPcStoredLzma2();
    xzOutput = "poison";
    assert(xzReader.decodeStoredLzma2(powerPcXz.data(), powerPcXz.size(),
                                      xzOutput) ==
           RinRuntime::ArchiveXzResult::Ok);
    assert(xzOutput == std::string({'\0', '\0', '\0', '\0',
                                    static_cast<char>(0x48), '\0', '\0', 1}));
    const std::vector<std::uint8_t> sparcXz = makeXzSparcStoredLzma2();
    xzOutput = "poison";
    assert(xzReader.decodeStoredLzma2(sparcXz.data(), sparcXz.size(),
                                      xzOutput) ==
           RinRuntime::ArchiveXzResult::Ok);
    assert(xzOutput == std::string({'\0', '\0', '\0', '\0',
                                    static_cast<char>(0x40), '\0', '\0', '\0'}));
    std::vector<std::uint8_t> unknownFilterXz = deltaXz;
    unknownFilterXz[16u] = 0x04u;
    writeLe32(unknownFilterXz, 24u,
              RinRuntime::rinruntime_archive_crc32(
                  unknownFilterXz.data() + 12u, 12u));
    xzOutput = "poison";
    assert(xzReader.decodeStoredLzma2(unknownFilterXz.data(),
                                      unknownFilterXz.size(), xzOutput) ==
           RinRuntime::ArchiveXzResult::Unsupported);
    assert(xzOutput == "poison");
    std::vector<std::uint8_t> duplicateDeltaXz = deltaXz;
    duplicateDeltaXz[19u] = 0x03u;
    writeLe32(duplicateDeltaXz, 24u,
              RinRuntime::rinruntime_archive_crc32(
                  duplicateDeltaXz.data() + 12u, 12u));
    xzOutput = "poison";
    assert(xzReader.decodeStoredLzma2(duplicateDeltaXz.data(),
                                      duplicateDeltaXz.size(), xzOutput) ==
           RinRuntime::ArchiveXzResult::Unsupported);
    assert(xzOutput == "poison");
    std::vector<std::uint8_t> wrongPropertySizeXz = deltaXz;
    wrongPropertySizeXz[17u] = 0u;
    writeLe32(wrongPropertySizeXz, 24u,
              RinRuntime::rinruntime_archive_crc32(
                  wrongPropertySizeXz.data() + 12u, 12u));
    xzOutput = "poison";
    assert(xzReader.decodeStoredLzma2(wrongPropertySizeXz.data(),
                                      wrongPropertySizeXz.size(), xzOutput) ==
           RinRuntime::ArchiveXzResult::Malformed);
    assert(xzOutput == "poison");
    std::vector<std::uint8_t> badCrc64Xz = crc64Xz;
    badCrc64Xz[36u] ^= 0x01u;
    xzOutput = "poison";
    assert(xzReader.decodeStoredLzma2(badCrc64Xz.data(), badCrc64Xz.size(),
                                      xzOutput) ==
           RinRuntime::ArchiveXzResult::CrcMismatch);
    assert(xzOutput == "poison");
    std::vector<std::uint8_t> badCrcXz = crcXz;
    badCrcXz[36u] ^= 0x01u;
    xzOutput = "poison";
    assert(xzReader.decodeStoredLzma2(badCrcXz.data(), badCrcXz.size(),
                                      xzOutput) ==
           RinRuntime::ArchiveXzResult::CrcMismatch);
    assert(xzOutput == "poison");

    const std::vector<std::uint8_t> rawLzma = {
        0x00u, 0x34u, 0x19u, 0x49u, 0xdbu, 0x85u, 0x5cu, 0x63u,
        0xadu, 0x3eu, 0xf9u, 0x63u, 0x73u, 0xe5u, 0x4fu, 0x1cu,
        0x74u, 0x7bu, 0xd4u, 0x27u, 0xaeu, 0x92u, 0xc5u, 0xf4u,
        0x54u, 0x43u, 0xdcu, 0xffu, 0xffu, 0xf2u, 0xcbu, 0x80u,
        0x00u};
    std::string rawLzmaExpected;
    for (unsigned index = 0u; index != 100u; ++index)
        rawLzmaExpected += "hello world! ";
    xzOutput = "poison";
    assert(xzReader.decodeRawLzma(
               rawLzma.data(), rawLzma.size(), 0x5du, 0x40000u,
               rawLzmaExpected.size(), xzOutput) ==
           RinRuntime::ArchiveXzResult::Ok);
    assert(xzOutput == rawLzmaExpected);
    xzOutput = "poison";
    assert(xzReader.decodeRawLzma(rawLzma.data(), rawLzma.size(), 0x5du,
                                  0x40000u, rawLzmaExpected.size(), xzOutput,
                                  cancelNow, &cancellationRequested) ==
           RinRuntime::ArchiveXzResult::Cancelled);
    assert(xzOutput == "poison");

    const std::vector<std::uint8_t> sevenZip = make7zStructure();
    RinRuntime::Archive7zReader sevenZipReader;
    RinRuntime::Archive7zSummary sevenZipSummary;
    assert(sevenZipReader.inspect(sevenZip.data(), sevenZip.size(),
                                  sevenZipSummary) ==
           RinRuntime::Archive7zResult::Ok);
    assert(sevenZipSummary.streamSize == sevenZip.size() &&
           sevenZipSummary.nextHeaderOffset == 32u &&
           sevenZipSummary.nextHeaderSize == 4u &&
           sevenZipSummary.majorVersion == 0u &&
           sevenZipSummary.minorVersion == 4u);
    std::vector<std::uint8_t> badSevenZip = sevenZip;
    badSevenZip[8u] ^= 0x01u;
    assert(sevenZipReader.inspect(badSevenZip.data(), badSevenZip.size(),
                                  sevenZipSummary) ==
           RinRuntime::Archive7zResult::CrcMismatch &&
           sevenZipSummary.streamSize == 0u);
    badSevenZip = sevenZip;
    badSevenZip[6u] = 1u;
    writeLe32(badSevenZip, 8u,
              RinRuntime::rinruntime_archive_crc32(badSevenZip.data() + 12u,
                                                   20u));
    assert(sevenZipReader.inspect(badSevenZip.data(), badSevenZip.size(),
                                  sevenZipSummary) ==
           RinRuntime::Archive7zResult::Unsupported);
    assert(sevenZipReader.inspect(nullptr, sevenZip.size(), sevenZipSummary) ==
           RinRuntime::Archive7zResult::InvalidArgument);
    assert(sevenZipReader.inspect(sevenZip.data(), 31u, sevenZipSummary) ==
           RinRuntime::Archive7zResult::Malformed);

    const std::vector<std::uint8_t> storedSevenZip = make7zStored();
    std::string sevenZipOutput = "poison";
    assert(sevenZipReader.decodeStored(storedSevenZip.data(),
                                       storedSevenZip.size(),
                                       sevenZipOutput) ==
           RinRuntime::Archive7zResult::Ok);
    assert(sevenZipOutput == "hello");
    const std::vector<std::uint8_t> emptySevenZip = make7zEmpty();
    sevenZipOutput = "poison";
    assert(sevenZipReader.decodeStored(emptySevenZip.data(),
                                       emptySevenZip.size(),
                                       sevenZipOutput) ==
           RinRuntime::Archive7zResult::Ok);
    assert(sevenZipOutput.empty());
    std::vector<std::uint8_t> malformedEmptySevenZip = emptySevenZip;
    malformedEmptySevenZip[38u] = 0x02u; /* multi-byte EmptyStream bitmap */
    malformedEmptySevenZip.insert(malformedEmptySevenZip.begin() + 40u, 0u);
    writeLe64(malformedEmptySevenZip, 20u,
              malformedEmptySevenZip.size() - 32u);
    writeLe32(malformedEmptySevenZip, 28u,
              RinRuntime::rinruntime_archive_crc32(
                  malformedEmptySevenZip.data() + 32u,
                  malformedEmptySevenZip.size() - 32u));
    writeLe32(malformedEmptySevenZip, 8u,
              RinRuntime::rinruntime_archive_crc32(
                  malformedEmptySevenZip.data() + 12u, 20u));
    sevenZipOutput = "poison";
    assert(sevenZipReader.decodeStored(malformedEmptySevenZip.data(),
                                       malformedEmptySevenZip.size(),
                                       sevenZipOutput) ==
           RinRuntime::Archive7zResult::Unsupported);
    assert(sevenZipOutput == "poison");
    std::vector<std::uint8_t> nonCanonicalSevenZip = storedSevenZip;
    nonCanonicalSevenZip.insert(nonCanonicalSevenZip.begin() + 41u, 0u);
    nonCanonicalSevenZip[40u] = 0x80u; /* PackPos 0 encoded with two bytes */
    writeLe64(nonCanonicalSevenZip, 20u,
              nonCanonicalSevenZip.size() - 37u);
    writeLe32(nonCanonicalSevenZip, 28u,
              RinRuntime::rinruntime_archive_crc32(
                  nonCanonicalSevenZip.data() + 37u,
                  nonCanonicalSevenZip.size() - 37u));
    writeLe32(nonCanonicalSevenZip, 8u,
              RinRuntime::rinruntime_archive_crc32(
                  nonCanonicalSevenZip.data() + 12u, 20u));
    sevenZipOutput = "poison";
    assert(sevenZipReader.decodeStored(nonCanonicalSevenZip.data(),
                                       nonCanonicalSevenZip.size(),
                                       sevenZipOutput) ==
           RinRuntime::Archive7zResult::Malformed);
    assert(sevenZipOutput == "poison");
    std::vector<std::uint8_t> emptyStoredSevenZip = storedSevenZip;
    emptyStoredSevenZip.erase(emptyStoredSevenZip.begin() + 32u,
                              emptyStoredSevenZip.begin() + 37u);
    writeLe64(emptyStoredSevenZip, 12u, 0u);
    writeLe64(emptyStoredSevenZip, 20u, 35u);
    emptyStoredSevenZip[38u] = 0u; /* PackInfo size */
    emptyStoredSevenZip[54u] = 0u; /* CodersUnpackSize */
    writeLe32(emptyStoredSevenZip, 41u,
              RinRuntime::rinruntime_archive_crc32(
                  emptyStoredSevenZip.data(), 0u));
    writeLe32(emptyStoredSevenZip, 57u,
              RinRuntime::rinruntime_archive_crc32(
                  emptyStoredSevenZip.data(), 0u));
    writeLe32(emptyStoredSevenZip, 28u,
              RinRuntime::rinruntime_archive_crc32(
                  emptyStoredSevenZip.data() + 32u, 35u));
    writeLe32(emptyStoredSevenZip, 8u,
              RinRuntime::rinruntime_archive_crc32(
                  emptyStoredSevenZip.data() + 12u, 20u));
    sevenZipOutput = "poison";
    assert(sevenZipReader.decodeStored(emptyStoredSevenZip.data(),
                                       emptyStoredSevenZip.size(),
                                       sevenZipOutput) ==
           RinRuntime::Archive7zResult::Unsupported);
    assert(sevenZipOutput == "poison");
    std::vector<std::uint8_t> badStoredSevenZip = storedSevenZip;
    badStoredSevenZip[32u] ^= 0x01u;
    sevenZipOutput = "poison";
    assert(sevenZipReader.decodeStored(badStoredSevenZip.data(),
                                       badStoredSevenZip.size(),
                                       sevenZipOutput) ==
           RinRuntime::Archive7zResult::CrcMismatch);
    assert(sevenZipOutput == "poison");
    return 0;
}
