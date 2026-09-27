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
    return 0;
}
