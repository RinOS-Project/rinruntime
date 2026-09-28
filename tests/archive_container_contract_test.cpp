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
    assert(value < 0x80u);
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
    header.push_back(0x01u); /* one-byte method ID, no properties */
    header.push_back(0x00u); /* Copy coder */
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
    put7zUInt64(header, 1u); /* NumFiles */
    header.push_back(0x00u); /* FilesInfo properties end */
    header.push_back(0x00u); /* Header end */

    std::vector<std::uint8_t> bytes(32u + sizeof(payload) + header.size(), 0u);
    std::memcpy(bytes.data(), signature, sizeof(signature));
    bytes[7u] = 4u;
    std::memcpy(bytes.data() + 32u, payload, sizeof(payload));
    const std::size_t headerOffset = 32u + sizeof(payload);
    std::memcpy(bytes.data() + headerOffset, header.data(), header.size());
    put64(bytes, 12u, sizeof(payload));
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

    std::vector<std::uint8_t> unsupportedXz = xz;
    unsupportedXz[24u] = 0x80u; /* range-coded LZMA2, outside public subset */
    assert(reader.parse(unsupportedXz.data(), unsupportedXz.size()) ==
           RinRuntime::ArchiveContainerResult::Unsupported);
    assert(reader.empty() && reader.kind() ==
           RinRuntime::ArchiveContainerKind::Unknown);
    return 0;
}
