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

    const std::vector<std::uint8_t> tar = makeTar();
    assert(reader.parse(tar.data(), tar.size()) ==
           RinRuntime::ArchiveContainerResult::Ok);
    assert(reader.kind() == RinRuntime::ArchiveContainerKind::Tar &&
           reader.readEntry(0u, output) ==
               RinRuntime::ArchiveContainerResult::Ok && output == "hello");

    const std::vector<std::uint8_t> targz = makeGzip(tar.data(), tar.size());
    assert(reader.parse(targz.data(), targz.size()) ==
           RinRuntime::ArchiveContainerResult::Ok);
    assert(reader.kind() == RinRuntime::ArchiveContainerKind::TarGzip &&
           reader.readEntry(0u, output) ==
               RinRuntime::ArchiveContainerResult::Ok && output == "hello");

    const std::uint8_t unknown[] = {'x'};
    assert(reader.parse(unknown, sizeof(unknown)) ==
           RinRuntime::ArchiveContainerResult::Unsupported);
    assert(reader.empty() && reader.kind() ==
           RinRuntime::ArchiveContainerKind::Unknown);
    assert(reader.readEntry(0u, output) ==
           RinRuntime::ArchiveContainerResult::InvalidArgument);
    return 0;
}
