// SPDX-License-Identifier: MIT

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <stdexcept>
#include <string>
#include <type_traits>

#include "../include/rinruntime/download_range_transport.hpp"

static_assert(!std::is_copy_constructible<
                  RinRuntime::DownloadRangeTransportAdapter>::value);
static_assert(!std::is_copy_assignable<
                  RinRuntime::DownloadRangeTransportAdapter>::value);

struct Owner {
    unsigned beginCalls = 0u;
    unsigned readCalls = 0u;
    unsigned abortCalls = 0u;
    bool failAfterFirst = false;
};

static int beginRange(void* opaque,
                      const RinRuntime::DownloadRangeRequest* request,
                      RinRuntime::DownloadRangeResponse* response) {
    auto* owner = static_cast<Owner*>(opaque);
    ++owner->beginCalls;
    owner->readCalls = 0u;
    if (request == nullptr || response == nullptr) return -1;
    response->statusCode = 206u;
    response->contentRangeStart = request->offset;
    response->contentRangeEnd = request->totalBytes - 1u;
    response->contentRangeTotal = request->totalBytes;
    response->contentLength = request->totalBytes - request->offset;
    response->generation = request->generation;
    response->validator = request->validator;
    return 0;
}

static int readRange(void* opaque, std::uint8_t* buffer, std::size_t capacity,
                     std::size_t* bytesRead) {
    auto* owner = static_cast<Owner*>(opaque);
    if (buffer == nullptr || bytesRead == nullptr || capacity == 0u)
        return -1;
    ++owner->readCalls;
    if (owner->readCalls == 1u) {
        if (capacity < 2u) return -1;
        buffer[0] = 0xa1u;
        buffer[1] = 0xa2u;
        buffer[capacity - 1u] = 0xeeu;
        *bytesRead = 2u;
        return 0;
    }
    if (owner->readCalls == 2u) {
        if (owner->failAfterFirst) {
            buffer[0] = 0xdeu;
            *bytesRead = 1u;
            return -1;
        }
        buffer[0] = 0xb1u;
        *bytesRead = 1u;
        return 0;
    }
    *bytesRead = 0u;
    return 0;
}

static void abortRange(void* opaque) {
    ++static_cast<Owner*>(opaque)->abortCalls;
}

static int throwingBegin(void*, const RinRuntime::DownloadRangeRequest*,
                         RinRuntime::DownloadRangeResponse*) {
    throw std::bad_alloc();
}

static int throwingRuntimeBegin(void*, const RinRuntime::DownloadRangeRequest*,
                                RinRuntime::DownloadRangeResponse*) {
    throw std::runtime_error("begin callback failure");
}

static int throwingRuntimeRead(void*, std::uint8_t*, std::size_t,
                               std::size_t*) {
    throw std::runtime_error("read callback failure");
}

static int throwingRuntimeCancellation(void*) {
    throw std::runtime_error("cancellation callback failure");
}

static void throwingRuntimeAbort(void*) {
    throw std::runtime_error("abort callback failure");
}

class ThrowingRangeTransport final : public RinRuntime::DownloadRangeTransport {
public:
    bool throwFromBegin = false;
    bool abortCalled = false;

    bool begin(const RinRuntime::DownloadRangeRequest& request,
               RinRuntime::DownloadRangeResponse& response) override {
        if (throwFromBegin)
            throw std::runtime_error("transport begin failure");
        response.statusCode = 206u;
        response.contentRangeStart = request.offset;
        response.contentRangeEnd = request.totalBytes - 1u;
        response.contentRangeTotal = request.totalBytes;
        response.contentLength = request.totalBytes - request.offset;
        response.generation = request.generation;
        response.validator = request.validator;
        return true;
    }

    bool read(std::uint8_t* buffer, std::size_t capacity,
              std::size_t& bytesRead) override {
        if (buffer != nullptr && capacity != 0u) buffer[0] = 0xccu;
        bytesRead = 1u;
        throw std::runtime_error("transport read failure");
    }

    void abort() override {
        abortCalled = true;
        throw std::runtime_error("transport abort failure");
    }
};

class IncompleteRangeTransport final
    : public RinRuntime::DownloadRangeTransport {
public:
    bool begin(const RinRuntime::DownloadRangeRequest&,
               RinRuntime::DownloadRangeResponse& response) override {
        response.statusCode = 206u;
        response.contentLength = 0u;
        return true;
    }

    bool read(std::uint8_t*, std::size_t, std::size_t& bytesRead) override {
        bytesRead = 0u;
        return true;
    }

    void abort() override {}
};

class ReentrantGenericRangeTransport final
    : public RinRuntime::DownloadRangeTransport {
public:
    bool cancelFromBegin = false;
    bool cancelFromRead = false;
    bool cancelled = false;
    unsigned readCalls = 0u;

    bool begin(const RinRuntime::DownloadRangeRequest& request,
               RinRuntime::DownloadRangeResponse& response) override {
        response.statusCode = 206u;
        response.contentRangeStart = request.offset;
        response.contentRangeEnd = request.totalBytes - 1u;
        response.contentRangeTotal = request.totalBytes;
        response.contentLength = request.totalBytes - request.offset;
        response.generation = request.generation;
        response.validator = request.validator;
        if (cancelFromBegin) cancelled = true;
        return true;
    }

    bool read(std::uint8_t* buffer, std::size_t capacity,
              std::size_t& bytesRead) override {
        if (buffer == nullptr || capacity == 0u) return false;
        ++readCalls;
        buffer[0] = 0xd2u;
        bytesRead = 1u;
        if (cancelFromRead) cancelled = true;
        return true;
    }

    void abort() override { cancelled = true; }

    bool wasCancelled() const override { return cancelled; }
};

static int statelessBegin(void*,
                          const RinRuntime::DownloadRangeRequest* request,
                          RinRuntime::DownloadRangeResponse* response) {
    if (request == nullptr || response == nullptr) return -1;
    response->statusCode = 206u;
    response->contentRangeStart = request->offset;
    response->contentRangeEnd = request->totalBytes - 1u;
    response->contentRangeTotal = request->totalBytes;
    response->contentLength = request->totalBytes - request->offset;
    response->generation = request->generation;
    response->validator = request->validator;
    return 0;
}

static int statelessRead(void*, std::uint8_t*, std::size_t,
                         std::size_t* bytesRead) {
    if (bytesRead == nullptr) return -1;
    static unsigned calls = 0u;
    if (calls++ == 0u) {
        *bytesRead = 3u;
        return 0;
    }
    *bytesRead = 0u;
    return 0;
}

static void statelessAbort(void*) {}

struct ReentrantOwner {
    RinRuntime::DownloadRangeTransportAdapter* adapter = nullptr;
    unsigned beginCalls = 0u;
    unsigned readCalls = 0u;
    unsigned cancelCalls = 0u;
    unsigned abortCalls = 0u;
    bool abortOnRead = false;
    bool abortOnSecondCancellation = false;
};

static int reentrantBegin(
    void* opaque, const RinRuntime::DownloadRangeRequest* request,
    RinRuntime::DownloadRangeResponse* response) {
    auto* owner = static_cast<ReentrantOwner*>(opaque);
    ++owner->beginCalls;
    if (request == nullptr || response == nullptr) return -1;
    response->statusCode = 206u;
    response->contentRangeStart = request->offset;
    response->contentRangeEnd = request->totalBytes - 1u;
    response->contentRangeTotal = request->totalBytes;
    response->contentLength = request->totalBytes - request->offset;
    response->generation = request->generation;
    response->validator = request->validator;
    return 0;
}

static int reentrantRead(void* opaque, std::uint8_t* buffer,
                         std::size_t capacity, std::size_t* bytesRead) {
    auto* owner = static_cast<ReentrantOwner*>(opaque);
    ++owner->readCalls;
    if (buffer == nullptr || capacity == 0u || bytesRead == nullptr)
        return -1;
    if (owner->abortOnRead && owner->adapter != nullptr)
        owner->adapter->abort();
    buffer[0] = 0xd1u;
    *bytesRead = 1u;
    return 0;
}

static int reentrantCancellation(void* opaque) {
    auto* owner = static_cast<ReentrantOwner*>(opaque);
    ++owner->cancelCalls;
    if (owner->abortOnSecondCancellation && owner->cancelCalls == 2u &&
        owner->adapter != nullptr)
        owner->adapter->abort();
    return 0;
}

static void reentrantAbort(void* opaque) {
    ++static_cast<ReentrantOwner*>(opaque)->abortCalls;
}

static int cancelAfterBegin(void* opaque) {
    return static_cast<Owner*>(opaque)->beginCalls == 0u ? 0 : 1;
}

static int cancelAfterRead(void* opaque) {
    return static_cast<Owner*>(opaque)->readCalls == 0u ? 0 : 1;
}

static RinRuntime::DownloadRangeRequest makeRequest() {
    RinRuntime::DownloadRangeRequest request;
    request.requestId = 9u;
    request.generation = 4u;
    request.offset = 2u;
    request.totalBytes = 5u;
    request.validator = "etag-4";
    return request;
}

int main() {
    {
        Owner lifetimeOwner;
        RinRuntime::DownloadRangeTransportOpsV1 lifetimeOps;
        lifetimeOps.structSize = sizeof(lifetimeOps);
        lifetimeOps.context = &lifetimeOwner;
        lifetimeOps.begin = beginRange;
        lifetimeOps.read = readRange;
        lifetimeOps.abort = abortRange;
        {
            RinRuntime::DownloadRangeTransportAdapter lifetime;
            assert(lifetime.bind(lifetimeOps));
            RinRuntime::DownloadRangeResponse lifetimeResponse;
            assert(lifetime.begin(makeRequest(), lifetimeResponse));
            assert(lifetime.state() ==
                   RinRuntime::DownloadRangeTransportAdapter::State::Streaming);
        }
        assert(lifetimeOwner.abortCalls == 1u);
    }

    std::uint64_t rangeStart = 41u;
    std::uint64_t rangeEnd = 42u;
    std::uint64_t rangeTotal = 43u;
    assert(!RinRuntime::parseDownloadContentRange(
        "bytes 2-4/5 trailing", rangeStart, rangeEnd, rangeTotal));
    assert(rangeStart == 0u && rangeEnd == 0u && rangeTotal == 0u);

    std::uint64_t contentLength = 41u;
    assert(!RinRuntime::parseDownloadContentLength("12x", contentLength));
    assert(contentLength == 0u);
    const std::string oversizedHeader(
        RinRuntime::DownloadRangeRequest::kMaxRangeHeaderBytes + 1u, '1');
    assert(!RinRuntime::parseDownloadContentRange(
        oversizedHeader, rangeStart, rangeEnd, rangeTotal));
    assert(rangeStart == 0u && rangeEnd == 0u && rangeTotal == 0u);
    assert(!RinRuntime::parseDownloadContentLength(
        oversizedHeader, contentLength));
    assert(contentLength == 0u);

    RinRuntime::DownloadPartialReceipt receipt;
    receipt.requestId = 9u;
    receipt.totalBytes = 5u;
    receipt.committedBytes = 2u;
    receipt.generation = 4u;
    receipt.validator = "etag-4";
    std::uint8_t receiptWire[RinRuntime::DownloadPartialReceipt::kWireSize] = {};
    std::size_t receiptSize = 0u;
    assert(receipt.encode(receiptWire, sizeof(receiptWire), receiptSize));
    RinRuntime::DownloadPartialReceipt decodedReceipt;
    assert(RinRuntime::DownloadPartialReceipt::decode(
        receiptWire, receiptSize, decodedReceipt));

    {
        RinRuntime::DownloadPartialReceipt aliasedReceipt = receipt;
        const RinRuntime::DownloadPartialReceipt before = aliasedReceipt;
        std::size_t aliasedSize = 0x13579bdfu;
        assert(!aliasedReceipt.encode(
            reinterpret_cast<std::uint8_t*>(&aliasedReceipt),
            sizeof(aliasedReceipt), aliasedSize));
        assert(aliasedSize == 0x13579bdfu);
        assert(aliasedReceipt.requestId == before.requestId &&
               aliasedReceipt.totalBytes == before.totalBytes &&
               aliasedReceipt.committedBytes == before.committedBytes &&
               aliasedReceipt.generation == before.generation &&
               aliasedReceipt.validator == before.validator);
    }

    {
        std::uint8_t aliasedWire[RinRuntime::DownloadPartialReceipt::kWireSize];
        std::size_t aliasedSize = 0u;
        assert(receipt.encode(aliasedWire, sizeof(aliasedWire), aliasedSize));
        RinRuntime::DownloadPartialReceipt aliasedOutput;
        aliasedOutput.validator.assign(
            reinterpret_cast<const char*>(aliasedWire), aliasedSize);
        const std::string before = aliasedOutput.validator;
        assert(!RinRuntime::DownloadPartialReceipt::decode(
            reinterpret_cast<const std::uint8_t*>(
                aliasedOutput.validator.data()),
            aliasedOutput.validator.size(), aliasedOutput));
        assert(aliasedOutput.validator == before);
    }

    {
        union {
            std::uint8_t bytes[RinRuntime::DownloadPartialReceipt::kWireSize];
            std::size_t size;
        } outputAlias = {};
        outputAlias.size = 0x2468ace0u;
        const auto before = outputAlias;
        assert(!receipt.encode(outputAlias.bytes, sizeof(outputAlias.bytes),
                               outputAlias.size));
        assert(outputAlias.size == 0x2468ace0u);
        assert(std::memcmp(outputAlias.bytes, before.bytes,
                           sizeof(outputAlias.bytes)) == 0);
    }

    receiptWire[42u] = 1u;
    assert(!RinRuntime::DownloadPartialReceipt::decode(
        receiptWire, receiptSize, decodedReceipt));
    receiptWire[42u] = 0u;
    receiptWire[43u] = 1u;
    assert(!RinRuntime::DownloadPartialReceipt::decode(
        receiptWire, receiptSize, decodedReceipt));

    RinRuntime::DownloadRangeRequest prepared;
    prepared.validator = "stale";
    assert(prepared.prepare(receipt, receipt.requestId, receipt.generation,
                            receipt.validator));
    assert(prepared.offset == receipt.committedBytes);
    std::string rangeHeader = "stale";
    assert(prepared.makeRangeHeader(rangeHeader));
    assert(rangeHeader == "bytes=2-");

    RinRuntime::DownloadRangeResponse madeResponse;
    assert(RinRuntime::makeDownloadRangeResponse(
        prepared, 206u, "bytes 2-4/5", "3", prepared.generation,
        prepared.validator, madeResponse));
    assert(madeResponse.validFor(prepared));

    Owner ordinaryOwner;
    RinRuntime::DownloadRangeTransportOpsV1 ordinaryOps;
    ordinaryOps.structSize = sizeof(ordinaryOps);
    ordinaryOps.context = &ordinaryOwner;
    ordinaryOps.begin = beginRange;
    ordinaryOps.read = readRange;
    ordinaryOps.abort = abortRange;
    RinRuntime::DownloadRangeTransportAdapter ordinary;
    assert(ordinary.bind(ordinaryOps));

    const auto request = makeRequest();
    IncompleteRangeTransport incomplete;
    std::uint8_t incompleteOutput[3u] = {0xffu, 0xffu, 0xffu};
    std::size_t incompleteSize = 99u;
    assert(!RinRuntime::readDownloadRangeToBuffer(
        incomplete, request, incompleteOutput, sizeof(incompleteOutput),
        incompleteSize));
    assert(incompleteSize == 0u);
    for (const std::uint8_t byte : incompleteOutput) assert(byte == 0u);

    ReentrantGenericRangeTransport genericBeginCancelled;
    genericBeginCancelled.cancelFromBegin = true;
    std::uint8_t genericCancelledOutput[3u] = {0xffu, 0xffu, 0xffu};
    std::size_t genericCancelledSize = 99u;
    assert(!RinRuntime::readDownloadRangeToBuffer(
        genericBeginCancelled, request, genericCancelledOutput,
        sizeof(genericCancelledOutput), genericCancelledSize));
    assert(genericCancelledSize == 0u);
    for (const std::uint8_t byte : genericCancelledOutput) assert(byte == 0u);
    assert(genericBeginCancelled.readCalls == 0u);

    ReentrantGenericRangeTransport genericReadCancelled;
    genericReadCancelled.cancelFromRead = true;
    genericCancelledSize = 99u;
    assert(!RinRuntime::readDownloadRangeToBuffer(
        genericReadCancelled, request, genericCancelledOutput,
        sizeof(genericCancelledOutput), genericCancelledSize));
    assert(genericCancelledSize == 0u);
    for (const std::uint8_t byte : genericCancelledOutput) assert(byte == 0u);
    assert(genericReadCancelled.readCalls == 1u);

    RinRuntime::DownloadRangeResponse response;
    assert(ordinary.begin(request, response));
    std::uint8_t buffer[64u] = {};
    std::size_t bytesRead = 0u;
    assert(ordinary.read(buffer, sizeof(buffer), bytesRead) && bytesRead == 2u);
    for (std::size_t index = 2u; index < sizeof(buffer); ++index)
        assert(buffer[index] == 0u);
    assert(ordinary.read(buffer, sizeof(buffer), bytesRead) && bytesRead == 1u);
    std::uint8_t ordinaryEof[4u] = {0xffu, 0xffu, 0xffu, 0xffu};
    assert(ordinary.read(ordinaryEof, sizeof(ordinaryEof), bytesRead) &&
           bytesRead == 0u);
    for (const std::uint8_t byte : ordinaryEof) assert(byte == 0u);

    /* An owner callback may re-enter the public adapter and abort the active
     * range.  Callback return values must not resurrect that range or publish
     * bytes after the adapter has transitioned to Idle. */
    ReentrantOwner reentrantReadOwner;
    RinRuntime::DownloadRangeTransportOpsV1 reentrantReadOps;
    reentrantReadOps.structSize = sizeof(reentrantReadOps);
    reentrantReadOps.context = &reentrantReadOwner;
    reentrantReadOps.begin = reentrantBegin;
    reentrantReadOps.read = reentrantRead;
    reentrantReadOps.abort = reentrantAbort;
    RinRuntime::DownloadRangeTransportAdapter reentrantReadAdapter;
    reentrantReadOwner.adapter = &reentrantReadAdapter;
    reentrantReadOwner.abortOnRead = true;
    assert(reentrantReadAdapter.bind(reentrantReadOps));
    assert(reentrantReadAdapter.begin(request, response));
    std::uint8_t reentrantBytes[4u] = {0xffu, 0xffu, 0xffu, 0xffu};
    assert(!reentrantReadAdapter.read(reentrantBytes, sizeof(reentrantBytes),
                                      bytesRead) &&
           bytesRead == 0u);
    for (const std::uint8_t byte : reentrantBytes) assert(byte == 0u);
    assert(reentrantReadAdapter.state() ==
           RinRuntime::DownloadRangeTransportAdapter::State::Idle);
    assert(reentrantReadOwner.readCalls == 1u &&
           reentrantReadOwner.abortCalls == 1u);

    ReentrantOwner reentrantBeginOwner;
    RinRuntime::DownloadRangeTransportOpsV1 reentrantBeginOps;
    reentrantBeginOps.structSize = sizeof(reentrantBeginOps);
    reentrantBeginOps.context = &reentrantBeginOwner;
    reentrantBeginOps.begin = reentrantBegin;
    reentrantBeginOps.read = reentrantRead;
    reentrantBeginOps.abort = reentrantAbort;
    reentrantBeginOps.cancelled = reentrantCancellation;
    reentrantBeginOwner.abortOnSecondCancellation = true;
    RinRuntime::DownloadRangeTransportAdapter reentrantBeginAdapter;
    reentrantBeginOwner.adapter = &reentrantBeginAdapter;
    assert(reentrantBeginAdapter.bind(reentrantBeginOps));
    assert(!reentrantBeginAdapter.begin(request, response));
    assert(reentrantBeginAdapter.state() ==
           RinRuntime::DownloadRangeTransportAdapter::State::Idle);
    assert(reentrantBeginOwner.cancelCalls == 2u &&
           reentrantBeginOwner.beginCalls == 1u &&
           reentrantBeginOwner.abortCalls == 1u);

    /* An invalid direct-read capacity is terminal too.  The public adapter
     * must scrub the bounded prefix before returning failure, while bytes
     * beyond its admitted maximum remain outside the adapter's scrub bound. */
    Owner invalidCapacityOwner;
    RinRuntime::DownloadRangeTransportOpsV1 invalidCapacityOps = ordinaryOps;
    invalidCapacityOps.context = &invalidCapacityOwner;
    RinRuntime::DownloadRangeTransportAdapter invalidCapacity;
    assert(invalidCapacity.bind(invalidCapacityOps));
    assert(invalidCapacity.begin(request, response));
    std::uint8_t oversized[RinRuntime::DownloadRangeTransportAdapter::
                               kMaxChunkBytes + 1u];
    for (std::uint8_t& byte : oversized) byte = 0xffu;
    assert(!invalidCapacity.read(oversized, sizeof(oversized), bytesRead) &&
           bytesRead == 0u);
    for (std::size_t index = 0u;
         index < RinRuntime::DownloadRangeTransportAdapter::kMaxChunkBytes;
         ++index)
        assert(oversized[index] == 0u);
    assert(oversized[sizeof(oversized) - 1u] == 0xffu);
    assert(invalidCapacity.state() ==
           RinRuntime::DownloadRangeTransportAdapter::State::Failed);
    assert(invalidCapacityOwner.abortCalls == 1u);

    Owner helperOwner;
    RinRuntime::DownloadRangeTransportOpsV1 helperOps = ordinaryOps;
    helperOps.context = &helperOwner;
    RinRuntime::DownloadRangeTransportAdapter helper;
    assert(helper.bind(helperOps));
    std::uint8_t whole[3u] = {0u, 0u, 0u};
    std::size_t wholeSize = 0u;
    assert(RinRuntime::readDownloadRangeToBuffer(
        helper, request, whole, sizeof(whole), wholeSize));
    assert(wholeSize == sizeof(whole));
    assert(whole[0] == 0xa1u && whole[1] == 0xa2u && whole[2] == 0xb1u);

    Owner shortBufferOwner;
    RinRuntime::DownloadRangeTransportOpsV1 shortBufferOps = ordinaryOps;
    shortBufferOps.context = &shortBufferOwner;
    RinRuntime::DownloadRangeTransportAdapter shortBuffer;
    assert(shortBuffer.bind(shortBufferOps));
    std::uint8_t shortBufferBytes[2u] = {0xffu, 0xffu};
    wholeSize = 99u;
    assert(!RinRuntime::readDownloadRangeToBuffer(
        shortBuffer, request, shortBufferBytes, sizeof(shortBufferBytes),
        wholeSize));
    assert(wholeSize == 0u);
    for (const std::uint8_t byte : shortBufferBytes) assert(byte == 0u);

    Owner failedReadOwner;
    failedReadOwner.failAfterFirst = true;
    RinRuntime::DownloadRangeTransportOpsV1 failedReadOps = ordinaryOps;
    failedReadOps.context = &failedReadOwner;
    RinRuntime::DownloadRangeTransportAdapter failedRead;
    assert(failedRead.bind(failedReadOps));
    std::uint8_t failedReadBytes[3u] = {0xffu, 0xffu, 0xffu};
    wholeSize = 99u;
    assert(!RinRuntime::readDownloadRangeToBuffer(
        failedRead, request, failedReadBytes, sizeof(failedReadBytes),
        wholeSize));
    assert(wholeSize == 0u);
    assert(failedReadBytes[0] == 0u && failedReadBytes[1] == 0u &&
           failedReadBytes[2] == 0u);

    Owner directFailedOwner;
    directFailedOwner.failAfterFirst = true;
    RinRuntime::DownloadRangeTransportOpsV1 directFailedOps = ordinaryOps;
    directFailedOps.context = &directFailedOwner;
    RinRuntime::DownloadRangeTransportAdapter directFailed;
    assert(directFailed.bind(directFailedOps));
    assert(directFailed.begin(request, response));
    std::uint8_t directFailedBytes[4u] = {0xffu, 0xffu, 0xffu, 0xffu};
    assert(directFailed.read(directFailedBytes, sizeof(directFailedBytes),
                             bytesRead) &&
           bytesRead == 2u);
    directFailedBytes[0] = 0xffu;
    directFailedBytes[1] = 0xffu;
    directFailedBytes[2] = 0xffu;
    directFailedBytes[3] = 0xffu;
    assert(!directFailed.read(directFailedBytes, sizeof(directFailedBytes),
                              bytesRead) &&
           bytesRead == 0u);
    for (const std::uint8_t byte : directFailedBytes)
        assert(byte == 0u);

    /* The cancellation callback was appended to the public v1 table.  An
     * owner built against the original prefix remains valid and simply has
     * no cancellation hook. */
    RinRuntime::DownloadRangeTransportOpsV1 legacyOps = ordinaryOps;
    legacyOps.structSize =
        offsetof(RinRuntime::DownloadRangeTransportOpsV1, cancelled);
    RinRuntime::DownloadRangeTransportAdapter legacy;
    assert(legacy.bind(legacyOps));
    assert(legacy.begin(request, response));
    assert(legacy.read(buffer, sizeof(buffer), bytesRead) && bytesRead == 2u);
    assert(legacy.read(buffer, sizeof(buffer), bytesRead) && bytesRead == 1u);
    assert(legacy.read(buffer, sizeof(buffer), bytesRead) && bytesRead == 0u);

    /* A callback cookie is optional: stateless owners are valid public
     * consumers and must not be forced to invent a context object. */
    RinRuntime::DownloadRangeTransportOpsV1 statelessOps;
    statelessOps.structSize = sizeof(statelessOps);
    statelessOps.begin = statelessBegin;
    statelessOps.read = statelessRead;
    statelessOps.abort = statelessAbort;
    RinRuntime::DownloadRangeTransportAdapter stateless;
    assert(stateless.bind(statelessOps));
    assert(stateless.begin(request, response));
    assert(stateless.read(buffer, sizeof(buffer), bytesRead) && bytesRead == 3u);
    assert(stateless.read(buffer, sizeof(buffer), bytesRead) && bytesRead == 0u);

    Owner cancellableOwner;
    RinRuntime::DownloadRangeTransportOpsV1 cancellableOps = ordinaryOps;
    cancellableOps.context = &cancellableOwner;
    cancellableOps.cancelled = cancelAfterBegin;
    RinRuntime::DownloadRangeTransportAdapter cancellable;
    assert(cancellable.bind(cancellableOps));
    assert(!cancellable.begin(request, response));
    assert(cancellable.wasCancelled());
    assert(cancellableOwner.abortCalls == 1u);
    std::uint8_t afterCancellation[4u] = {0xffu, 0xffu, 0xffu, 0xffu};
    assert(!cancellable.read(afterCancellation, sizeof(afterCancellation),
                             bytesRead) &&
           bytesRead == 0u);
    for (const std::uint8_t byte : afterCancellation)
        assert(byte == 0u);
    cancellable.abort();

    Owner helperCancelledOwner;
    RinRuntime::DownloadRangeTransportOpsV1 helperCancelledOps = ordinaryOps;
    helperCancelledOps.context = &helperCancelledOwner;
    helperCancelledOps.cancelled = cancelAfterBegin;
    RinRuntime::DownloadRangeTransportAdapter helperCancelled;
    assert(helperCancelled.bind(helperCancelledOps));
    std::uint8_t cancelledOutput[5u] = {0xffu, 0xffu, 0xffu, 0xffu, 0xffu};
    std::size_t cancelledOutputSize = 99u;
    assert(!RinRuntime::readDownloadRangeToBuffer(
        helperCancelled, request, cancelledOutput, sizeof(cancelledOutput),
        cancelledOutputSize));
    assert(cancelledOutputSize == 0u);
    assert(helperCancelled.wasCancelled());
    assert(helperCancelledOwner.abortCalls == 1u);

    /* A cancellation reported after the owner has produced a partial read is
     * already terminal in the public adapter.  The convenience helper must
     * scrub the caller buffer without resetting that observable state. */
    Owner readCancelledOwner;
    RinRuntime::DownloadRangeTransportOpsV1 readCancelledOps = ordinaryOps;
    readCancelledOps.context = &readCancelledOwner;
    readCancelledOps.cancelled = cancelAfterRead;
    RinRuntime::DownloadRangeTransportAdapter readCancelled;
    assert(readCancelled.bind(readCancelledOps));
    std::uint8_t readCancelledOutput[3u] = {0xffu, 0xffu, 0xffu};
    std::size_t readCancelledSize = 99u;
    assert(!RinRuntime::readDownloadRangeToBuffer(
        readCancelled, request, readCancelledOutput,
        sizeof(readCancelledOutput), readCancelledSize));
    assert(readCancelledSize == 0u);
    for (const std::uint8_t byte : readCancelledOutput) assert(byte == 0u);
    assert(readCancelled.wasCancelled());
    assert(readCancelledOwner.abortCalls == 1u);

    Owner throwingOwner;
    RinRuntime::DownloadRangeTransportOpsV1 throwingOps = ordinaryOps;
    throwingOps.context = &throwingOwner;
    throwingOps.begin = throwingBegin;
    RinRuntime::DownloadRangeTransportAdapter throwing;
    assert(throwing.bind(throwingOps));
    response.statusCode = 206u;
    assert(!throwing.begin(request, response));
    assert(throwing.state() ==
           RinRuntime::DownloadRangeTransportAdapter::State::Idle);
    assert(throwingOwner.abortCalls == 1u);
    assert(response.statusCode == 0u);

    /* Public callback boundaries must also contain non-allocation C++
     * exceptions.  The owner may throw from begin/read/cancel/abort, but no
     * exception may escape and no partial bytes may remain visible. */
    RinRuntime::DownloadRangeTransportOpsV1 throwingRuntimeOps = ordinaryOps;
    throwingRuntimeOps.begin = throwingRuntimeBegin;
    throwingRuntimeOps.abort = throwingRuntimeAbort;
    RinRuntime::DownloadRangeTransportAdapter throwingRuntime;
    assert(throwingRuntime.bind(throwingRuntimeOps));
    assert(!throwingRuntime.begin(request, response));
    assert(throwingRuntime.state() ==
           RinRuntime::DownloadRangeTransportAdapter::State::Idle);
    throwingRuntimeOps = ordinaryOps;
    throwingRuntimeOps.read = throwingRuntimeRead;
    throwingRuntimeOps.abort = throwingRuntimeAbort;
    assert(throwingRuntime.bind(throwingRuntimeOps));
    assert(throwingRuntime.begin(request, response));
    std::uint8_t throwingBytes[4u] = {0xffu, 0xffu, 0xffu, 0xffu};
    assert(!throwingRuntime.read(throwingBytes, sizeof(throwingBytes),
                                 bytesRead));
    assert(bytesRead == 0u);
    for (const std::uint8_t byte : throwingBytes) assert(byte == 0u);
    assert(throwingRuntime.state() ==
           RinRuntime::DownloadRangeTransportAdapter::State::Failed);

    RinRuntime::DownloadRangeTransportAdapter throwingCancellation;
    throwingRuntimeOps = ordinaryOps;
    throwingRuntimeOps.cancelled = throwingRuntimeCancellation;
    assert(throwingCancellation.bind(throwingRuntimeOps));
    assert(!throwingCancellation.begin(request, response));
    assert(throwingCancellation.state() ==
           RinRuntime::DownloadRangeTransportAdapter::State::Idle);

    /* The convenience helper is also a public virtual-transport boundary.
     * A general application may implement DownloadRangeTransport directly;
     * owner exceptions must not escape, and a partially written caller
     * buffer must be scrubbed even when abort() itself throws. */
    ThrowingRangeTransport throwingTransport;
    throwingTransport.throwFromBegin = true;
    std::uint8_t ownerFailureOutput[4u] = {0xffu, 0xffu, 0xffu, 0xffu};
    std::size_t ownerFailureSize = 99u;
    assert(!RinRuntime::readDownloadRangeToBuffer(
        throwingTransport, request, ownerFailureOutput,
        sizeof(ownerFailureOutput), ownerFailureSize));
    assert(ownerFailureSize == 0u);
    for (const std::uint8_t byte : ownerFailureOutput) assert(byte == 0u);
    assert(throwingTransport.abortCalled);

    throwingTransport.throwFromBegin = false;
    throwingTransport.abortCalled = false;
    ownerFailureOutput[0] = ownerFailureOutput[1] =
        ownerFailureOutput[2] = ownerFailureOutput[3] = 0xffu;
    ownerFailureSize = 99u;
    assert(!RinRuntime::readDownloadRangeToBuffer(
        throwingTransport, request, ownerFailureOutput,
        sizeof(ownerFailureOutput), ownerFailureSize));
    assert(ownerFailureSize == 0u);
    for (const std::uint8_t byte : ownerFailureOutput) assert(byte == 0u);
    assert(throwingTransport.abortCalled);
    return 0;
}
