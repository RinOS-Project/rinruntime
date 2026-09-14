// SPDX-License-Identifier: MIT

#include <cassert>
#include <cstddef>
#include <cstdint>

#include "../include/rinruntime/download_range_transport.hpp"

struct Owner {
    unsigned beginCalls = 0u;
    unsigned readCalls = 0u;
    unsigned abortCalls = 0u;
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
        *bytesRead = 2u;
        return 0;
    }
    if (owner->readCalls == 2u) {
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

static int cancelAfterBegin(void* opaque) {
    return static_cast<Owner*>(opaque)->beginCalls == 0u ? 0 : 1;
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
    receiptWire[42u] = 1u;
    assert(!RinRuntime::DownloadPartialReceipt::decode(
        receiptWire, receiptSize, decodedReceipt));
    receiptWire[42u] = 0u;
    receiptWire[43u] = 1u;
    assert(!RinRuntime::DownloadPartialReceipt::decode(
        receiptWire, receiptSize, decodedReceipt));

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
    RinRuntime::DownloadRangeResponse response;
    assert(ordinary.begin(request, response));
    std::uint8_t buffer[64u] = {};
    std::size_t bytesRead = 0u;
    assert(ordinary.read(buffer, sizeof(buffer), bytesRead) && bytesRead == 2u);
    assert(ordinary.read(buffer, sizeof(buffer), bytesRead) && bytesRead == 1u);
    assert(ordinary.read(buffer, sizeof(buffer), bytesRead) && bytesRead == 0u);

    Owner cancellableOwner;
    RinRuntime::DownloadRangeTransportOpsV1 cancellableOps = ordinaryOps;
    cancellableOps.context = &cancellableOwner;
    cancellableOps.cancelled = cancelAfterBegin;
    RinRuntime::DownloadRangeTransportAdapter cancellable;
    assert(cancellable.bind(cancellableOps));
    assert(!cancellable.begin(request, response));
    assert(cancellable.wasCancelled());
    assert(cancellableOwner.abortCalls == 1u);
    return 0;
}
