/* SPDX-License-Identifier: MIT */

/*
 * General applications consume the public umbrella only.  This contract
 * deliberately does not include a kernel wait-set, service owner, Browser,
 * File Portal, or keyring header: those authorities remain private.
 */
#include <rinruntime/rinruntime.hpp>

#include <cassert>
#include <type_traits>

static_assert(std::is_default_constructible<RinRuntime::EventLoop>::value,
              "EventLoop is a public userspace model");
static_assert(std::is_base_of<RinRuntime::DownloadRangeTransport,
                              RinRuntime::DownloadRangeTransportAdapter>::value,
              "range transport adapter is a public generic transport");
static_assert(std::is_default_constructible<
                  RinRuntime::TlsClientCertificateTransport>::value,
              "TLS callback transport is a public adapter");
static_assert(!std::is_copy_constructible<
                  RinRuntime::DownloadRangeTransportAdapter>::value,
              "caller-owned streaming state must not be copied");

int main() {
    RinRuntime::EventLoop loop;
    RinRuntime::Event event = {};
    event.type = RinRuntime::EventType::Close;
    assert(loop.post(event));

    RinRuntime::Event output = {};
    assert(loop.runOne(0u, &output));
    assert(output.type == RinRuntime::EventType::Close);

    RinRuntime::DownloadRangeTransportAdapter range_transport;
    RinRuntime::TlsClientCertificateTransport tls_transport;
    (void)range_transport;
    (void)tls_transport;
    return 0;
}
