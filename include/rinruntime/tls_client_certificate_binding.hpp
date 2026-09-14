/* SPDX-License-Identifier: MIT */
/* Backend-neutral installer for pre-handshake TLS client certificates. */

#ifndef RINRUNTIME_TLS_CLIENT_CERTIFICATE_BINDING_HPP
#define RINRUNTIME_TLS_CLIENT_CERTIFICATE_BINDING_HPP

#include "tls_client_certificate_transport.hpp"

namespace RinRuntime {

using TlsClientCertificateInstallFunction = int (*)(
    void* tls_context, const void* certificate_list,
    std::size_t certificate_list_size,
    int (*signer)(void* opaque, std::uint16_t signature_scheme,
                  const std::uint8_t* message, std::size_t message_length,
                  std::uint8_t* signature, std::size_t signature_capacity,
                  std::size_t* signature_length),
    void* signer_opaque);

/* Install exactly once before the first handshake step. A failed backend
 * install leaves the transport Bound and does not expose a partial identity. */
inline bool installTlsClientCertificate(
    void* tls_context, TlsClientCertificateTransport& transport,
    TlsClientCertificateInstallFunction installer) {
    if (tls_context == nullptr || installer == nullptr ||
        transport.state() != TlsClientCertificateTransportState::Bound)
        return false;
    if (installer(tls_context, transport.certificateList(),
                  static_cast<std::size_t>(transport.certificateListSize()),
                  &TlsClientCertificateTransport::signCallback, &transport) !=
        0)
        return false;
    return transport.startHandshake();
}

} // namespace RinRuntime

#endif /* RINRUNTIME_TLS_CLIENT_CERTIFICATE_BINDING_HPP */
