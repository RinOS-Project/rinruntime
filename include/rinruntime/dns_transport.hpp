/* SPDX-License-Identifier: MIT */
/* Backend-independent DNS transport selection and exchange boundary. */

#ifndef RINRUNTIME_DNS_TRANSPORT_HPP
#define RINRUNTIME_DNS_TRANSPORT_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace RinRuntime {

/* The endpoint deliberately describes policy and identity, not a socket.  A
 * future DoT/DoH backend can consume the same immutable endpoint without
 * making the resolver or an external toolkit depend on a TLS/HTTP library. */
enum class DnsTransportKind : std::uint8_t {
    Udp = 1,
    Tcp = 2,
    Dot = 3,
    Doh = 4,
};

class DnsTransportEndpoint final {
public:
    using NamespaceId = std::array<std::uint8_t, 16>;

    static constexpr std::size_t kMaxAuthorityBytes = 253u;
    static constexpr std::size_t kMaxLabelBytes = 63u;
    static constexpr std::size_t kMaxHttpPathBytes = 256u;

    /* An empty DoH path selects the interoperable /dns-query resource.  For
     * UDP, TCP, and DoT the path must remain empty. */
    static bool build(DnsTransportKind kind, const std::string& authority,
                      std::uint16_t port, std::uint64_t network_generation,
                      std::uint64_t namespace_generation,
                      const NamespaceId& namespace_id,
                      DnsTransportEndpoint& output,
                      const std::string& http_path = std::string()) {
        DnsTransportEndpoint candidate;
        if (!validKind(kind) || !validAuthority(authority, candidate.authority_) ||
            port == 0u || network_generation == 0u ||
            namespace_generation == 0u || allZero(namespace_id))
            return false;

        candidate.kind_ = kind;
        candidate.port_ = port;
        candidate.network_generation_ = network_generation;
        candidate.namespace_generation_ = namespace_generation;
        candidate.namespace_id_ = namespace_id;

        if (kind == DnsTransportKind::Doh) {
            candidate.http_path_ = http_path.empty() ? "/dns-query" : http_path;
            if (!validHttpPath(candidate.http_path_)) return false;
        } else if (!http_path.empty()) {
            return false;
        }

        output = candidate;
        return true;
    }

    bool valid() const {
        DnsTransportEndpoint canonical;
        if (!build(kind_, authority_, port_, network_generation_,
                   namespace_generation_, namespace_id_, canonical,
                   http_path_))
            return false;
        return canonical.kind_ == kind_ && canonical.authority_ == authority_ &&
               canonical.port_ == port_ &&
               canonical.network_generation_ == network_generation_ &&
               canonical.namespace_generation_ == namespace_generation_ &&
               canonical.namespace_id_ == namespace_id_ &&
               canonical.http_path_ == http_path_;
    }

    DnsTransportKind kind() const { return kind_; }
    const std::string& authority() const { return authority_; }
    std::uint16_t port() const { return port_; }
    std::uint64_t networkGeneration() const { return network_generation_; }
    std::uint64_t namespaceGeneration() const { return namespace_generation_; }
    const NamespaceId& namespaceId() const { return namespace_id_; }
    const std::string& httpPath() const { return http_path_; }

    bool encrypted() const {
        return kind_ == DnsTransportKind::Dot ||
               kind_ == DnsTransportKind::Doh;
    }
    bool usesTls() const { return encrypted(); }
    bool usesHttp() const { return kind_ == DnsTransportKind::Doh; }

private:
    DnsTransportKind kind_ = DnsTransportKind::Udp;
    std::string authority_;
    std::uint16_t port_ = 0u;
    std::uint64_t network_generation_ = 0u;
    std::uint64_t namespace_generation_ = 0u;
    NamespaceId namespace_id_{};
    std::string http_path_;

    static bool validKind(DnsTransportKind kind) {
        return kind == DnsTransportKind::Udp || kind == DnsTransportKind::Tcp ||
               kind == DnsTransportKind::Dot || kind == DnsTransportKind::Doh;
    }

    static bool allZero(const NamespaceId& value) {
        for (std::uint8_t byte : value)
            if (byte != 0u) return false;
        return true;
    }

    static bool validAuthority(const std::string& value,
                               std::string& canonical) {
        if (value.empty() || value.size() > kMaxAuthorityBytes) return false;
        std::size_t label_length = 0u;
        canonical.clear();
        canonical.reserve(value.size());
        for (std::size_t index = 0u; index < value.size(); ++index) {
            const unsigned char byte =
                static_cast<unsigned char>(value[index]);
            if (byte == '.') {
                if (label_length == 0u || value[index - 1u] == '-') return false;
                label_length = 0u;
                canonical.push_back('.');
                continue;
            }
            const bool alpha = (byte >= 'a' && byte <= 'z') ||
                               (byte >= 'A' && byte <= 'Z');
            const bool digit = byte >= '0' && byte <= '9';
            if ((!alpha && !digit && byte != '-') ||
                (label_length == 0u && byte == '-'))
                return false;
            ++label_length;
            if (label_length > kMaxLabelBytes) return false;
            if (index + 1u == value.size() && byte == '-') return false;
            canonical.push_back(alpha && byte >= 'A' && byte <= 'Z'
                                    ? static_cast<char>(byte - 'A' + 'a')
                                    : static_cast<char>(byte));
        }
        return label_length != 0u;
    }

    static bool validHttpPath(const std::string& value) {
        if (value.empty() || value.size() > kMaxHttpPathBytes ||
            value.front() != '/' || value.find("//") != std::string::npos)
            return false;
        std::size_t segment_start = 1u;
        for (std::size_t index = 0u; index <= value.size(); ++index) {
            if (index != value.size() && value[index] != '/') continue;
            const std::string segment =
                value.substr(segment_start, index - segment_start);
            if (segment == "." || segment == "..") return false;
            segment_start = index + 1u;
        }
        for (unsigned char byte : value) {
            if (byte <= 0x20u || byte >= 0x7fu || byte == '?' || byte == '#' ||
                byte == '\\' || byte == '%')
                return false;
        }
        return true;
    }
};

/* The callback is the only backend seam.  It receives an immutable endpoint
 * and bounded DNS wire buffers; it must not publish a result for another
 * network/namespace generation.  TLS certificate verification and HTTP
 * content-type handling remain backend responsibilities. */
using DnsTransportExchangeFunction = int (*)(
    void* context, const DnsTransportEndpoint& endpoint,
    const std::uint8_t* query, std::size_t query_length,
    std::uint8_t* response, std::size_t response_capacity,
    std::size_t* response_length);

class DnsTransportSession final {
public:
    static constexpr std::size_t kMaxQueryBytes = 1232u;
    static constexpr std::size_t kMaxResponseBytes = 4096u;

    bool bind(const DnsTransportEndpoint& endpoint,
              DnsTransportExchangeFunction exchange, void* context) {
        if (bound_ || exchange == nullptr || context == nullptr ||
            !endpoint.valid())
            return false;
        endpoint_ = endpoint;
        exchange_ = exchange;
        context_ = context;
        bound_ = true;
        return true;
    }

    bool exchange(const std::uint8_t* query, std::size_t query_length,
                  std::uint8_t* response, std::size_t response_capacity,
                  std::size_t* response_length) {
        if (response_length != nullptr) *response_length = 0u;
        if (!bound_ || in_flight_ || exchange_ == nullptr || query == nullptr ||
            query_length == 0u || query_length > kMaxQueryBytes ||
            response == nullptr || response_capacity == 0u ||
            response_capacity > kMaxResponseBytes || response_length == nullptr)
            return failResponse(response, response_capacity);

        for (std::size_t index = 0u; index < response_capacity; ++index)
            response[index] = 0u;
        in_flight_ = true;
        std::size_t written = 0u;
        const int result = exchange_(context_, endpoint_, query, query_length,
                                     response, response_capacity, &written);
        in_flight_ = false;
        if (result != 0 || written == 0u || written > response_capacity) {
            for (std::size_t index = 0u; index < response_capacity; ++index)
                response[index] = 0u;
            return false;
        }
        *response_length = written;
        return true;
    }

    void reset() {
        endpoint_ = DnsTransportEndpoint();
        exchange_ = nullptr;
        context_ = nullptr;
        in_flight_ = false;
        bound_ = false;
    }

    bool bound() const { return bound_; }
    const DnsTransportEndpoint& endpoint() const { return endpoint_; }

private:
    DnsTransportEndpoint endpoint_;
    DnsTransportExchangeFunction exchange_ = nullptr;
    void* context_ = nullptr;
    bool in_flight_ = false;
    bool bound_ = false;

    static bool failResponse(std::uint8_t* response,
                             std::size_t response_capacity) {
        if (response != nullptr && response_capacity <= kMaxResponseBytes)
            for (std::size_t index = 0u; index < response_capacity; ++index)
                response[index] = 0u;
        return false;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_DNS_TRANSPORT_HPP */
