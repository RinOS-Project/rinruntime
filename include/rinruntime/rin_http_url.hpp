/* SPDX-License-Identifier: MIT */
#ifndef RIN_SHARED_HTTP_URL_HPP
#define RIN_SHARED_HTTP_URL_HPP

#include <rinuri/uri.h>

#include <string>

namespace RinRuntime {

/* URL value object shared by transport users without pulling in Browser UI. */
struct ParsedURL {
    std::string protocol;
    std::string host;
    int port = 80;
    std::string path;
    std::string query;
    bool valid = false;

    bool isSecure() const { return protocol == "https"; }
    bool isInternal() const { return protocol == "rin"; }
    bool isValid() const { return valid && !host.empty(); }

    std::string toString() const {
        if (!isValid()) return {};
        std::string result = protocol + "://";
        if (host.find(':') != std::string::npos) result += "[" + host + "]";
        else result += host;
        if ((protocol == "http" && port != 80) ||
            (protocol == "https" && port != 443)) {
            result += ":" + std::to_string(port);
        }
        result += path;
        if (!query.empty()) {
            result += "?" + query;
        }
        return result;
    }

    static ParsedURL parse(const std::string& url) {
        ParsedURL result;
        std::string input = url;
        RinUri uri = {};
        if (url.empty() || url.size() > RIN_URI_MAX_BYTES) return result;
        if (url.find("://") == std::string::npos) {
            if (url.size() > RIN_URI_MAX_BYTES - 7u) return result;
            input = "http://" + url;
        }
        if (rin_uri_parse(input.data(), input.size(), &uri) != 0 ||
            !uri.has_authority || uri.host.size == 0u ||
            uri.scheme.size == 0u || uri.port.size > 5u ||
            uri.has_userinfo != 0u || uri.has_fragment != 0u)
            return result;
        result.protocol.assign(uri.scheme.data, uri.scheme.size);
        result.host.assign(uri.host.data, uri.host.size);
        for (char& value : result.protocol) {
            if (value >= 'A' && value <= 'Z') value =
                static_cast<char>(value + ('a' - 'A'));
        }
        for (char& value : result.host) {
            if (value >= 'A' && value <= 'Z') value =
                static_cast<char>(value + ('a' - 'A'));
        }
        if (uri.port.size != 0u) {
            /* Port zero is a bind-side wildcard, not a usable HTTP origin. */
            if (uri.port_number == 0u) return result;
            result.port = static_cast<int>(uri.port_number);
        } else if (result.protocol == "https") result.port = 443;
        else result.port = 80;
        result.path = uri.path.size == 0u ? "/" :
            std::string(uri.path.data, uri.path.size);
        if (uri.has_query) result.query.assign(uri.query.data, uri.query.size);
        result.valid = true;
        return result;
    }
};

}  // namespace RinRuntime

#endif
