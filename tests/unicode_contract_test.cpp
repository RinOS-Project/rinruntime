// SPDX-License-Identifier: MIT

#include <cassert>
#include <cstdint>
#include <string>

#include "../include/rinruntime/unicode.hpp"

static std::string scalar(std::uint32_t codepoint)
{
    char bytes[4] = {};
    std::size_t written = 0u;
    assert(RinRuntime::utf8Encode(bytes, sizeof(bytes), codepoint, &written));
    return std::string(bytes, written);
}

static void appendScalar(std::string& value, std::uint32_t codepoint)
{
    value += scalar(codepoint);
}

int main()
{
    char encodeBytes[4] = {};
    std::size_t encodeWritten = 0u;
    const std::string combining = std::string("a") + scalar(0x0301u) + "b";
    assert(RinRuntime::utf8GraphemeNext(combining, 0u) ==
           combining.size() - 1u);
    assert(RinRuntime::utf8GraphemeNext(combining, combining.size() - 1u) ==
           combining.size());

    /* U+1A55 is a Unicode Mc spacing mark outside the former hand-written
     * C++ subset.  The public text model must follow libunicode's generated
     * property snapshot rather than silently splitting this cluster. */
    const std::string generatedSpacingMark =
        std::string("a") + scalar(0x1a55u) + "b";
    assert(RinRuntime::utf8GraphemeNext(generatedSpacingMark, 0u) ==
           generatedSpacingMark.size() - 1u);
    assert(RinRuntime::utf8GraphemeSpacingMark(0x1a55u));
    assert(RinRuntime::utf8GraphemeExtend(0x1e944u));
    assert(RinRuntime::utf8GraphemePrepend(0x1193fu));
    assert(RinRuntime::utf8GraphemeControl(0x061cu));
    assert(RinRuntime::utf8GraphemeRegionalIndicator(0x1f1fau));
    assert(RinRuntime::utf8GraphemeExtendedPictographic(0x00a9u));

    std::string zwj;
    appendScalar(zwj, 0x1f469u);
    appendScalar(zwj, 0x200du);
    appendScalar(zwj, 0x1f4bbu);
    zwj += "x";
    assert(RinRuntime::utf8GraphemeNext(zwj, 0u) == zwj.size() - 1u);

    std::string modifier;
    appendScalar(modifier, 0x1f44du);
    appendScalar(modifier, 0x1f3fdu);
    modifier += "!";
    assert(RinRuntime::utf8GraphemeNext(modifier, 0u) == modifier.size() - 1u);

    std::string flag;
    appendScalar(flag, 0x1f1fau);
    appendScalar(flag, 0x1f1f8u);
    appendScalar(flag, 0x1f1ef);
    const std::size_t flagPairBytes = scalar(0x1f1fau).size() * 2u;
    assert(RinRuntime::utf8GraphemeNext(flag, 0u) == flagPairBytes);
    assert(RinRuntime::utf8GraphemeNext(flag, flagPairBytes) == flag.size());

    const std::string crlf = "\r\nq";
    assert(RinRuntime::utf8GraphemeNext(crlf, 0u) == 2u);
    assert(RinRuntime::utf8GraphemeNext(crlf, 2u) == crlf.size());

    std::string hangul;
    appendScalar(hangul, 0x1100u);
    appendScalar(hangul, 0x1161u);
    appendScalar(hangul, 0x11a8u);
    hangul += "z";
    assert(RinRuntime::utf8GraphemeNext(hangul, 0u) == hangul.size() - 1u);
    assert(RinRuntime::utf8GraphemeHangulL(0x1100u));
    assert(RinRuntime::utf8GraphemeHangulV(0x1161u));
    assert(RinRuntime::utf8GraphemeHangulT(0x11a8u));
    assert(RinRuntime::utf8GraphemeHangulLV(0xac00u));
    assert(RinRuntime::utf8GraphemeHangulLVT(0xac01u));

    const std::string separate = std::string("A") + scalar(0x200du) + "B";
    assert(RinRuntime::utf8GraphemeNext(separate, 0u) ==
           1u + scalar(0x200du).size());

    encodeWritten = 99u;
    assert(!RinRuntime::utf8Encode(encodeBytes, 1u, 0x20acu,
                                   &encodeWritten));
    assert(encodeWritten == 0u);
    encodeWritten = 99u;
    assert(!RinRuntime::utf8Encode(nullptr, sizeof(encodeBytes), 'x',
                                   &encodeWritten));
    assert(encodeWritten == 0u);
    return 0;
}
