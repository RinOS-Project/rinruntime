// SPDX-License-Identifier: MIT
// Backend-independent Widget input contract.
#pragma once

#include <cstdint>

namespace RinRuntime {

enum class EventType : std::uint8_t {
    None,
    MouseDown,
    MouseUp,
    MouseMove,
    MouseWheel,
    MouseHorizontalWheel,
    KeyDown,
    KeyUp,
    TextInput,
    /* An uncommitted IME preedit string. compositionText remains valid only
     * while the receiver handles this Event; TextInputModel copies it. */
    TextComposition,
    Paint,
    Close,
};

enum EventFlags : std::uint32_t {
    EVENT_FLAG_NONE = 0u,
    /* The event was translated from a platform key event.  Text widgets must
     * wait for its matching TextInput event instead of inserting a legacy
     * single-byte character on KeyDown. */
    EVENT_FLAG_NATIVE = 1u << 0u,
    EVENT_FLAG_KEY_REPEAT = 1u << 1u,
};

constexpr std::uint32_t EVENT_MODIFIER_SHIFT = 0x00000001u;
constexpr std::uint32_t EVENT_MODIFIER_CTRL = 0x00000002u;
constexpr std::uint32_t EVENT_MODIFIER_ALT = 0x00000004u;

struct Event {
    EventType type = EventType::None;
    std::int32_t x = 0;
    std::int32_t y = 0;
    std::int32_t wheelX = 0;
    std::int32_t wheelY = 0;
    std::uint32_t button = 0;
    std::uint32_t key = 0;
    std::uint32_t nativeScancode = 0;
    std::uint32_t codepoint = 0;
    std::uint32_t modifiers = 0;
    std::uint32_t flags = EVENT_FLAG_NONE;
    const char* compositionText = nullptr;
    std::uint32_t compositionSize = 0u;
    std::uint32_t compositionSelectionStart = 0u;
    std::uint32_t compositionSelectionEnd = 0u;
};

/* Convert a Set-1 scancode to the small virtual-key vocabulary used by the
 * common controls.  Printable input remains a separate TextInput event so
 * IME/layout processing is never bypassed. */
constexpr std::uint32_t virtualKeyFromSet1(std::uint32_t encodedScancode,
                                            std::uint32_t ascii) noexcept {
    const std::uint32_t scancode = encodedScancode & 0x7fu;
    if (ascii >= 0x20u && ascii <= 0x7eu) return ascii;
    switch (scancode) {
        case 0x01u: return 0x1bu; /* Escape */
        case 0x0eu: return 0x08u; /* Backspace */
        case 0x0fu: return 0x09u; /* Tab */
        case 0x1cu: return 0x0du; /* Enter */
        case 0x39u: return 0x20u; /* Space */
        case 0x47u: return 0x24u; /* Home */
        case 0x48u: return 0x26u; /* Up */
        case 0x49u: return 0x21u; /* Page up */
        case 0x4bu: return 0x25u; /* Left */
        case 0x4du: return 0x27u; /* Right */
        case 0x4fu: return 0x23u; /* End */
        case 0x50u: return 0x28u; /* Down */
        case 0x51u: return 0x22u; /* Page down */
        case 0x53u: return 0x2eu; /* Delete */
        case 0x3bu: return 0x70u; /* F1 */
        case 0x3cu: return 0x71u;
        case 0x3du: return 0x72u;
        case 0x3eu: return 0x73u;
        case 0x3fu: return 0x74u;
        case 0x40u: return 0x75u;
        case 0x41u: return 0x76u;
        case 0x42u: return 0x77u;
        case 0x43u: return 0x78u;
        case 0x44u: return 0x79u;
        case 0x57u: return 0x7au;
        case 0x58u: return 0x7bu;
        default: return 0u;
    }
}

constexpr bool isUnicodeScalar(std::uint32_t codepoint) noexcept {
    return codepoint <= 0x10ffffu &&
           !(codepoint >= 0xd800u && codepoint <= 0xdfffu);
}

} // namespace RinRuntime
