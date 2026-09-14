/* SPDX-License-Identifier: MIT */
/* C++ translation of the public window-event ABI. */
#pragma once

#include <cstdint>
#include <rin/gui/event_abi.h>
#include "event.hpp"

namespace RinRuntime {

struct WindowEvent {
    RinWindowEventV1 abi{};
    Event input{};

    bool isClose() const noexcept {
        return abi.type == RIN_WINDOW_EVENT_CLOSE;
    }
};

inline EventType windowEventType(uint32_t type, uint32_t native_data) noexcept {
    switch (type) {
        case RIN_WINDOW_EVENT_CLOSE: return EventType::Close;
        case RIN_WINDOW_EVENT_KEY_DOWN: return EventType::KeyDown;
        case RIN_WINDOW_EVENT_KEY_UP: return EventType::KeyUp;
        case RIN_WINDOW_EVENT_POINTER_MOVE: return EventType::MouseMove;
        case RIN_WINDOW_EVENT_POINTER_BUTTON:
            return (native_data & RIN_GUI_NATIVE_POINTER_ACTION_MASK) ==
                           RIN_GUI_NATIVE_POINTER_ACTION_UP
                       ? EventType::MouseUp
                       : EventType::MouseDown;
        case RIN_WINDOW_EVENT_SCROLL: return EventType::MouseWheel;
        case RIN_WINDOW_EVENT_HORIZONTAL_SCROLL:
            return EventType::MouseHorizontalWheel;
        case RIN_WINDOW_EVENT_TEXT_INPUT: return EventType::TextInput;
        case RIN_WINDOW_EVENT_TEXT_COMPOSITION:
            return EventType::TextComposition;
        default: return EventType::None;
    }
}

inline bool decodeWindowEvent(const RinWindowEventV1& abi,
                              WindowEvent* output) noexcept {
    if (!output || !rin_window_event_valid(&abi)) return false;
    output->abi = abi;
    output->input = Event{};
    output->input.type = windowEventType(abi.type, abi.native.data);
    output->input.x = abi.native.screen_x;
    output->input.y = abi.native.screen_y;
    output->input.wheelY = abi.type == RIN_WINDOW_EVENT_SCROLL
                               ? abi.native.wheel_delta
                               : 0;
    output->input.wheelX = abi.type == RIN_WINDOW_EVENT_HORIZONTAL_SCROLL
                               ? abi.native.wheel_delta
                               : 0;
    output->input.button = abi.native.data & RIN_GUI_NATIVE_POINTER_KNOWN_MASK;
    output->input.key = abi.native.data & RIN_GUI_NATIVE_KEY_DATA_MASK;
    output->input.nativeScancode = output->input.key;
    output->input.modifiers = abi.native.key_modifiers &
                              RIN_GUI_NATIVE_KEYMOD_KNOWN_MASK;
    output->input.flags = EVENT_FLAG_NATIVE;
    if ((abi.flags & RIN_WINDOW_EVENT_FLAG_KEY_REPEAT) != 0u)
        output->input.flags |= EVENT_FLAG_KEY_REPEAT;
    return true;
}

} // namespace RinRuntime
