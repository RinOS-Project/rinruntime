// SPDX-License-Identifier: MIT

#include <cassert>
#include <cstdint>
#include <string>

#include "../include/rinruntime/drag_drop.hpp"

int main()
{
    RinRuntime::DragDropSession session;
    const std::uint8_t text[] = {'o', 'k'};

    assert(!session.begin(0u, 1u, RinRuntime::DragDropAction::Copy));
    assert(session.begin(17u, 3u,
                         static_cast<RinRuntime::DragDropAction>(3u)));
    assert(session.addPayload("text/plain", "メモ", text, sizeof(text)));
    assert(session.addPayload("application/octet-stream", "", nullptr, 0u));
    assert(session.payloadCount() == 2u && session.totalBytes() == 2u);
    assert(session.payloadAt(0u) != nullptr &&
           session.payloadAt(0u)->label == "メモ");
    assert(session.payloadAt(2u) == nullptr);
    assert(!session.accept(RinRuntime::DragDropAction::Link));
    assert(session.accept(RinRuntime::DragDropAction::Move));
    assert(session.drop());
    assert(!session.active() && session.dropped());
    assert(!session.addPayload("text/plain", "", text, sizeof(text)));
    assert(!session.drop());

    session.reset();
    assert(session.begin(18u, 4u, RinRuntime::DragDropAction::Copy));
    assert(!session.addPayload("text/plain", "", nullptr, 1u));
    assert(!session.addPayload("text/plain", std::string("\xc0\x80"),
                               text, sizeof(text)));
    assert(!session.addPayload("text/plain/extra", "", text, sizeof(text)));
    assert(session.addPayload("text/plain", "", text, sizeof(text)));
    session.cancel();
    assert(session.cancelled() && session.payloadCount() == 0u);
    assert(!session.accept(RinRuntime::DragDropAction::Copy));
    return 0;
}
