/* SPDX-License-Identifier: MIT */
/* Backend-independent, bounded drag-and-drop offer model. */

#ifndef RINRUNTIME_DRAG_DROP_HPP
#define RINRUNTIME_DRAG_DROP_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace RinRuntime {

/* These values describe an application-level choice.  They are not a
 * capability or a filesystem permission; a private compositor/File Portal
 * adapter must authorize the resulting operation separately. */
enum class DragDropAction : std::uint8_t {
    None = 0u,
    Copy = 1u,
    Move = 2u,
    Link = 4u,
};

struct DragDropPayload final {
    std::string mimeType;
    std::string label;
    std::vector<std::uint8_t> bytes;

    bool valid() const;
};

/* A drag session owns only bounded MIME payloads and lifecycle state.  It
 * deliberately carries no pathname, descriptor, socket, process pointer,
 * compositor handle, or portal token.  A payload may contain an opaque token
 * defined by a separate public protocol, but this model never interprets it. */
class DragDropSession final {
public:
    static constexpr std::size_t kMaxPayloads = 32u;
    static constexpr std::size_t kMaxMimeTypeBytes = 127u;
    static constexpr std::size_t kMaxLabelBytes = 255u;
    static constexpr std::size_t kMaxPayloadBytes = 256u * 1024u;
    static constexpr std::size_t kMaxTotalBytes = 1024u * 1024u;

private:
    std::uint64_t sessionId_ = 0u;
    std::uint64_t generation_ = 0u;
    DragDropAction actions_ = DragDropAction::None;
    DragDropAction acceptedAction_ = DragDropAction::None;
    std::vector<DragDropPayload> payloads_;
    std::size_t totalBytes_ = 0u;
    bool active_ = false;
    bool dropped_ = false;
    bool cancelled_ = false;

    static bool utf8Valid(const std::string& value, std::size_t maximum);
    static bool mimeTypeValid(const std::string& value);
    static bool actionValid(DragDropAction action);
    static bool actionSingleBit(DragDropAction action);

    void clearPayloads();

public:
    DragDropSession() = default;

    /* Starts a fresh session.  A zero identity or an empty action set leaves
     * the session inactive and clears any prior offer. */
    bool begin(std::uint64_t sessionId, std::uint64_t generation,
               DragDropAction actions);

    /* Copies one caller-owned payload into the bounded session.  The bytes
     * remain private to this model and are never published on failure. */
    bool addPayload(const std::string& mimeType, const std::string& label,
                    const std::uint8_t* bytes, std::size_t size);

    /* Selects exactly one action offered by the source. */
    bool accept(DragDropAction action);

    /* Marks the offer delivered.  A drop is possible only after a valid
     * action was accepted and at least one payload was added. */
    bool drop();
    void cancel();
    void reset();

    std::uint64_t sessionId() const { return sessionId_; }
    std::uint64_t generation() const { return generation_; }
    DragDropAction actions() const { return actions_; }
    DragDropAction acceptedAction() const { return acceptedAction_; }
    std::size_t payloadCount() const { return payloads_.size(); }
    std::size_t totalBytes() const { return totalBytes_; }
    bool active() const { return active_; }
    bool dropped() const { return dropped_; }
    bool cancelled() const { return cancelled_; }

    const DragDropPayload* payloadAt(std::size_t index) const;
};

inline bool DragDropPayload::valid() const
{
    if (mimeType.size() > DragDropSession::kMaxMimeTypeBytes ||
        label.size() > DragDropSession::kMaxLabelBytes ||
        bytes.size() > DragDropSession::kMaxPayloadBytes)
        return false;
    if (mimeType.empty()) return false;
    for (unsigned char byte : mimeType) {
        if (byte < 0x21u || byte > 0x7eu) return false;
    }
    return true;
}

inline bool DragDropSession::utf8Valid(const std::string& value,
                                       std::size_t maximum)
{
    if (value.size() > maximum) return false;
    std::size_t index = 0u;
    while (index < value.size()) {
        const std::uint8_t lead = static_cast<std::uint8_t>(value[index]);
        std::size_t width = 0u;
        std::uint32_t codepoint = 0u;
        if (lead <= 0x7fu) {
            width = 1u;
            codepoint = lead;
        } else if (lead >= 0xc2u && lead <= 0xdfu) {
            width = 2u;
            codepoint = lead & 0x1fu;
        } else if (lead >= 0xe0u && lead <= 0xefu) {
            width = 3u;
            codepoint = lead & 0x0fu;
        } else if (lead >= 0xf0u && lead <= 0xf4u) {
            width = 4u;
            codepoint = lead & 0x07u;
        } else {
            return false;
        }
        if (width > value.size() - index) return false;
        for (std::size_t offset = 1u; offset < width; ++offset) {
            const std::uint8_t continuation =
                static_cast<std::uint8_t>(value[index + offset]);
            if ((continuation & 0xc0u) != 0x80u) return false;
            codepoint = (codepoint << 6u) | (continuation & 0x3fu);
        }
        if ((width == 2u && codepoint < 0x80u) ||
            (width == 3u && codepoint < 0x800u) ||
            (width == 4u && codepoint < 0x10000u) ||
            codepoint > 0x10ffffu ||
            (codepoint >= 0xd800u && codepoint <= 0xdfffu))
            return false;
        index += width;
    }
    return true;
}

inline bool DragDropSession::mimeTypeValid(const std::string& value)
{
    if (value.empty() || value.size() > kMaxMimeTypeBytes) return false;
    const std::size_t slash = value.find('/');
    if (slash == std::string::npos || slash == 0u ||
        slash + 1u >= value.size())
        return false;
    for (std::size_t index = 0u; index < value.size(); ++index) {
        const unsigned char byte = static_cast<unsigned char>(value[index]);
        if (byte < 0x21u || byte > 0x7eu || byte == ' ' || byte == '\\' ||
            byte == '"' || byte == '(' || byte == ')' || byte == ',' ||
            byte == ';' || byte == '<' || byte == '>' || byte == '@' ||
            byte == '[' || byte == ']' || byte == ':' || byte == '?')
            return false;
    }
    return value.find('/', slash + 1u) == std::string::npos;
}

inline bool DragDropSession::actionValid(DragDropAction action)
{
    const unsigned value = static_cast<unsigned>(action);
    return value != 0u && (value & ~7u) == 0u;
}

inline bool DragDropSession::actionSingleBit(DragDropAction action)
{
    const unsigned value = static_cast<unsigned>(action);
    return actionValid(action) && (value & (value - 1u)) == 0u;
}

inline void DragDropSession::clearPayloads()
{
    payloads_.clear();
    totalBytes_ = 0u;
}

inline bool DragDropSession::begin(std::uint64_t sessionId,
                                   std::uint64_t generation,
                                   DragDropAction actions)
{
    reset();
    if (sessionId == 0u || generation == 0u ||
        !actionValid(actions))
        return false;
    sessionId_ = sessionId;
    generation_ = generation;
    actions_ = actions;
    active_ = true;
    return true;
}

inline bool DragDropSession::addPayload(const std::string& mimeType,
                                        const std::string& label,
                                        const std::uint8_t* bytes,
                                        std::size_t size)
{
    if (!active_ || dropped_ || cancelled_ || payloads_.size() >= kMaxPayloads ||
        !mimeTypeValid(mimeType) || !utf8Valid(label, kMaxLabelBytes) ||
        (size != 0u && bytes == nullptr) || size > kMaxPayloadBytes ||
        size > kMaxTotalBytes - totalBytes_)
        return false;
    DragDropPayload candidate;
    candidate.mimeType = mimeType;
    candidate.label = label;
    if (size != 0u) candidate.bytes.assign(bytes, bytes + size);
    if (!candidate.valid()) return false;
    payloads_.push_back(std::move(candidate));
    totalBytes_ += size;
    return true;
}

inline bool DragDropSession::accept(DragDropAction action)
{
    if (!active_ || dropped_ || cancelled_ || !actionSingleBit(action) ||
        (static_cast<unsigned>(action) & static_cast<unsigned>(actions_)) == 0u)
        return false;
    acceptedAction_ = action;
    return true;
}

inline bool DragDropSession::drop()
{
    if (!active_ || dropped_ || cancelled_ || payloads_.empty() ||
        !actionSingleBit(acceptedAction_))
        return false;
    dropped_ = true;
    active_ = false;
    return true;
}

inline void DragDropSession::cancel()
{
    if (!active_ || dropped_) return;
    active_ = false;
    cancelled_ = true;
    acceptedAction_ = DragDropAction::None;
    clearPayloads();
}

inline void DragDropSession::reset()
{
    sessionId_ = 0u;
    generation_ = 0u;
    actions_ = DragDropAction::None;
    acceptedAction_ = DragDropAction::None;
    clearPayloads();
    active_ = false;
    dropped_ = false;
    cancelled_ = false;
}

inline const DragDropPayload* DragDropSession::payloadAt(
    std::size_t index) const
{
    if (index >= payloads_.size()) return nullptr;
    return &payloads_[index];
}

} // namespace RinRuntime

#endif /* RINRUNTIME_DRAG_DROP_HPP */
