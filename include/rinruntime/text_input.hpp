/* SPDX-License-Identifier: MIT */
/* Backend-independent UTF-8 byte-range text editing model. */

#ifndef RINRUNTIME_TEXT_INPUT_HPP
#define RINRUNTIME_TEXT_INPUT_HPP

#include "event.hpp"
#include "accessibility.hpp"
#include "unicode.hpp"

namespace RinRuntime {

/*
 * This model deliberately exposes byte ranges, matching the current public
 * accessibility wire.  It guarantees scalar-valid insertion and never treats
 * a native printable KeyDown as committed text.  Cursor movement and erase
 * commands use LibUnicode extended grapheme boundaries, so a user-visible
 * character (including combining sequences, flags, and ZWJ emoji) is edited as
 * one unit.
 */
class TextInputModel {
    std::string text_;
    size_t cursor_ = 0u;
    size_t selectionStart_ = 0u;
    size_t selectionEnd_ = 0u;

    static bool isContinuationByte(unsigned char value) {
        return (value & 0xc0u) == 0x80u;
    }

    /* Public ranges are bytes for compatibility, but a text editing command
     * must never leave a cursor or an erase endpoint in a valid UTF-8 scalar. */
    static size_t previousBoundary(const std::string& value, size_t position) {
        if (position > value.length()) position = value.length();
        while (position > 0u && position < value.length() &&
               isContinuationByte(static_cast<unsigned char>(value[position]))) {
            --position;
        }
        return position;
    }

    static size_t previousScalarBoundary(const std::string& value,
                                         size_t position) {
        position = previousBoundary(value, position);
        return utf8GraphemePrev(value, position);
    }

    static size_t nextBoundary(const std::string& value, size_t position) {
        if (position >= value.length()) return value.length();
        position = previousBoundary(value, position);
        return utf8GraphemeNext(value, position);
    }

    static bool isGraphemeBoundary(const std::string& value, size_t position) {
        if (position == 0u || position == value.length()) return true;
        const size_t scalar = previousBoundary(value, position);
        if (scalar != position) return false;
        const size_t start = utf8GraphemePrev(value, position);
        return start < position &&
               utf8GraphemeNext(value, start) == position;
    }

    static size_t graphemeStartAtOrBefore(const std::string& value,
                                          size_t position) {
        if (position > value.length()) position = value.length();
        position = previousBoundary(value, position);
        if (isGraphemeBoundary(value, position)) return position;
        return utf8GraphemePrev(value, position);
    }

    static size_t graphemeEndAtOrAfter(const std::string& value,
                                       size_t position) {
        if (position > value.length()) position = value.length();
        const size_t scalar = previousBoundary(value, position);
        if (isGraphemeBoundary(value, position)) return position;
        size_t start = utf8GraphemePrev(value, scalar);
        if (utf8GraphemeNext(value, start) == scalar)
            start = scalar;
        return utf8GraphemeNext(value, start);
    }

    static bool validUtf8(const char* bytes, size_t length) {
        size_t index = 0u;
        if (!bytes && length != 0u) return false;
        while (index < length) {
            const unsigned char first = static_cast<unsigned char>(bytes[index]);
            size_t count = 0u;
            uint32_t codepoint = 0u;
            if (first <= 0x7fu) {
                count = 1u;
                codepoint = first;
            } else if (first >= 0xc2u && first <= 0xdfu) {
                count = 2u;
                codepoint = first & 0x1fu;
            } else if (first >= 0xe0u && first <= 0xefu) {
                count = 3u;
                codepoint = first & 0x0fu;
            } else if (first >= 0xf0u && first <= 0xf4u) {
                count = 4u;
                codepoint = first & 0x07u;
            } else {
                return false;
            }
            if (count > length - index) return false;
            for (size_t offset = 1u; offset < count; ++offset) {
                const unsigned char next =
                    static_cast<unsigned char>(bytes[index + offset]);
                if (!isContinuationByte(next)) return false;
                codepoint = (codepoint << 6u) | (next & 0x3fu);
            }
            if (!isUnicodeScalar(codepoint) ||
                (count == 2u && codepoint < 0x80u) ||
                (count == 3u && codepoint < 0x800u) ||
                (count == 4u && codepoint < 0x10000u))
                return false;
            index += count;
        }
        return true;
    }

    bool eraseSelection() {
        size_t start = selectionStart_ < selectionEnd_ ? selectionStart_ : selectionEnd_;
        size_t end = selectionStart_ < selectionEnd_ ? selectionEnd_ : selectionStart_;
        if (start == end) return false;
        text_.erase(start, end - start);
        cursor_ = start;
        selectionStart_ = start;
        selectionEnd_ = start;
        return true;
    }

    bool replaceRange(size_t start, size_t end, const std::string& value) {
        if (start > end || end > text_.length()) return false;
        text_.erase(start, end - start);
        text_.insert(start, value);
        cursor_ = start + value.length();
        selectionStart_ = cursor_;
        selectionEnd_ = cursor_;
        return true;
    }

    void moveCursor(size_t position, bool extendSelection) {
        position = previousBoundary(text_, position);
        if (extendSelection) selectionEnd_ = position;
        else selectionStart_ = selectionEnd_ = position;
        cursor_ = position;
    }

public:
    struct Composition {
        std::string text;
        AccessibilityTextRange selection;
        bool active = false;
    };

private:
    Composition composition_ = {};
    size_t compositionReplaceStart_ = 0u;
    size_t compositionReplaceEnd_ = 0u;

    void clearComposition() {
        composition_.text.clear();
        composition_.selection = {0u, 0u};
        composition_.active = false;
        compositionReplaceStart_ = cursor_;
        compositionReplaceEnd_ = cursor_;
    }

public:
    bool setText(const std::string& value) {
        if (!validUtf8(value.data(), value.length())) return false;
        text_ = value;
        cursor_ = text_.length();
        selectionStart_ = cursor_;
        selectionEnd_ = cursor_;
        clearComposition();
        return true;
    }
    const std::string& text() const { return text_; }
    size_t cursor() const { return cursor_; }
    AccessibilityTextRange selection() const {
        return {selectionStart_, selectionEnd_};
    }
    const Composition& composition() const { return composition_; }
    bool hasComposition() const { return composition_.active; }
    AccessibilityTextRange displayCompositionSelection() const {
        if (!composition_.active) return {0u, 0u};
        return {compositionReplaceStart_ + composition_.selection.start,
                compositionReplaceStart_ + composition_.selection.end};
    }

    /* The composition never mutates committed text until the IME commits it.
     * Repeated preedit updates retain the selection that was active at start. */
    bool setComposition(const char* value, size_t valueLength,
                        size_t selectionStart, size_t selectionEnd) {
        if (!value && valueLength != 0u) return false;
        std::string candidate(value ? value : "", valueLength);
        if (!validUtf8(value, valueLength) || selectionStart > valueLength ||
            selectionEnd > valueLength ||
            previousBoundary(candidate, selectionStart) != selectionStart ||
            previousBoundary(candidate, selectionEnd) != selectionEnd)
            return false;
        if (valueLength == 0u) {
            clearComposition();
            return true;
        }
        if (!composition_.active) {
            compositionReplaceStart_ = selectionStart_ < selectionEnd_
                ? selectionStart_ : selectionEnd_;
            compositionReplaceEnd_ = selectionStart_ < selectionEnd_
                ? selectionEnd_ : selectionStart_;
        }
        composition_.text.assign(value, valueLength);
        composition_.selection = {selectionStart, selectionEnd};
        composition_.active = true;
        return true;
    }
    bool setComposition(const std::string& value, size_t selectionStart,
                        size_t selectionEnd) {
        return setComposition(value.data(), value.length(), selectionStart,
                              selectionEnd);
    }
    void cancelComposition() { clearComposition(); }
    bool commitComposition() {
        bool result;
        if (!composition_.active) return false;
        result = replaceRange(compositionReplaceStart_, compositionReplaceEnd_,
                              composition_.text);
        clearComposition();
        return result;
    }
    std::string displayText() const {
        if (!composition_.active) return text_;
        std::string value = text_;
        value.erase(compositionReplaceStart_,
                    compositionReplaceEnd_ - compositionReplaceStart_);
        value.insert(compositionReplaceStart_, composition_.text);
        return value;
    }
    void setSelection(size_t start, size_t end) {
        size_t length = text_.length();
        selectionStart_ = start > length ? length : start;
        selectionEnd_ = end > length ? length : end;
        if (selectionStart_ == selectionEnd_) {
            selectionStart_ = previousBoundary(text_, selectionStart_);
            selectionEnd_ = selectionStart_;
        } else {
            const size_t lower = selectionStart_ < selectionEnd_ ?
                selectionStart_ : selectionEnd_;
            const size_t upper = selectionStart_ < selectionEnd_ ?
                selectionEnd_ : selectionStart_;
            const size_t scalarStart = graphemeStartAtOrBefore(text_, lower);
            const size_t scalarEnd = graphemeEndAtOrAfter(text_, upper);
            if (selectionStart_ < selectionEnd_) {
                selectionStart_ = scalarStart;
                selectionEnd_ = scalarEnd;
            } else {
                selectionStart_ = scalarEnd;
                selectionEnd_ = scalarStart;
            }
        }
        cursor_ = selectionEnd_;
        clearComposition();
    }
    void setCursor(size_t position) { setSelection(position, position); }

    bool insertUnicodeScalar(uint32_t codepoint) {
        char encoded[4];
        size_t byteCount;
        if (!isUnicodeScalar(codepoint)) return false;
        if (codepoint <= 0x7fu) {
            encoded[0] = static_cast<char>(codepoint); byteCount = 1u;
        } else if (codepoint <= 0x7ffu) {
            encoded[0] = static_cast<char>(0xc0u | (codepoint >> 6u));
            encoded[1] = static_cast<char>(0x80u | (codepoint & 0x3fu));
            byteCount = 2u;
        } else if (codepoint <= 0xffffu) {
            encoded[0] = static_cast<char>(0xe0u | (codepoint >> 12u));
            encoded[1] = static_cast<char>(0x80u | ((codepoint >> 6u) & 0x3fu));
            encoded[2] = static_cast<char>(0x80u | (codepoint & 0x3fu));
            byteCount = 3u;
        } else {
            encoded[0] = static_cast<char>(0xf0u | (codepoint >> 18u));
            encoded[1] = static_cast<char>(0x80u | ((codepoint >> 12u) & 0x3fu));
            encoded[2] = static_cast<char>(0x80u | ((codepoint >> 6u) & 0x3fu));
            encoded[3] = static_cast<char>(0x80u | (codepoint & 0x3fu));
            byteCount = 4u;
        }
        clearComposition();
        (void)eraseSelection();
        text_.insert(cursor_, encoded, byteCount);
        moveCursor(cursor_ + byteCount, false);
        return true;
    }

    bool handleEvent(const Event& event, bool focused, bool acceptsNewline) {
        if (!focused) return false;
        if (event.type == EventType::TextComposition)
            return setComposition(event.compositionText, event.compositionSize,
                                  event.compositionSelectionStart,
                                  event.compositionSelectionEnd);
        if (event.type == EventType::TextInput)
            return insertUnicodeScalar(event.codepoint);
        if (event.type != EventType::KeyDown) return false;
        clearComposition();
        const bool extendSelection =
            (event.modifiers & EVENT_MODIFIER_SHIFT) != 0u;
        if (event.key == 0x25u) {
            moveCursor(previousScalarBoundary(text_, cursor_), extendSelection);
            return true;
        }
        if (event.key == 0x27u) {
            moveCursor(nextBoundary(text_, cursor_), extendSelection);
            return true;
        }
        if (event.key == 0x24u) { moveCursor(0u, extendSelection); return true; }
        if (event.key == 0x23u) {
            moveCursor(text_.length(), extendSelection);
            return true;
        }
        if (event.key == 0x08u) {
            if (!eraseSelection() && cursor_ > 0u) {
                const size_t start = previousScalarBoundary(text_, cursor_);
                text_.erase(start, cursor_ - start);
                moveCursor(start, false);
            }
            return true;
        }
        if (event.key == 0x2eu) {
            if (!eraseSelection() && cursor_ < text_.length()) {
                const size_t end = nextBoundary(text_, cursor_);
                text_.erase(cursor_, end - cursor_);
            }
            return true;
        }
        if (event.key >= 0x20u && event.key <= 0x7eu &&
            (event.flags & EVENT_FLAG_NATIVE) == 0u)
            return insertUnicodeScalar(event.key);
        return event.key == 0x0du && acceptsNewline &&
               insertUnicodeScalar(static_cast<uint32_t>('\n'));
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_TEXT_INPUT_HPP */
