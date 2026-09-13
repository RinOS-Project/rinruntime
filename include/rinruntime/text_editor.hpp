/* SPDX-License-Identifier: MIT */
/* Backend-independent bounded UTF-8 text editor model. */

#ifndef RINRUNTIME_TEXT_EDITOR_HPP
#define RINRUNTIME_TEXT_EDITOR_HPP

#include <string>
#include "unicode.hpp"

namespace RinRuntime {

/*
 * TextEditorModel is the editing-oriented sibling of TextInputModel.  It
 * intentionally has no Event, Window, renderer, or document-format
 * dependency, so external toolkits and RinOS applications can share the same
 * cursor, selection, word-navigation, and erase semantics.  Offsets are
 * UTF-8 byte offsets and are always normalized to LibUnicode grapheme
 * boundaries before they are exposed or used for mutation.
 */
class TextEditorModel final {
    std::string text_;
    size_t cursor_ = 0u;
    size_t anchor_ = 0u;

    static bool continuation(unsigned char value) {
        return (value & 0xc0u) == 0x80u;
    }

    static size_t boundary(const std::string& text, size_t position) {
        if (position > text.size()) position = text.size();
        while (position > 0u && position < text.size() &&
               continuation(static_cast<unsigned char>(text[position]))) {
            --position;
        }
        return position;
    }

    static size_t previous(const std::string& text, size_t position) {
        return utf8GraphemePrev(text, boundary(text, position));
    }

    static size_t next(const std::string& text, size_t position) {
        return utf8GraphemeNext(text, boundary(text, position));
    }

    static bool isWordCluster(const std::string& text, size_t start,
                              size_t end) {
        if (start >= end || start >= text.size()) return false;
        const unsigned char first = static_cast<unsigned char>(text[start]);
        if (first < 0x80u) {
            return (first >= 'a' && first <= 'z') ||
                   (first >= 'A' && first <= 'Z') ||
                   (first >= '0' && first <= '9') || first == '_';
        }
        /* Keep non-ASCII grapheme clusters indivisible without introducing a
         * second locale-sensitive word-break table into every toolkit. */
        return true;
    }

    void move(size_t position, bool extend) {
        position = boundary(text_, position);
        if (!extend) {
            if (cursor_ != anchor_) {
                const size_t lower = cursor_ < anchor_ ? cursor_ : anchor_;
                const size_t upper = cursor_ < anchor_ ? anchor_ : cursor_;
                position = position <= lower ? lower : upper;
            }
            anchor_ = position;
        }
        cursor_ = position;
    }

    bool eraseRange(size_t start, size_t end) {
        if (start > end || end > text_.size()) return false;
        text_.erase(start, end - start);
        cursor_ = anchor_ = start;
        return true;
    }

public:
    /* Replace the whole document only after strict UTF-8 validation. */
    bool setText(const std::string& value) {
        size_t validPrefix = 0u;
        if (!rinruntime_utf8_validate(value.data(), value.size(),
                                      &validPrefix) ||
            validPrefix != value.size()) {
            return false;
        }
        text_ = value;
        cursor_ = anchor_ = text_.size();
        return true;
    }

    const std::string& text() const { return text_; }
    size_t cursor() const { return cursor_; }
    size_t anchor() const { return anchor_; }
    bool hasSelection() const { return cursor_ != anchor_; }
    size_t selectionStart() const {
        return cursor_ < anchor_ ? cursor_ : anchor_;
    }
    size_t selectionEnd() const {
        return cursor_ < anchor_ ? anchor_ : cursor_;
    }

    void selectAll() {
        anchor_ = 0u;
        cursor_ = text_.size();
    }

    void clearSelection() { anchor_ = cursor_; }

    void moveStart(bool extend) { move(0u, extend); }
    void moveEnd(bool extend) { move(text_.size(), extend); }

    void moveLeft(bool extend) {
        if (!extend && hasSelection()) {
            move(selectionStart(), false);
            return;
        }
        move(previous(text_, cursor_), extend);
    }

    void moveRight(bool extend) {
        if (!extend && hasSelection()) {
            move(selectionEnd(), false);
            return;
        }
        move(next(text_, cursor_), extend);
    }

    void moveWordLeft(bool extend) {
        size_t position = cursor_;
        if (!extend && hasSelection()) {
            move(selectionStart(), false);
            return;
        }
        while (position != 0u) {
            const size_t end = position;
            const size_t start = previous(text_, position);
            if (isWordCluster(text_, start, end)) break;
            position = start;
        }
        while (position != 0u) {
            const size_t end = position;
            const size_t start = previous(text_, position);
            if (!isWordCluster(text_, start, end)) break;
            position = start;
        }
        move(position, extend);
    }

    void moveWordRight(bool extend) {
        size_t position = cursor_;
        if (!extend && hasSelection()) {
            move(selectionEnd(), false);
            return;
        }
        while (position < text_.size()) {
            const size_t end = next(text_, position);
            if (isWordCluster(text_, position, end)) break;
            position = end;
        }
        while (position < text_.size()) {
            const size_t end = next(text_, position);
            if (!isWordCluster(text_, position, end)) break;
            position = end;
        }
        move(position, extend);
    }

    bool insertCodepoint(uint32_t codepoint) {
        char encoded[4] = {};
        size_t count = 0u;
        if (!utf8Encode(encoded, sizeof(encoded), codepoint, &count) ||
            count == 0u) {
            return false;
        }
        if (hasSelection() && !eraseRange(selectionStart(), selectionEnd())) {
            return false;
        }
        text_.insert(cursor_, encoded, count);
        cursor_ += count;
        anchor_ = cursor_;
        return true;
    }

    bool insertNewline() {
        return insertCodepoint(static_cast<uint32_t>('\n'));
    }

    bool backspace() {
        if (hasSelection()) return eraseRange(selectionStart(), selectionEnd());
        if (cursor_ == 0u) return false;
        const size_t start = previous(text_, cursor_);
        return eraseRange(start, cursor_);
    }

    bool eraseForward() {
        if (hasSelection()) return eraseRange(selectionStart(), selectionEnd());
        if (cursor_ >= text_.size()) return false;
        return eraseRange(cursor_, next(text_, cursor_));
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_TEXT_EDITOR_HPP */
