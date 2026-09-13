/* SPDX-License-Identifier: MIT */
/* Bounded, renderer-independent piece table for large text documents. */

#ifndef RINRUNTIME_PIECE_TABLE_HPP
#define RINRUNTIME_PIECE_TABLE_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace RinRuntime {

/*
 * PieceTable keeps the immutable source and append-only insertion buffers
 * separate from the piece index.  Mutations therefore do not copy the whole
 * document.  It deliberately models bytes rather than text semantics; a
 * UTF-8 editor validates inserted ranges before calling insert/erase.
 */
class PieceTable final {
public:
    static constexpr size_t kMaxBytes = 8u * 1024u * 1024u;
    static constexpr size_t kMaxPieces = 65536u;

    PieceTable() = default;

    explicit PieceTable(const std::string& original) { (void)setOriginal(original); }

    bool setOriginal(const std::string& original) {
        if (original.size() > kMaxBytes) return false;
        original_ = original;
        added_.clear();
        pieces_.clear();
        if (!original.empty()) pieces_.push_back({Source::Original, 0u,
                                                   original.size()});
        size_ = original.size();
        rebuildLineIndex();
        return true;
    }

    void clear() {
        original_.clear();
        added_.clear();
        pieces_.clear();
        size_ = 0u;
        lineStarts_.clear();
        lineStarts_.push_back(0u);
    }

    size_t size() const { return size_; }
    bool empty() const { return size_ == 0u; }
    size_t pieceCount() const { return pieces_.size(); }

    /* Insert bytes at a document boundary.  The added buffer is append-only,
     * so old pieces remain valid after later edits. */
    bool insert(size_t position, const std::string& value) {
        if (position > size_ || value.empty() ||
            value.size() > kMaxBytes - size_ || added_.size() > kMaxBytes - value.size())
            return false;
        if (pieces_.size() >= kMaxPieces && position != size_) return false;

        const size_t addedOffset = added_.size();
        added_.append(value);
        Piece inserted = {Source::Added, addedOffset, value.size()};
        std::vector<Piece> next;
        next.reserve(pieces_.size() + 2u);
        bool placed = false;
        size_t cursor = 0u;
        for (const Piece& piece : pieces_) {
            if (!placed && position <= cursor + piece.length) {
                const size_t local = position - cursor;
                if (local == 0u) {
                    next.push_back(inserted);
                    next.push_back(piece);
                    placed = true;
                } else if (local == piece.length) {
                    next.push_back(piece);
                    next.push_back(inserted);
                    placed = true;
                } else {
                    next.push_back({piece.source, piece.offset, local});
                    next.push_back(inserted);
                    next.push_back({piece.source, piece.offset + local,
                                    piece.length - local});
                    placed = true;
                }
            } else {
                next.push_back(piece);
            }
            cursor += piece.length;
        }
        if (!placed) {
            next.push_back(inserted);
            placed = true;
        }
        if (next.size() > kMaxPieces) {
            added_.resize(addedOffset);
            return false;
        }
        pieces_.swap(next);
        size_ += value.size();
        coalesce();
        rebuildLineIndex();
        return true;
    }

    bool erase(size_t position, size_t length) {
        if (position > size_ || length > size_ - position) return false;
        if (length == 0u) return true;
        const size_t end = position + length;
        std::vector<Piece> next;
        next.reserve(pieces_.size());
        size_t cursor = 0u;
        for (const Piece& piece : pieces_) {
            const size_t pieceEnd = cursor + piece.length;
            if (pieceEnd <= position || cursor >= end) {
                next.push_back(piece);
            } else {
                if (cursor < position)
                    next.push_back({piece.source, piece.offset,
                                    position - cursor});
                if (pieceEnd > end)
                    next.push_back({piece.source,
                                    piece.offset + (end - cursor),
                                    pieceEnd - end});
            }
            cursor = pieceEnd;
        }
        pieces_.swap(next);
        size_ -= length;
        coalesce();
        rebuildLineIndex();
        return true;
    }

    bool read(size_t position, size_t length, std::string& output) const {
        output.clear();
        if (position > size_ || length > size_ - position ||
            length > kMaxBytes) return false;
        output.reserve(length);
        if (length == 0u) return true;
        const size_t end = position + length;
        size_t cursor = 0u;
        for (const Piece& piece : pieces_) {
            const size_t pieceEnd = cursor + piece.length;
            if (pieceEnd <= position) {
                cursor = pieceEnd;
                continue;
            }
            if (cursor >= end) break;
            const size_t begin = position > cursor ? position - cursor : 0u;
            const size_t stop = end < pieceEnd ? end - cursor : piece.length;
            const std::string& source = piece.source == Source::Original
                ? original_ : added_;
            output.append(source, piece.offset + begin, stop - begin);
            cursor = pieceEnd;
        }
        return output.size() == length;
    }

    /* Locate one newline-delimited line without materializing the document.
     * The returned range includes a trailing CR when the source uses CRLF;
     * text adapters may remove that byte after reading the bounded line. */
    bool lineRange(size_t line, size_t& position, size_t& length) const {
        position = 0u;
        length = 0u;
        if (line >= lineStarts_.size()) return false;
        position = lineStarts_[line];
        const size_t next = line + 1u < lineStarts_.size()
            ? lineStarts_[line + 1u] - 1u : size_;
        if (next < position) return false;
        length = next - position;
        return true;
    }

    size_t lineCount() const {
        return lineStarts_.size();
    }

    std::string materialize() const {
        std::string output;
        if (!read(0u, size_, output)) output.clear();
        return output;
    }

private:
    enum class Source : uint8_t { Original, Added };
    struct Piece {
        Source source;
        size_t offset;
        size_t length;
    };

    static bool adjacent(const Piece& left, const Piece& right) {
        return left.source == right.source &&
               left.offset + left.length == right.offset;
    }

    void coalesce() {
        if (pieces_.size() < 2u) return;
        std::vector<Piece> merged;
        merged.reserve(pieces_.size());
        for (const Piece& piece : pieces_) {
            if (!merged.empty() && adjacent(merged.back(), piece))
                merged.back().length += piece.length;
            else
                merged.push_back(piece);
        }
        pieces_.swap(merged);
    }

    /* Keep line starts as a bounded, document-relative index.  Rebuilding
     * after each mutation is intentionally simple and failure-atomic: the
     * piece mutation has already succeeded, while readers thereafter avoid
     * rescanning every byte for each visible line. */
    void rebuildLineIndex() {
        std::vector<size_t> next;
        next.reserve(lineStarts_.size() > 0u ? lineStarts_.size() : 1u);
        next.push_back(0u);
        size_t documentPosition = 0u;
        for (const Piece& piece : pieces_) {
            const std::string& source = piece.source == Source::Original
                ? original_ : added_;
            for (size_t index = 0u; index < piece.length; ++index) {
                ++documentPosition;
                if (source[piece.offset + index] == '\n')
                    next.push_back(documentPosition);
            }
        }
        lineStarts_.swap(next);
    }

    std::string original_;
    std::string added_;
    std::vector<Piece> pieces_;
    std::vector<size_t> lineStarts_{0u};
    size_t size_ = 0u;
};

} // namespace RinRuntime

#endif /* RINRUNTIME_PIECE_TABLE_HPP */
