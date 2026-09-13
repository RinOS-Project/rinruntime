/* SPDX-License-Identifier: MIT */
/* Backend-independent selection and scrolling state for common widgets. */

#ifndef RINRUNTIME_CONTROLS_HPP
#define RINRUNTIME_CONTROLS_HPP

#include "accessibility.hpp"

namespace RinRuntime {

class IndexedSelection {
    int32_t count_;
    int32_t selected_;

public:
    IndexedSelection() : count_(0), selected_(-1) {}

    void setCount(int32_t count) {
        count_ = count < 0 ? 0 : count;
        if (selected_ >= count_) selected_ = -1;
    }

    int32_t count() const { return count_; }
    int32_t selected() const { return selected_; }
    bool hasSelection() const { return selected_ >= 0 && selected_ < count_; }

    bool select(int32_t index) {
        if (index < 0 || index >= count_) return false;
        if (selected_ == index) return false;
        selected_ = index;
        return true;
    }

    bool clear() {
        if (selected_ < 0) return false;
        selected_ = -1;
        return true;
    }

    bool selectFirst() { return count_ > 0 ? select(0) : false; }
    bool selectLast() { return count_ > 0 ? select(count_ - 1) : false; }

    bool move(int32_t delta, bool wrap = false) {
        int64_t requested;
        if (count_ <= 0 || delta == 0) return false;
        if (!hasSelection()) return delta < 0 ? selectLast() : selectFirst();
        requested = (int64_t)selected_ + delta;
        if (wrap) {
            requested %= count_;
            if (requested < 0) requested += count_;
        } else if (requested < 0) {
            requested = 0;
        } else if (requested >= count_) {
            requested = count_ - 1;
        }
        return select((int32_t)requested);
    }
};

class ScrollModel {
    int32_t contentExtent_;
    int32_t viewportExtent_;
    int32_t offset_;

    void clampOffset() {
        int32_t limit = maxOffset();
        if (offset_ < 0) offset_ = 0;
        else if (offset_ > limit) offset_ = limit;
    }

public:
    ScrollModel() : contentExtent_(0), viewportExtent_(0), offset_(0) {}

    void setExtents(int32_t contentExtent, int32_t viewportExtent) {
        contentExtent_ = contentExtent < 0 ? 0 : contentExtent;
        viewportExtent_ = viewportExtent < 0 ? 0 : viewportExtent;
        clampOffset();
    }

    int32_t contentExtent() const { return contentExtent_; }
    int32_t viewportExtent() const { return viewportExtent_; }
    int32_t offset() const { return offset_; }
    int32_t maxOffset() const {
        return contentExtent_ > viewportExtent_
                   ? contentExtent_ - viewportExtent_
                   : 0;
    }

    bool scrollTo(int32_t offset) {
        int32_t limit = maxOffset();
        int32_t next = offset < 0 ? 0 : (offset > limit ? limit : offset);
        if (next == offset_) return false;
        offset_ = next;
        return true;
    }

    bool scrollBy(int32_t delta) {
        int64_t requested = (int64_t)offset_ + delta;
        if (requested < 0) requested = 0;
        if (requested > maxOffset()) requested = maxOffset();
        return scrollTo((int32_t)requested);
    }

    bool reveal(int32_t start, int32_t extent) {
        int64_t end;
        if (start < 0 || extent < 0) return false;
        end = (int64_t)start + extent;
        if (end > INT32_MAX) return false;
        if (start < offset_) return scrollTo(start);
        if (end > (int64_t)offset_ + viewportExtent_)
            return scrollTo((int32_t)(end - viewportExtent_));
        return false;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_CONTROLS_HPP */
