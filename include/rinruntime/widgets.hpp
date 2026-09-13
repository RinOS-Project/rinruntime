/* SPDX-License-Identifier: MIT */
/*
 * Backend-independent common widgets.
 *
 * These classes intentionally contain state, input semantics and
 * Accessibility metadata only.  A renderer is free to derive from a model
 * and paint it using its own surface API; no RinOS window or graphics handle
 * is required.  RinApp's controls remain a rendering adapter around the same
 * public contract.
 */

#ifndef RINRUNTIME_WIDGETS_HPP
#define RINRUNTIME_WIDGETS_HPP

#include "controls.hpp"
#include "text_input.hpp"
#include "widget.hpp"
#include <functional>

namespace RinRuntime {

namespace widget_detail {
constexpr uint32_t kReturn = 0x0du;
constexpr uint32_t kSpace = 0x20u;
constexpr uint32_t kEscape = 0x1bu;
constexpr uint32_t kHome = 0x24u;
constexpr uint32_t kLeft = 0x25u;
constexpr uint32_t kUp = 0x26u;
constexpr uint32_t kRight = 0x27u;
constexpr uint32_t kDown = 0x28u;
constexpr uint32_t kEnd = 0x23u;

/* All public widget labels are eventually exposed through the Accessibility
 * tree.  Keep the admission rule identical to TextInputModel so a renderer
 * cannot retain bytes that the shared IPC/text contract would reject. */
inline bool validText(const std::string& value) {
    return strictUtf8TextValid(value);
}
}

class Button : public Widget {
    std::string text_;
    std::function<void()> onClick_;
    bool hovered_ = false;
    bool pressed_ = false;

public:
    explicit Button(const std::string& text = "") {
        (void)setText(text);
    }

    bool setText(const std::string& text) {
        if (!widget_detail::validText(text)) return false;
        text_ = text;
        return true;
    }
    const std::string& text() const { return text_; }
    void setOnClick(std::function<void()> callback) { onClick_ = callback; }
    bool isHovered() const { return hovered_; }
    bool isPressed() const { return pressed_; }

    AccessibilityRole accessibilityRole() const override {
        return AccessibilityRole::Button;
    }
    std::string accessibilityDefaultName() const override { return text_; }
    uint32_t accessibilityActions() const override {
        return ACCESSIBILITY_ACTION_ACTIVATE;
    }
    bool acceptsKeyboardFocus() const override { return true; }
    LayoutSize minimumLayoutSize() const override {
        return enforceControlTarget({88, 32});
    }

    bool handleEvent(const Event& event) override {
        if (!isVisible() || !isEnabled()) return false;
        if (event.type == EventType::MouseMove) {
            hovered_ = getBounds().contains(event.x, event.y);
            return false;
        }
        if (event.type == EventType::MouseDown &&
            getBounds().contains(event.x, event.y)) {
            hovered_ = true;
            pressed_ = true;
            return true;
        }
        if (event.type == EventType::MouseUp && pressed_) {
            pressed_ = false;
            if (getBounds().contains(event.x, event.y) && onClick_) onClick_();
            return true;
        }
        if (event.type == EventType::KeyDown && hasAccessibilityFocus() &&
            (event.key == widget_detail::kReturn ||
             event.key == widget_detail::kSpace)) {
            if (onClick_) onClick_();
            return true;
        }
        return false;
    }
};

class Label : public Widget {
    std::string text_;

public:
    explicit Label(const std::string& text = "") {
        (void)setText(text);
    }

    bool setText(const std::string& text) {
        if (!widget_detail::validText(text)) return false;
        text_ = text;
        return true;
    }
    const std::string& text() const { return text_; }

    AccessibilityRole accessibilityRole() const override {
        return AccessibilityRole::Label;
    }
    std::string accessibilityDefaultName() const override { return text_; }
    LayoutSize minimumLayoutSize() const override {
        return localizedTextMinimumLayoutSize(text_);
    }
};

class TextField : public Widget {
protected:
    TextInputModel input_;
    std::string placeholder_;

public:
    TextField() = default;

    bool setText(const std::string& text) { return input_.setText(text); }
    std::string text() const { return input_.text(); }
    bool setPlaceholder(const std::string& text) {
        if (!widget_detail::validText(text)) return false;
        placeholder_ = text;
        return true;
    }
    const std::string& placeholder() const { return placeholder_; }
    void setSelection(size_t start, size_t end) { input_.setSelection(start, end); }
    void setCursor(size_t position) { input_.setCursor(position); }
    bool setComposition(const std::string& value, size_t start, size_t end) {
        return input_.setComposition(value, start, end);
    }
    bool commitComposition() { return input_.commitComposition(); }
    void cancelComposition() { input_.cancelComposition(); }
    bool hasComposition() const { return input_.hasComposition(); }
    const TextInputModel::Composition& composition() const {
        return input_.composition();
    }
    /* Renderers need the same preedit projection that Accessibility clients
     * observe.  Exposing it here avoids adapters reaching into TextInputModel
     * internals or reimplementing composition rendering. */
    std::string displayText() const { return input_.displayText(); }
    AccessibilityTextRange displayCompositionSelection() const {
        return input_.displayCompositionSelection();
    }

    AccessibilityRole accessibilityRole() const override {
        return AccessibilityRole::TextField;
    }
    std::string accessibilityDefaultName() const override { return placeholder_; }
    std::string accessibilityValue() const override { return input_.text(); }
    uint32_t accessibilityActions() const override {
        return ACCESSIBILITY_ACTION_SET_VALUE;
    }
    bool acceptsKeyboardFocus() const override { return true; }
    bool isTextEditable() const override { return true; }
    bool setAccessibilityValue(const std::string& value) override {
        return input_.setText(value);
    }
    virtual bool acceptsNewline() const { return false; }
    AccessibilityTextRange accessibilityCursor() const override {
        return {input_.cursor(), input_.cursor()};
    }
    AccessibilityTextRange accessibilitySelection() const override {
        return input_.selection();
    }
    AccessibilityTextRange accessibilityEditableRange() const override {
        return {0u, input_.text().length()};
    }
    LayoutSize minimumLayoutSize() const override {
        return enforceControlTarget({120, 32});
    }

    bool handleEvent(const Event& event) override {
        if (!isVisible() || !isEnabled()) return false;
        if (event.type == EventType::MouseDown)
            return getBounds().contains(event.x, event.y);
        return input_.handleEvent(event, hasAccessibilityFocus(),
                                  acceptsNewline());
    }

    /* Renderer adapters that specialize TextField (for example TextArea)
     * can retain the shared model while selecting the newline policy through
     * their own virtual contract. */
    bool handleEventWithNewline(const Event& event, bool allowNewline) {
        if (!isVisible() || !isEnabled()) return false;
        if (event.type == EventType::MouseDown)
            return getBounds().contains(event.x, event.y);
        return input_.handleEvent(event, hasAccessibilityFocus(), allowNewline);
    }
};

class TextArea : public TextField {
public:
    AccessibilityRole accessibilityRole() const override {
        return AccessibilityRole::TextArea;
    }
    LayoutSize minimumLayoutSize() const override {
        return enforceControlTarget({120, 80});
    }
    bool acceptsNewline() const override { return true; }
};

class CheckBox : public Widget {
    std::string label_;
    bool checked_ = false;
    std::function<void(bool)> onChange_;

public:
    explicit CheckBox(const std::string& label = "") {
        (void)setLabel(label);
    }

    bool setLabel(const std::string& label) {
        if (!widget_detail::validText(label)) return false;
        label_ = label;
        return true;
    }
    const std::string& label() const { return label_; }
    void setChecked(bool checked) { checked_ = checked; }
    bool isChecked() const { return checked_; }
    void setOnChange(std::function<void(bool)> callback) { onChange_ = callback; }

    AccessibilityRole accessibilityRole() const override {
        return AccessibilityRole::CheckBox;
    }
    std::string accessibilityDefaultName() const override { return label_; }
    std::string accessibilityValue() const override {
        return checked_ ? "true" : "false";
    }
    uint32_t accessibilityExtraState() const override {
        return checked_ ? ACCESSIBILITY_STATE_CHECKED : 0u;
    }
    uint32_t accessibilityActions() const override {
        return ACCESSIBILITY_ACTION_ACTIVATE;
    }
    bool acceptsKeyboardFocus() const override { return true; }
    LayoutSize minimumLayoutSize() const override {
        LayoutSize minimum = localizedTextMinimumLayoutSize(label_, 32);
        minimum.width += 24;
        return enforceControlTarget(minimum);
    }

    bool toggle() {
        if (!isEnabled()) return false;
        checked_ = !checked_;
        if (onChange_) onChange_(checked_);
        return true;
    }

    bool handleEvent(const Event& event) override {
        if (!isVisible() || !isEnabled()) return false;
        if (event.type == EventType::MouseDown &&
            getBounds().contains(event.x, event.y)) return toggle();
        if (event.type == EventType::KeyDown && hasAccessibilityFocus() &&
            (event.key == widget_detail::kReturn ||
             event.key == widget_detail::kSpace)) return toggle();
        return false;
    }
};

class Slider : public Widget {
    int32_t value_ = 50;
    int32_t minValue_ = 0;
    int32_t maxValue_ = 100;
    bool dragging_ = false;
    std::function<void(int32_t)> onChange_;

    void notifyIfChanged(int32_t oldValue) {
        if (value_ != oldValue && onChange_) onChange_(value_);
    }

public:
    Slider() = default;

    void setValue(int32_t value) {
        if (value < minValue_) value = minValue_;
        if (value > maxValue_) value = maxValue_;
        value_ = value;
    }
    int32_t value() const { return value_; }
    void setRange(int32_t minimum, int32_t maximum) {
        if (maximum < minimum) maximum = minimum;
        minValue_ = minimum;
        maxValue_ = maximum;
        setValue(value_);
    }
    int32_t minimumValue() const { return minValue_; }
    int32_t maximumValue() const { return maxValue_; }
    void setOnChange(std::function<void(int32_t)> callback) { onChange_ = callback; }
    bool isDragging() const { return dragging_; }

    AccessibilityRole accessibilityRole() const override {
        return AccessibilityRole::Slider;
    }
    std::string accessibilityValue() const override {
        return std::to_string((int)value_);
    }
    uint32_t accessibilityActions() const override {
        return ACCESSIBILITY_ACTION_SET_VALUE | ACCESSIBILITY_ACTION_INCREMENT |
               ACCESSIBILITY_ACTION_DECREMENT;
    }
    bool acceptsKeyboardFocus() const override { return true; }
    LayoutSize minimumLayoutSize() const override {
        return enforceControlTarget({120, 32});
    }

    bool setValueFromPosition(int32_t x) {
        Rect rect = getBounds();
        if (rect.w <= 0 || maxValue_ <= minValue_) return false;
        int32_t position = x - rect.x;
        if (position < 0) position = 0;
        if (position > rect.w) position = rect.w;
        int32_t oldValue = value_;
        value_ = minValue_ + (int64_t)position * (maxValue_ - minValue_) / rect.w;
        notifyIfChanged(oldValue);
        return value_ != oldValue;
    }

    bool handleEvent(const Event& event) override {
        if (!isVisible() || !isEnabled()) return false;
        if (event.type == EventType::MouseDown &&
            getBounds().contains(event.x, event.y)) {
            dragging_ = true;
            setValueFromPosition(event.x);
            return true;
        }
        if (event.type == EventType::MouseUp) {
            bool wasDragging = dragging_;
            dragging_ = false;
            return wasDragging;
        }
        if (event.type == EventType::MouseMove && dragging_) {
            setValueFromPosition(event.x);
            return true;
        }
        if (event.type == EventType::KeyDown && hasAccessibilityFocus()) {
            int32_t oldValue = value_;
            if (event.key == widget_detail::kLeft || event.key == widget_detail::kDown)
                setValue(value_ - 1);
            else if (event.key == widget_detail::kRight || event.key == widget_detail::kUp)
                setValue(value_ + 1);
            else
                return false;
            notifyIfChanged(oldValue);
            return true;
        }
        return false;
    }
};

class ProgressBar : public Widget {
    int32_t value_ = 0;
    bool showText_ = true;

public:
    ProgressBar() = default;
    void setValue(int32_t value) {
        value_ = value < 0 ? 0 : (value > 100 ? 100 : value);
    }
    int32_t value() const { return value_; }
    void setShowText(bool value) { showText_ = value; }
    bool showText() const { return showText_; }

    AccessibilityRole accessibilityRole() const override {
        return AccessibilityRole::ProgressBar;
    }
    std::string accessibilityValue() const override {
        return std::to_string((int)value_) + "%";
    }
    LayoutSize minimumLayoutSize() const override {
        return enforceControlTarget({120, 20});
    }
};

/* Modal dialog state is a model, not a renderer.  A toolkit can derive from
 * this class and paint the title/content using its own surface API while
 * retaining the same accessibility and keyboard semantics. */
class Dialog : public Widget {
    std::string title_;
    bool open_ = false;
    bool modal_ = true;
    std::function<void()> defaultAction_;
    std::function<void()> cancelAction_;

public:
    explicit Dialog(const std::string& title = "", bool modal = true)
        : modal_(modal) {
        (void)setTitle(title);
        setVisible(false);
    }

    bool setTitle(const std::string& title) {
        if (!widget_detail::validText(title)) return false;
        title_ = title;
        return true;
    }
    const std::string& title() const { return title_; }
    void setModal(bool modal) { modal_ = modal; }
    bool isModal() const { return modal_; }
    bool isOpen() const { return open_; }

    void show() {
        open_ = true;
        setVisible(true);
    }
    void dismiss() {
        open_ = false;
        setVisible(false);
    }
    void setDefaultAction(std::function<void()> action) {
        defaultAction_ = std::move(action);
    }
    void setCancelAction(std::function<void()> action) {
        cancelAction_ = std::move(action);
    }

    AccessibilityRole accessibilityRole() const override {
        return AccessibilityRole::Dialog;
    }
    std::string accessibilityDefaultName() const override { return title_; }
    uint32_t accessibilityExtraState() const override {
        return modal_ ? ACCESSIBILITY_STATE_MODAL : 0u;
    }
    uint32_t accessibilityActions() const override {
        return ACCESSIBILITY_ACTION_DISMISS;
    }
    bool acceptsKeyboardFocus() const override { return open_; }
    LayoutSize minimumLayoutSize() const override {
        return enforceControlTarget({240, 120});
    }

    bool handleEvent(const Event& event) override {
        if (!open_ || event.type != EventType::KeyDown) return false;
        if (event.key == widget_detail::kEscape) {
            if (cancelAction_) cancelAction_();
            else dismiss();
            return true;
        }
        if (event.key == widget_detail::kReturn) {
            if (defaultAction_) defaultAction_();
            return true;
        }
        return false;
    }
};

/* Selection and scrolling semantics for a list are portable as well.  The
 * renderer only needs to read items(), selectedIndex(), and scrollOffset(). */
class List : public Widget {
    static constexpr size_t kMaxItems = 4096u;
    static constexpr size_t kMaxItemBytes = 4096u;
    std::vector<std::string> items_;
    IndexedSelection selection_;
    ScrollModel scroll_;
    int32_t rowHeight_ = 32;
    std::function<void(int32_t)> onSelect_;

    int32_t visibleRows() const {
        return rowHeight_ > 0 && bounds.h > 0 ? bounds.h / rowHeight_ : 0;
    }
    void syncModels() {
        const size_t maxCount = static_cast<size_t>(0x7fffffff);
        const int32_t count = items_.size() > maxCount
            ? static_cast<int32_t>(0x7fffffff)
            : static_cast<int32_t>(items_.size());
        selection_.setCount(count);
        scroll_.setExtents(count, visibleRows());
    }
    void revealSelected() {
        if (selection_.hasSelection())
            (void)scroll_.reveal(selection_.selected(), 1);
    }
    bool selectIndex(int32_t index, bool notify) {
        if (!selection_.select(index)) return false;
        revealSelected();
        if (notify && onSelect_) onSelect_(index);
        return true;
    }
    static bool validItem(const std::string& value) {
        if (value.size() > kMaxItemBytes) return false;
        TextInputModel validator;
        return validator.setText(value);
    }

public:
    void setItems(const std::vector<std::string>& values) {
        if (values.size() > kMaxItems) {
            clear();
            return;
        }
        for (const auto& value : values) {
            if (!validItem(value)) {
                clear();
                return;
            }
        }
        items_ = values;
        syncModels();
    }
    void addItem(const std::string& value) {
        if (items_.size() >= kMaxItems || !validItem(value)) return;
        items_.push_back(value);
        syncModels();
    }
    void clear() {
        items_.clear();
        selection_.setCount(0);
        scroll_.setExtents(0, 0);
    }
    const std::vector<std::string>& items() const { return items_; }
    void setOnSelect(std::function<void(int32_t)> callback) {
        onSelect_ = std::move(callback);
    }
    int32_t selectedIndex() const { return selection_.selected(); }
    const std::string* selectedItem() const {
        int32_t index = selection_.selected();
        return index >= 0 && index < static_cast<int32_t>(items_.size())
            ? &items_[index] : nullptr;
    }
    bool setSelectedIndex(int32_t index) {
        syncModels();
        return selectIndex(index, false);
    }
    void setRowHeight(int32_t value) {
        if (value >= 16) {
            rowHeight_ = value;
            syncModels();
        }
    }
    int32_t rowHeight() const { return rowHeight_; }
    int32_t scrollOffset() const { return scroll_.offset(); }
    int32_t maxScrollOffset() const { return scroll_.maxOffset(); }

    AccessibilityRole accessibilityRole() const override {
        return AccessibilityRole::List;
    }
    std::string accessibilityValue() const override {
        const std::string* value = selectedItem();
        return value ? *value : "";
    }
    uint32_t accessibilityExtraState() const override {
        return selection_.hasSelection() ? ACCESSIBILITY_STATE_SELECTED : 0u;
    }
    uint32_t accessibilityActions() const override {
        return ACCESSIBILITY_ACTION_SELECT |
               ACCESSIBILITY_ACTION_SCROLL_FORWARD |
               ACCESSIBILITY_ACTION_SCROLL_BACKWARD;
    }
    bool acceptsKeyboardFocus() const override { return true; }
    LayoutSize minimumLayoutSize() const override {
        return enforceControlTarget({160, 96});
    }

    bool handleEvent(const Event& event) override {
        syncModels();
        if (event.type == EventType::MouseDown &&
            bounds.contains(event.x, event.y)) {
            int32_t index = scroll_.offset() +
                (event.y - bounds.y) / rowHeight_;
            bool changed = selectIndex(index, true);
            // A valid row click is consumed even when it repeats the current
            // selection; callers must not route it to an underlying widget.
            return changed || (index >= 0 &&
                               index < selection_.count());
        }
        if (event.type != EventType::KeyDown || !hasAccessibilityFocus())
            return false;
        if (event.key == widget_detail::kReturn) {
            if (selection_.hasSelection() && onSelect_)
                onSelect_(selection_.selected());
            return selection_.hasSelection();
        }
        bool changed = false;
        if (event.key == widget_detail::kUp) changed = selection_.move(-1);
        else if (event.key == widget_detail::kDown) changed = selection_.move(1);
        else if (event.key == widget_detail::kHome) changed = selection_.selectFirst();
        else if (event.key == widget_detail::kEnd) changed = selection_.selectLast();
        else if (event.key == 0x21u) changed = selection_.move(-visibleRows());
        else if (event.key == 0x22u) changed = selection_.move(visibleRows());
        else return false;
        revealSelected();
        if (changed && onSelect_) onSelect_(selection_.selected());
        return true;
    }
};

/* Viewport state is portable; drawing the clipped content remains a toolkit
 * concern.  ScrollView exposes the same bounded offsets to any renderer. */
class ScrollView : public Widget {
    ScrollModel horizontal_;
    ScrollModel vertical_;
    int32_t contentWidth_ = 0;
    int32_t contentHeight_ = 0;

    void syncModels() {
        horizontal_.setExtents(contentWidth_, bounds.w);
        vertical_.setExtents(contentHeight_, bounds.h);
    }
    bool scrollBy(int32_t x, int32_t y) {
        /* Evaluate both axes even when the first one changes.  Short-circuit
         * evaluation here used to leave the vertical offset stale whenever a
         * diagonal/page operation moved horizontally first. */
        const bool horizontalChanged = horizontal_.scrollBy(x);
        const bool verticalChanged = vertical_.scrollBy(y);
        return horizontalChanged || verticalChanged;
    }

public:
    void setContentExtent(int32_t width, int32_t height) {
        contentWidth_ = width < 0 ? 0 : width;
        contentHeight_ = height < 0 ? 0 : height;
        syncModels();
    }
    int32_t contentWidth() const { return contentWidth_; }
    int32_t contentHeight() const { return contentHeight_; }
    int32_t horizontalOffset() const { return horizontal_.offset(); }
    int32_t verticalOffset() const { return vertical_.offset(); }
    bool scrollTo(int32_t x, int32_t y) {
        syncModels();
        const bool horizontalChanged = horizontal_.scrollTo(x);
        const bool verticalChanged = vertical_.scrollTo(y);
        return horizontalChanged || verticalChanged;
    }

    AccessibilityRole accessibilityRole() const override {
        return AccessibilityRole::ScrollView;
    }
    std::string accessibilityValue() const override {
        return std::to_string(horizontal_.offset()) + "," +
               std::to_string(vertical_.offset());
    }
    uint32_t accessibilityActions() const override {
        return ACCESSIBILITY_ACTION_SCROLL_FORWARD |
               ACCESSIBILITY_ACTION_SCROLL_BACKWARD;
    }
    bool acceptsKeyboardFocus() const override { return true; }
    LayoutSize minimumLayoutSize() const override {
        return enforceControlTarget({96, 96});
    }

    bool handleEvent(const Event& event) override {
        syncModels();
        if ((event.type == EventType::MouseWheel ||
             event.type == EventType::MouseHorizontalWheel) &&
            getBounds().contains(event.x, event.y)) {
            int32_t x = event.type == EventType::MouseHorizontalWheel
                            ? -event.wheelX * 32 : 0;
            int32_t y = event.type == EventType::MouseWheel
                            ? -event.wheelY * 32 : 0;
            (void)scrollBy(x, y);
            return true;
        }
        if (event.type != EventType::KeyDown || !hasAccessibilityFocus())
            return false;
        const int32_t page = bounds.h > 0 ? bounds.h : 1;
        if (event.key == widget_detail::kLeft) {
            (void)scrollBy(-32, 0);
            return true;
        }
        if (event.key == widget_detail::kRight) {
            (void)scrollBy(32, 0);
            return true;
        }
        if (event.key == widget_detail::kUp) {
            (void)scrollBy(0, -32);
            return true;
        }
        if (event.key == widget_detail::kDown) {
            (void)scrollBy(0, 32);
            return true;
        }
        if (event.key == 0x21u) {
            (void)scrollBy(0, -page);
            return true;
        }
        if (event.key == 0x22u) {
            (void)scrollBy(0, page);
            return true;
        }
        if (event.key == widget_detail::kHome) {
            (void)scrollTo(0, 0);
            return true;
        }
        if (event.key == widget_detail::kEnd) {
            (void)scrollTo(horizontal_.maxOffset(), vertical_.maxOffset());
            return true;
        }
        return false;
    }
};

/* Table keeps column/row interaction state independent from cell painting.
 * A renderer can obtain the immutable column descriptors and draw cell values
 * from its own data source while sharing selection and sort semantics. */
class Table : public Widget {
public:
    struct Column {
        std::string header;
        int32_t width = 96;
        bool sortable = false;
        std::function<std::string(int32_t)> valueAt;

        Column() = default;
        Column(const std::string& value, int32_t columnWidth,
               bool canSort = false)
            : header(value), width(columnWidth), sortable(canSort) {}
    };

private:
    static constexpr size_t kMaxColumns = 64u;
    static constexpr int32_t kMaxRows = 1 << 20;
    std::vector<Column> columns_;
    int32_t rowCount_ = 0;
    int32_t headerHeight_ = 32;
    int32_t rowHeight_ = 32;
    IndexedSelection selection_;
    ScrollModel scroll_;
    int32_t sortColumn_ = -1;
    bool sortAscending_ = true;
    std::function<void(int32_t)> onSelect_;
    std::function<void(int32_t, bool)> onSort_;

    int32_t visibleRows() const {
        int32_t available = bounds.h > headerHeight_ ? bounds.h - headerHeight_ : 0;
        return rowHeight_ > 0 ? available / rowHeight_ : 0;
    }
    void syncModels() {
        selection_.setCount(rowCount_);
        scroll_.setExtents(rowCount_, visibleRows());
    }
    bool validColumn(const Column& column) const {
        if (column.width < 32 || column.width > 16384 ||
            column.header.size() > 4096u)
            return false;
        TextInputModel validator;
        return validator.setText(column.header);
    }

public:
    bool addColumn(const Column& column) {
        if (columns_.size() >= kMaxColumns || !validColumn(column)) return false;
        columns_.push_back(column);
        return true;
    }
    const std::vector<Column>& columns() const { return columns_; }
    std::vector<Column>& columns() { return columns_; }
    bool setColumnValue(int32_t index,
                        std::function<std::string(int32_t)> callback) {
        if (index < 0 || index >= static_cast<int32_t>(columns_.size()))
            return false;
        columns_[index].valueAt = std::move(callback);
        return true;
    }
    void setRowCount(int32_t count) {
        rowCount_ = count < 0 ? 0 : (count > kMaxRows ? kMaxRows : count);
        syncModels();
    }
    int32_t rowCount() const { return rowCount_; }
    int32_t headerHeight() const { return headerHeight_; }
    int32_t rowHeight() const { return rowHeight_; }
    int32_t scrollOffset() const { return scroll_.offset(); }
    int32_t maxScrollOffset() const { return scroll_.maxOffset(); }
    void updateLayout() { syncModels(); }
    void setOnSelect(std::function<void(int32_t)> callback) {
        onSelect_ = std::move(callback);
    }
    void setOnSort(std::function<void(int32_t, bool)> callback) {
        onSort_ = std::move(callback);
    }
    int32_t selectedRow() const { return selection_.selected(); }
    int32_t sortedColumn() const { return sortColumn_; }
    bool ascending() const { return sortAscending_; }
    bool sortBy(int32_t column) {
        if (column < 0 || column >= (int32_t)columns_.size() ||
            !columns_[column].sortable)
            return false;
        if (sortColumn_ == column) sortAscending_ = !sortAscending_;
        else {
            sortColumn_ = column;
            sortAscending_ = true;
        }
        if (onSort_) onSort_(sortColumn_, sortAscending_);
        return true;
    }

    AccessibilityRole accessibilityRole() const override {
        return AccessibilityRole::Table;
    }
    std::string accessibilityValue() const override {
        return std::to_string(selection_.selected());
    }
    uint32_t accessibilityExtraState() const override {
        return selection_.hasSelection() ? ACCESSIBILITY_STATE_SELECTED : 0u;
    }
    uint32_t accessibilityActions() const override {
        return ACCESSIBILITY_ACTION_SELECT |
               ACCESSIBILITY_ACTION_SCROLL_FORWARD |
               ACCESSIBILITY_ACTION_SCROLL_BACKWARD;
    }
    bool acceptsKeyboardFocus() const override { return true; }
    LayoutSize minimumLayoutSize() const override {
        return enforceControlTarget({240, 128});
    }

    bool handleEvent(const Event& event) override {
        syncModels();
        if (event.type == EventType::MouseDown &&
            getBounds().contains(event.x, event.y)) {
            if (event.y < bounds.y + headerHeight_) {
                int32_t x = bounds.x;
                for (int32_t index = 0; index < (int32_t)columns_.size(); ++index) {
                    if (event.x >= x && event.x < x + columns_[index].width) {
                        (void)sortBy(index);
                        return true;
                    }
                    x += columns_[index].width;
                }
                return true;
            }
            int32_t row = scroll_.offset() +
                (event.y - bounds.y - headerHeight_) / rowHeight_;
            bool changed = selection_.select(row);
            if (changed) {
                (void)scroll_.reveal(row, 1);
                if (onSelect_) onSelect_(row);
            }
            return changed || (row >= 0 && row < rowCount_);
        }
        if (event.type != EventType::KeyDown || !hasAccessibilityFocus())
            return false;
        bool changed = false;
        if (event.key == widget_detail::kUp) changed = selection_.move(-1);
        else if (event.key == widget_detail::kDown) changed = selection_.move(1);
        else if (event.key == widget_detail::kHome) changed = selection_.selectFirst();
        else if (event.key == widget_detail::kEnd) changed = selection_.selectLast();
        else if (event.key == 0x21u) changed = selection_.move(-visibleRows());
        else if (event.key == 0x22u) changed = selection_.move(visibleRows());
        else return false;
        if (selection_.hasSelection()) (void)scroll_.reveal(selection_.selected(), 1);
        if (changed && onSelect_) onSelect_(selection_.selected());
        return true;
    }
};

struct TreeItem {
    uint64_t id = 0u;
    std::string label;
    bool expanded = false;
    std::vector<TreeItem> children;
};

/* Hierarchy and navigation state are portable; indentation and glyphs remain
 * renderer policy.  IDs are stable until the tree is destroyed. */
class Tree : public Widget {
    struct VisibleItem {
        TreeItem* item;
        int32_t depth;
    };

    static constexpr size_t kMaxItems = 4096u;
    static constexpr size_t kMaxLabelBytes = 4096u;
    std::vector<TreeItem> roots_;
    uint64_t nextId_ = 1u;
    uint64_t selectedId_ = 0u;
    ScrollModel scroll_;
    int32_t rowHeight_ = 32;
    std::function<void(uint64_t)> onSelect_;

    static bool validLabel(const std::string& label) {
        if (label.size() > kMaxLabelBytes) return false;
        TextInputModel validator;
        return validator.setText(label);
    }
    static TreeItem* findIn(std::vector<TreeItem>& values, uint64_t id) {
        for (auto& value : values) {
            if (value.id == id) return &value;
            TreeItem* nested = findIn(value.children, id);
            if (nested) return nested;
        }
        return nullptr;
    }
    static const TreeItem* findIn(const std::vector<TreeItem>& values,
                                  uint64_t id) {
        for (const auto& value : values) {
            if (value.id == id) return &value;
            const TreeItem* nested = findIn(value.children, id);
            if (nested) return nested;
        }
        return nullptr;
    }
    static uint64_t parentOf(const std::vector<TreeItem>& values, uint64_t id,
                             uint64_t parent = 0u) {
        for (const auto& value : values) {
            if (value.id == id) return parent;
            uint64_t nested = parentOf(value.children, id, value.id);
            if (nested != 0u) return nested;
        }
        return 0u;
    }
    static void appendVisible(std::vector<TreeItem>& values, int32_t depth,
                              std::vector<VisibleItem>& output) {
        for (auto& value : values) {
            output.push_back({&value, depth});
            if (value.expanded) appendVisible(value.children, depth + 1, output);
        }
    }
    void visible(std::vector<VisibleItem>& output) {
        output.clear();
        appendVisible(roots_, 0, output);
    }
    int32_t visibleRows() const {
        return rowHeight_ > 0 && bounds.h > 0 ? bounds.h / rowHeight_ : 0;
    }
    void syncScroll(size_t itemCount) {
        const int32_t count = itemCount > static_cast<size_t>(0x7fffffff)
            ? 0x7fffffff : static_cast<int32_t>(itemCount);
        scroll_.setExtents(count, visibleRows());
    }
    bool selectId(uint64_t id) {
        if (id == 0u || id == selectedId_ || !findIn(roots_, id)) return false;
        selectedId_ = id;
        if (onSelect_) onSelect_(selectedId_);
        return true;
    }
    size_t itemCount() const {
        size_t count = 0u;
        std::vector<const std::vector<TreeItem>*> pending;
        pending.push_back(&roots_);
        while (!pending.empty()) {
            const auto* values = pending.back();
            pending.pop_back();
            for (const auto& value : *values) {
                ++count;
                pending.push_back(&value.children);
            }
        }
        return count;
    }

public:
    uint64_t addRoot(const std::string& label) {
        if (itemCount() >= kMaxItems || !validLabel(label) || nextId_ == 0u)
            return 0u;
        TreeItem value;
        value.id = nextId_++;
        value.label = label;
        roots_.push_back(std::move(value));
        return roots_.back().id;
    }
    uint64_t addChild(uint64_t parentId, const std::string& label) {
        if (itemCount() >= kMaxItems || !validLabel(label) || nextId_ == 0u)
            return 0u;
        TreeItem* parent = findIn(roots_, parentId);
        if (!parent) return 0u;
        TreeItem value;
        value.id = nextId_++;
        value.label = label;
        parent->children.push_back(std::move(value));
        return parent->children.back().id;
    }
    bool setExpanded(uint64_t id, bool value) {
        TreeItem* item = findIn(roots_, id);
        if (!item || item->children.empty() || item->expanded == value) return false;
        item->expanded = value;
        return true;
    }
    const std::vector<TreeItem>& roots() const { return roots_; }
    uint64_t selectedItemId() const { return selectedId_; }
    int32_t rowHeight() const { return rowHeight_; }
    int32_t scrollOffset() const { return scroll_.offset(); }
    int32_t maxScrollOffset() const { return scroll_.maxOffset(); }
    void updateLayout() { syncScroll(itemCount()); }
    void setOnSelect(std::function<void(uint64_t)> callback) {
        onSelect_ = std::move(callback);
    }

    AccessibilityRole accessibilityRole() const override {
        return AccessibilityRole::Tree;
    }
    std::string accessibilityValue() const override {
        const TreeItem* item = findIn(roots_, selectedId_);
        return item ? item->label : "";
    }
    uint32_t accessibilityExtraState() const override {
        const TreeItem* item = findIn(roots_, selectedId_);
        return (selectedId_ != 0u ? ACCESSIBILITY_STATE_SELECTED : 0u) |
               (item && item->expanded ? ACCESSIBILITY_STATE_EXPANDED : 0u);
    }
    uint32_t accessibilityActions() const override {
        const TreeItem* item = findIn(roots_, selectedId_);
        return ACCESSIBILITY_ACTION_SELECT |
               ACCESSIBILITY_ACTION_SCROLL_FORWARD |
               ACCESSIBILITY_ACTION_SCROLL_BACKWARD |
               (item && !item->children.empty()
                    ? (item->expanded ? ACCESSIBILITY_ACTION_COLLAPSE
                                      : ACCESSIBILITY_ACTION_EXPAND)
                    : 0u);
    }
    bool acceptsKeyboardFocus() const override { return true; }
    LayoutSize minimumLayoutSize() const override {
        return enforceControlTarget({160, 96});
    }

    bool handleEvent(const Event& event) override {
        std::vector<VisibleItem> entries;
        visible(entries);
        syncScroll(entries.size());
        if (event.type == EventType::MouseDown &&
            getBounds().contains(event.x, event.y)) {
            int32_t index = scroll_.offset() +
                (event.y - bounds.y) / rowHeight_;
            if (index < 0 || index >= static_cast<int32_t>(entries.size()))
                return true;
            VisibleItem entry = entries[index];
            if (event.x < bounds.x + 28 + entry.depth * 16 &&
                !entry.item->children.empty())
                entry.item->expanded = !entry.item->expanded;
            else
                (void)selectId(entry.item->id);
            return true;
        }
        if (event.type != EventType::KeyDown || !hasAccessibilityFocus())
            return false;
        int32_t selectedIndex = -1;
        for (int32_t index = 0; index < static_cast<int32_t>(entries.size()); ++index)
            if (entries[index].item->id == selectedId_) selectedIndex = index;
        if (entries.empty()) return true;
        if (event.key == widget_detail::kUp || event.key == widget_detail::kDown ||
            event.key == widget_detail::kHome || event.key == widget_detail::kEnd ||
            event.key == 0x21u || event.key == 0x22u) {
            int32_t next = selectedIndex;
            if (event.key == widget_detail::kUp) next = selectedIndex <= 0 ? 0 : selectedIndex - 1;
            else if (event.key == widget_detail::kDown) next = selectedIndex < 0 ? 0 : (selectedIndex + 1 < static_cast<int32_t>(entries.size()) ? selectedIndex + 1 : selectedIndex);
            else if (event.key == widget_detail::kHome) next = 0;
            else if (event.key == widget_detail::kEnd) next = static_cast<int32_t>(entries.size()) - 1;
            else if (event.key == 0x21u) next = selectedIndex - visibleRows();
            else next = selectedIndex + visibleRows();
            if (next < 0) next = 0;
            if (next >= static_cast<int32_t>(entries.size())) next = static_cast<int32_t>(entries.size()) - 1;
            (void)selectId(entries[next].item->id);
            (void)scroll_.reveal(next, 1);
            return true;
        }
        TreeItem* selected = findIn(roots_, selectedId_);
        if (event.key == widget_detail::kRight && selected) {
            if (!selected->children.empty() && !selected->expanded) selected->expanded = true;
            else if (!selected->children.empty()) (void)selectId(selected->children[0].id);
            return true;
        }
        if (event.key == widget_detail::kLeft && selected) {
            if (selected->expanded) selected->expanded = false;
            else {
                uint64_t parent = parentOf(roots_, selectedId_);
                if (parent) (void)selectId(parent);
            }
            return true;
        }
        if ((event.key == widget_detail::kReturn ||
             event.key == widget_detail::kSpace) && selected &&
            !selected->children.empty()) {
            selected->expanded = !selected->expanded;
            return true;
        }
        return false;
    }
};

class TabView : public Widget {
    std::vector<std::string> tabs_;
    int32_t activeTab_ = 0;
    std::function<void(int32_t)> onChange_;

public:
    TabView() = default;
    void addTab(const std::string& label) { tabs_.push_back(label); }
    void setTabs(const std::vector<std::string>& tabs) {
        tabs_ = tabs;
        if (tabs_.empty()) activeTab_ = 0;
        else if (activeTab_ >= (int32_t)tabs_.size()) activeTab_ = (int32_t)tabs_.size() - 1;
    }
    const std::vector<std::string>& tabs() const { return tabs_; }
    void setActiveTab(int32_t index) {
        if (index < 0 || index >= (int32_t)tabs_.size()) return;
        if (activeTab_ == index) return;
        activeTab_ = index;
        if (onChange_) onChange_(activeTab_);
    }
    int32_t activeTab() const { return activeTab_; }
    void setOnTabChange(std::function<void(int32_t)> callback) { onChange_ = callback; }

    AccessibilityRole accessibilityRole() const override {
        return AccessibilityRole::TabList;
    }
    std::string accessibilityValue() const override {
        return activeTab_ >= 0 && activeTab_ < (int32_t)tabs_.size()
                   ? tabs_[activeTab_]
                   : "";
    }
    uint32_t accessibilityActions() const override {
        return ACCESSIBILITY_ACTION_SET_VALUE;
    }
    bool acceptsKeyboardFocus() const override { return true; }
    LayoutSize minimumLayoutSize() const override {
        return enforceControlTarget({140, 32});
    }

    bool handleEvent(const Event& event) override {
        if (!isVisible() || !isEnabled() || tabs_.empty()) return false;
        if (event.type == EventType::MouseDown && getBounds().contains(event.x, event.y)) {
            int32_t width = getBounds().w / (int32_t)tabs_.size();
            if (width <= 0) return false;
            int32_t index = (event.x - getBounds().x) / width;
            if (index >= 0 && index < (int32_t)tabs_.size()) setActiveTab(index);
            return true;
        }
        if (event.type == EventType::KeyDown && hasAccessibilityFocus()) {
            int32_t next = activeTab_;
            if (event.key == widget_detail::kLeft || event.key == widget_detail::kUp)
                next = activeTab_ == 0 ? (int32_t)tabs_.size() - 1 : activeTab_ - 1;
            else if (event.key == widget_detail::kRight || event.key == widget_detail::kDown)
                next = activeTab_ + 1 == (int32_t)tabs_.size() ? 0 : activeTab_ + 1;
            else
                return false;
            setActiveTab(next);
            return true;
        }
        return false;
    }
};

class ComboBox : public Widget {
    std::vector<std::string> items_;
    int32_t selectedIndex_ = -1;
    bool open_ = false;
    std::function<void(int32_t)> onSelect_;

public:
    ComboBox() = default;
    void addItem(const std::string& item) { items_.push_back(item); }
    void setItems(const std::vector<std::string>& items) {
        items_ = items;
        selectedIndex_ = -1;
        open_ = false;
    }
    const std::vector<std::string>& items() const { return items_; }
    void setSelectedIndex(int32_t index) {
        if (index < -1 || index >= (int32_t)items_.size()) return;
        selectedIndex_ = index;
    }
    int32_t selectedIndex() const { return selectedIndex_; }
    std::string selectedItem() const {
        return selectedIndex_ >= 0 ? items_[selectedIndex_] : "";
    }
    void setOpen(bool open) { open_ = open; }
    void toggleOpen() { open_ = !open_; }
    bool selectIndex(int32_t index) {
        if (index < 0 || index >= (int32_t)items_.size()) return false;
        if (selectedIndex_ == index) {
            open_ = false;
            return false;
        }
        selectedIndex_ = index;
        open_ = false;
        if (onSelect_) onSelect_(selectedIndex_);
        return true;
    }
    bool isOpen() const { return open_; }
    void setOnSelect(std::function<void(int32_t)> callback) { onSelect_ = callback; }

    AccessibilityRole accessibilityRole() const override {
        return AccessibilityRole::ComboBox;
    }
    std::string accessibilityValue() const override { return selectedItem(); }
    uint32_t accessibilityExtraState() const override {
        return open_ ? ACCESSIBILITY_STATE_EXPANDED : 0u;
    }
    uint32_t accessibilityActions() const override {
        return open_ ? ACCESSIBILITY_ACTION_COLLAPSE : ACCESSIBILITY_ACTION_EXPAND;
    }
    bool acceptsKeyboardFocus() const override { return true; }
    LayoutSize minimumLayoutSize() const override {
        return enforceControlTarget({120, 32});
    }

    bool handleEvent(const Event& event) override {
        if (!isVisible() || !isEnabled()) return false;
        if (event.type == EventType::MouseDown && getBounds().contains(event.x, event.y)) {
            toggleOpen();
            return true;
        }
        if (event.type != EventType::KeyDown || !hasAccessibilityFocus()) return false;
        if (event.key == widget_detail::kReturn || event.key == widget_detail::kSpace) {
            open_ = !open_;
            return true;
        }
        if (event.key == widget_detail::kEscape && open_) {
            open_ = false;
            return true;
        }
        if (items_.empty()) return false;
        int32_t next = selectedIndex_;
        if (event.key == widget_detail::kUp || event.key == widget_detail::kLeft)
            next = selectedIndex_ <= 0 ? (int32_t)items_.size() - 1 : selectedIndex_ - 1;
        else if (event.key == widget_detail::kDown || event.key == widget_detail::kRight)
            next = selectedIndex_ + 1 >= (int32_t)items_.size() ? 0 : selectedIndex_ + 1;
        else if (event.key == widget_detail::kHome)
            next = 0;
        else if (event.key == widget_detail::kEnd)
            next = (int32_t)items_.size() - 1;
        else
            return false;
        if (next != selectedIndex_) {
            selectedIndex_ = next;
            if (onSelect_) onSelect_(selectedIndex_);
        }
        return true;
    }
};

/* A radio button is intentionally group-neutral in the portable layer.  A
 * toolkit or window focus owner can enforce exclusivity for matching group
 * names without making the model depend on a native widget tree. */
class RadioButton : public Widget {
    std::string label_;
    std::string group_;
    bool checked_ = false;
    std::function<void(bool)> onChange_;

public:
    explicit RadioButton(const std::string& label = "",
                         const std::string& group = "")
    {
        (void)setLabel(label);
        (void)setGroup(group);
    }

    bool setLabel(const std::string& label) {
        if (!widget_detail::validText(label)) return false;
        label_ = label;
        return true;
    }
    const std::string& label() const { return label_; }
    bool setGroup(const std::string& group) {
        if (!widget_detail::validText(group)) return false;
        group_ = group;
        return true;
    }
    const std::string& group() const { return group_; }
    bool isChecked() const { return checked_; }
    void setOnChange(std::function<void(bool)> callback) {
        onChange_ = std::move(callback);
    }
    void setChecked(bool value) {
        if (checked_ == value) return;
        checked_ = value;
        if (onChange_) onChange_(checked_);
    }

    AccessibilityRole accessibilityRole() const override {
        return AccessibilityRole::RadioButton;
    }
    std::string accessibilityDefaultName() const override { return label_; }
    std::string accessibilityValue() const override {
        return checked_ ? "true" : "false";
    }
    uint32_t accessibilityExtraState() const override {
        return checked_ ? ACCESSIBILITY_STATE_CHECKED : 0u;
    }
    uint32_t accessibilityActions() const override {
        return ACCESSIBILITY_ACTION_SELECT;
    }
    bool acceptsKeyboardFocus() const override { return true; }
    LayoutSize minimumLayoutSize() const override {
        return enforceControlTarget({96, 32});
    }

    bool handleEvent(const Event& event) override {
        if (!isVisible() || !isEnabled()) return false;
        if (event.type == EventType::MouseDown &&
            getBounds().contains(event.x, event.y)) {
            setChecked(true);
            return true;
        }
        if (event.type == EventType::KeyDown && hasAccessibilityFocus() &&
            (event.key == widget_detail::kReturn ||
             event.key == widget_detail::kSpace)) {
            setChecked(true);
            return true;
        }
        return false;
    }
};

/* Menu state and geometry belong to the portable widget layer.  A platform
 * adapter may paint the returned rectangles, but it must not duplicate menu
 * hit-testing or keep a second open/selection state. */
struct MenuItem {
    std::string label;
    std::string shortcut;
    std::function<void()> action;
    bool separator = false;
    bool enabled = true;
    bool selected = false;

    MenuItem() = default;
    MenuItem(const std::string& itemLabel, const std::string& itemShortcut,
             std::function<void()> itemAction, bool isSeparator = false,
             bool isEnabled = true)
        : label(itemLabel), shortcut(itemShortcut), action(itemAction),
          separator(isSeparator), enabled(isEnabled) {}
};

struct Menu {
    std::string title;
    std::vector<MenuItem> items;
    bool open = false;
};

/* A popup menu is intentionally separate from MenuBar: it has one trigger
 * widget and a vertical child list, while MenuBar owns horizontal menu
 * geometry.  Keeping this state portable lets native adapters paint the
 * popup without reimplementing selection, activation, or accessibility. */
class PopupMenu : public RinRuntime::Widget {
    static constexpr size_t kMaxItems = 128u;
    static constexpr size_t kMaxTextBytes = 4096u;
    std::string title_;
    std::vector<MenuItem> items_;
    int32_t activeIndex_ = -1;
    bool open_ = false;

    static bool validText(const std::string& value) {
        if (value.size() > kMaxTextBytes) return false;
        TextInputModel validator;
        return validator.setText(value);
    }

    int32_t nextEnabledFrom(int32_t from, int direction) const {
        const int32_t count = static_cast<int32_t>(items_.size());
        if (count == 0) return -1;
        int32_t index = from;
        for (int32_t attempts = count; attempts-- > 0;) {
            index += direction;
            if (index < 0) index = count - 1;
            if (index >= count) index = 0;
            if (!items_[index].separator && items_[index].enabled)
                return index;
        }
        return -1;
    }

    void clearSelection() {
        for (auto& item : items_) item.selected = false;
        activeIndex_ = -1;
    }

public:
    explicit PopupMenu(const std::string& title = "") {
        (void)setTitle(title);
        items_.reserve(kMaxItems);
    }

    bool setTitle(const std::string& title) {
        if (!validText(title)) return false;
        title_ = title;
        return true;
    }
    const std::string& title() const { return title_; }

    int32_t addItem(const std::string& label, const std::string& shortcut = "",
                    std::function<void()> action = nullptr,
                    bool enabled = true) {
        if (items_.size() >= kMaxItems || !validText(label) ||
            !validText(shortcut)) return -1;
        items_.push_back(MenuItem(label, shortcut, std::move(action), false,
                                  enabled));
        return static_cast<int32_t>(items_.size() - 1u);
    }

    int32_t addSeparator() {
        if (items_.size() >= kMaxItems) return -1;
        items_.push_back(MenuItem("", "", nullptr, true, false));
        return static_cast<int32_t>(items_.size() - 1u);
    }

    const std::vector<MenuItem>& items() const { return items_; }
    std::vector<MenuItem>& items() { return items_; }
    int32_t activeIndex() const { return activeIndex_; }
    bool isOpen() const { return open_; }

    bool setItemEnabled(int32_t index, bool enabled) {
        if (index < 0 || index >= static_cast<int32_t>(items_.size()) ||
            items_[index].separator) return false;
        items_[index].enabled = enabled;
        if (!enabled && activeIndex_ == index) clearSelection();
        return true;
    }

    bool setItemAction(int32_t index, std::function<void()> action) {
        if (index < 0 || index >= static_cast<int32_t>(items_.size()) ||
            items_[index].separator) return false;
        items_[index].action = std::move(action);
        return true;
    }

    bool setActiveIndex(int32_t index) {
        if (index < 0 || index >= static_cast<int32_t>(items_.size()) ||
            items_[index].separator || !items_[index].enabled) return false;
        for (auto& item : items_) item.selected = false;
        items_[index].selected = true;
        activeIndex_ = index;
        return true;
    }

    int32_t nextEnabled(int direction) const {
        return nextEnabledFrom(activeIndex_, direction < 0 ? -1 : 1);
    }

    void close() {
        open_ = false;
        clearSelection();
    }

    void setOpen(bool value) {
        if (!value) {
            close();
            return;
        }
        if (open_) return;
        open_ = true;
        const int32_t first = nextEnabledFrom(-1, 1);
        if (first >= 0) setActiveIndex(first);
    }

    bool activate(int32_t index) {
        if (index < 0 || index >= static_cast<int32_t>(items_.size()) ||
            items_[index].separator || !items_[index].enabled) return false;
        std::function<void()> action = items_[index].action;
        close();
        if (action) action();
        return true;
    }

    bool activateActive() {
        return activeIndex_ >= 0 && activate(activeIndex_);
    }

    AccessibilityRole accessibilityRole() const override {
        return AccessibilityRole::Menu;
    }
    std::string accessibilityDefaultName() const override { return title_; }
    std::string accessibilityValue() const override {
        return activeIndex_ >= 0 ? items_[activeIndex_].label : "";
    }
    uint32_t accessibilityExtraState() const override {
        return open_ ? ACCESSIBILITY_STATE_EXPANDED : 0u;
    }
    uint32_t accessibilityActions() const override {
        return open_ ? ACCESSIBILITY_ACTION_COLLAPSE
                     : ACCESSIBILITY_ACTION_EXPAND;
    }
    bool acceptsKeyboardFocus() const override { return true; }
    LayoutSize minimumLayoutSize() const override {
        return enforceControlTarget({80, 32});
    }

    bool handleEvent(const RinRuntime::Event& event) override {
        if (!isVisible() || !isEnabled()) return false;
        if (event.type == EventType::MouseDown &&
            getBounds().contains(event.x, event.y)) {
            setOpen(!open_);
            return true;
        }
        if (event.type != EventType::KeyDown || !hasAccessibilityFocus())
            return false;
        if (event.key == widget_detail::kEscape && open_) {
            close();
            return true;
        }
        if (event.key == widget_detail::kReturn ||
            event.key == widget_detail::kSpace) {
            if (open_) activateActive();
            else setOpen(true);
            return true;
        }
        if (event.key == widget_detail::kDown ||
            event.key == widget_detail::kUp) {
            if (!open_) {
                /* The first directional key opens on the first enabled item.
                 * Do not advance a second time: otherwise Down skips the
                 * first command (and Up can wrap to the last one) on open. */
                setOpen(true);
                return true;
            }
            const int32_t next = nextEnabled(event.key == widget_detail::kDown ? 1 : -1);
            if (next >= 0) setActiveIndex(next);
            return true;
        }
        if (event.key == widget_detail::kHome ||
            event.key == widget_detail::kEnd) {
            if (!open_) setOpen(true);
            const int32_t next = event.key == widget_detail::kHome
                                     ? nextEnabledFrom(-1, 1)
                                     : nextEnabledFrom(0, -1);
            if (next >= 0) setActiveIndex(next);
            return true;
        }
        return false;
    }
};

class MenuBar : public Widget {
    static constexpr size_t kMaxMenus = 32u;
    static constexpr size_t kMaxItemsPerMenu = 128u;
    static constexpr size_t kMaxTextBytes = 4096u;
    static constexpr int32_t kMaxSurfaceWidth = 16384;
    std::vector<Menu> menus_;
    int32_t activeMenu_ = -1;
    int32_t surfaceWidth_ = 1;
    int32_t barHeight_ = 24;
    int32_t itemHeight_ = 24;

    int32_t clampedTitleWidth(int32_t index, int32_t x) const {
        if (index < 0 || index >= (int32_t)menus_.size()) return 1;
        int32_t width = textPixelWidth(menus_[index].title) + 16;
        int32_t remaining = surfaceWidth_ - x - 10;
        if (remaining < 1) remaining = 1;
        if (width > remaining) width = remaining;
        return width < 1 ? 1 : width;
    }
    static bool validText(const std::string& value) {
        if (value.size() > kMaxTextBytes) return false;
        TextInputModel validator;
        return validator.setText(value);
    }

public:
    explicit MenuBar(int32_t surfaceWidth = 1) {
        setSurfaceWidth(surfaceWidth);
    }

    void setSurfaceWidth(int32_t value) {
        surfaceWidth_ = value > 0 ? value : 1;
        if (surfaceWidth_ > kMaxSurfaceWidth)
            surfaceWidth_ = kMaxSurfaceWidth;
        Rect current = getBounds();
        setBounds(Rect(0, current.y, surfaceWidth_, barHeight_));
    }
    int32_t surfaceWidth() const { return surfaceWidth_; }
    int32_t barHeight() const { return barHeight_; }
    int32_t itemHeight() const { return itemHeight_; }

    void clearMenus() {
        menus_.clear();
        activeMenu_ = -1;
    }
    int32_t addMenu(const std::string& title) {
        if (menus_.size() >= kMaxMenus || !validText(title)) return -1;
        menus_.push_back(Menu());
        menus_.back().title = title;
        return (int32_t)menus_.size() - 1;
    }
    bool addItem(int32_t menuIndex, const MenuItem& item) {
        if (menuIndex < 0 || menuIndex >= (int32_t)menus_.size()) return false;
        if (menus_[menuIndex].items.size() >= kMaxItemsPerMenu ||
            !validText(item.label) || !validText(item.shortcut)) return false;
        menus_[menuIndex].items.push_back(item);
        return true;
    }
    bool setAction(const std::string& menuTitle, const std::string& itemLabel,
                   std::function<void()> action) {
        for (auto& menu : menus_) {
            if (menu.title != menuTitle) continue;
            for (auto& item : menu.items) {
                if (item.label == itemLabel) {
                    item.action = action;
                    return true;
                }
            }
        }
        return false;
    }
    const std::vector<Menu>& menus() const { return menus_; }
    std::vector<Menu>& menus() { return menus_; }
    int32_t activeMenu() const { return activeMenu_; }
    bool isOpen(int32_t index) const {
        return index >= 0 && index < (int32_t)menus_.size() && menus_[index].open;
    }

    Rect menuRect(int32_t index, int32_t y) const {
        int32_t x = 10;
        for (int32_t i = 0; i < index && i < (int32_t)menus_.size(); ++i)
            x += clampedTitleWidth(i, x) + 8;
        if (x >= surfaceWidth_) x = surfaceWidth_ - 1;
        if (x < 0) x = 0;
        return Rect(x, y, clampedTitleWidth(index, x), barHeight_);
    }

    int32_t dropdownWidth(int32_t index) const {
        if (index < 0 || index >= (int32_t)menus_.size()) return 1;
        int32_t width = 0;
        for (const auto& item : menus_[index].items) {
            int32_t row = textPixelWidth(item.label) +
                          (item.shortcut.empty() ? 32 :
                           textPixelWidth(item.shortcut) + 48);
            if (row > width) width = row;
        }
        if (width < 180) width = 180;
        int32_t maximum = surfaceWidth_ - 20;
        if (maximum < 1) maximum = 1;
        if (width > maximum) width = maximum;
        return width;
    }

    Rect dropdownRect(int32_t index, int32_t y) const {
        Rect title = menuRect(index, y - barHeight_);
        int32_t width = dropdownWidth(index);
        int32_t x = title.x;
        if (x + width > surfaceWidth_ - 10) x = surfaceWidth_ - 10 - width;
        if (x < 0) x = 0;
        int32_t height = 8 + itemHeight_ *
                         (index >= 0 && index < (int32_t)menus_.size()
                              ? (int32_t)menus_[index].items.size() : 0);
        if (height < 1) height = 1;
        return Rect(x, y, width, height);
    }

    Rect menuItemRect(int32_t menuIndex, int32_t itemIndex, int32_t y) const {
        Rect dropdown = dropdownRect(menuIndex, y);
        return Rect(dropdown.x, dropdown.y + 4 + itemIndex * itemHeight_,
                    dropdown.w, itemHeight_);
    }

    int32_t hitTestMenu(int32_t x, int32_t y, int32_t baseY) const {
        if (y < baseY || y >= baseY + barHeight_) return -1;
        for (int32_t index = 0; index < (int32_t)menus_.size(); ++index)
            if (menuRect(index, baseY).contains(x, y)) return index;
        return -1;
    }

    void openMenu(int32_t index) {
        if (index < 0 || index >= (int32_t)menus_.size()) return;
        closeMenus();
        activeMenu_ = index;
        menus_[index].open = true;
    }
    void closeMenus() {
        for (auto& menu : menus_) menu.open = false;
        activeMenu_ = -1;
    }

    bool handlePointer(int32_t x, int32_t y, int32_t baseY) {
        int32_t menuIndex = hitTestMenu(x, y, baseY);
        if (menuIndex >= 0) {
            if (activeMenu_ == menuIndex && menus_[menuIndex].open)
                closeMenus();
            else
                openMenu(menuIndex);
            return true;
        }
        if (activeMenu_ < 0 || !menus_[activeMenu_].open) return false;
        Rect dropdown = dropdownRect(activeMenu_, baseY + barHeight_);
        if (!dropdown.contains(x, y)) {
            closeMenus();
            return false;
        }
        int32_t itemIndex = (y - dropdown.y - 4) / itemHeight_;
        if (itemIndex < 0 || itemIndex >= (int32_t)menus_[activeMenu_].items.size()) {
            closeMenus();
            return true;
        }
        MenuItem item = menus_[activeMenu_].items[itemIndex];
        closeMenus();
        if (!item.separator && item.enabled && item.action) item.action();
        return true;
    }

    AccessibilityRole accessibilityRole() const override {
        return AccessibilityRole::Menu;
    }
    std::string accessibilityDefaultName() const override { return "Menu bar"; }
    uint32_t accessibilityExtraState() const override {
        return activeMenu_ >= 0 ? ACCESSIBILITY_STATE_EXPANDED : 0u;
    }
    uint32_t accessibilityActions() const override {
        return activeMenu_ >= 0 ? ACCESSIBILITY_ACTION_COLLAPSE
                                : ACCESSIBILITY_ACTION_EXPAND;
    }
    bool acceptsKeyboardFocus() const override { return true; }
    LayoutSize minimumLayoutSize() const override {
        return enforceControlTarget({surfaceWidth_, barHeight_});
    }

    bool handleEvent(const Event& event) override {
        if (!isVisible() || !isEnabled()) return false;
        if (event.type == EventType::MouseDown)
            return handlePointer(event.x, event.y, getBounds().y);
        if (event.type != EventType::KeyDown || !hasAccessibilityFocus()) return false;
        if (event.key == widget_detail::kEscape && activeMenu_ >= 0) {
            closeMenus();
            return true;
        }
        if (menus_.empty()) return false;
        int32_t next = activeMenu_ < 0 ? 0 : activeMenu_;
        if (event.key == widget_detail::kLeft)
            next = next == 0 ? (int32_t)menus_.size() - 1 : next - 1;
        else if (event.key == widget_detail::kRight)
            next = next + 1 == (int32_t)menus_.size() ? 0 : next + 1;
        else if (event.key == widget_detail::kReturn || event.key == widget_detail::kSpace) {
            if (activeMenu_ < 0) openMenu(next);
            else if (!menus_[activeMenu_].items.empty()) {
                MenuItem item = menus_[activeMenu_].items.front();
                closeMenus();
                if (!item.separator && item.enabled && item.action) item.action();
            }
            return true;
        } else {
            return false;
        }
        openMenu(next);
        return true;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_WIDGETS_HPP */
