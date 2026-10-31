/* SPDX-License-Identifier: MIT */
#ifndef RINRUNTIME_CONTEXT_MENU_HPP
#define RINRUNTIME_CONTEXT_MENU_HPP

#include "text_input.hpp"
#include "widget.hpp"

#include <stdint.h>
#include <string>
#include <utility>
#include <vector>
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
#include <new>
#endif

namespace RinRuntime {

struct ContextMenuRect {
    int32_t x = 0;
    int32_t y = 0;
    int32_t width = 0;
    int32_t height = 0;

    bool contains(int32_t px, int32_t py) const {
        const int64_t dx = (int64_t)px - x;
        const int64_t dy = (int64_t)py - y;
        return width > 0 && height > 0 && dx >= 0 && dy >= 0 &&
               dx < width && dy < height;
    }
};

struct ContextMenuItem {
    std::string label;
    std::string shortcut;
    uint64_t action_id = 0u;
    uint64_t submenu_id = 0u;
    uint64_t icon_id = 0u;
    bool separator = false;
    bool enabled = true;
    bool checked = false;
};

enum class ContextMenuKey : uint8_t {
    Escape,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    Enter
};

/* Portable menu state and hit testing. Rendering code owns the pixels and
 * applies its current theme, scale, and transparency policy. Menu actions are
 * opaque IDs returned to the caller; this class never executes commands or
 * resolves paths. The owner cookie and generation make delayed activations
 * rejectable after an app or menu instance has been replaced. */
class ContextMenuModel {
    static constexpr size_t kMaximumMenus = 32u;
    static constexpr size_t kMaximumItemsPerMenu = 128u;
    static constexpr size_t kMaximumDepth = 8u;
    static constexpr size_t kMaximumTextBytes = 4096u;

    struct MenuLevel {
        uint64_t id = 0u;
        std::vector<ContextMenuItem> items;
    };

    std::vector<MenuLevel> menus_;
    uint64_t menu_path_[kMaximumDepth] = {};
    int32_t parent_item_path_[kMaximumDepth] = {};
    ContextMenuRect parent_row_path_[kMaximumDepth] = {};
    ContextMenuRect menu_bounds_path_[kMaximumDepth] = {};
    size_t depth_ = 0u;
    int32_t active_index_ = -1;
    size_t first_visible_ = 0u;
    uint64_t owner_cookie_ = 0u;
    uint64_t owner_generation_ = 0u;
    uint64_t next_generation_ = 1u;
    uint64_t opening_generation_ = 0u;
    ContextMenuRect bounds_;
    int32_t anchor_x_ = 0;
    int32_t anchor_y_ = 0;
    int32_t screen_width_ = 0;
    int32_t screen_height_ = 0;
    int32_t row_height_ = 0;
    int32_t padding_ = 0;
    int32_t menu_width_ = 0;
    bool open_ = false;

    static bool validText(const std::string& value) {
        return value.size() <= kMaximumTextBytes &&
               strictUtf8TextValid(value);
    }

    int32_t menuIndex(uint64_t id) const {
        for (size_t index = 0u; index < menus_.size(); ++index)
            if (menus_[index].id == id) return (int32_t)index;
        return -1;
    }

    const MenuLevel* currentMenu() const {
        if (depth_ == 0u) return nullptr;
        int32_t index = menuIndex(menu_path_[depth_ - 1u]);
        return index < 0 ? nullptr : &menus_[(size_t)index];
    }

    MenuLevel* menu(uint64_t id) {
        int32_t index = menuIndex(id);
        return index < 0 ? nullptr : &menus_[(size_t)index];
    }

    void clearSelection() {
        active_index_ = -1;
        first_visible_ = 0u;
    }

    bool itemFocusable(size_t index) const {
        const MenuLevel* current = currentMenu();
        return current && index < current->items.size() &&
               !current->items[index].separator &&
               current->items[index].enabled;
    }

    void select(int32_t index) {
        const MenuLevel* current = currentMenu();
        if (!current || index < 0 ||
            (size_t)index >= current->items.size() ||
            !itemFocusable((size_t)index)) {
            active_index_ = -1;
            return;
        }
        active_index_ = index;
        const size_t visible = row_height_ > 0 && screen_height_ > 2 * padding_
            ? (size_t)((screen_height_ - 2 * padding_) / row_height_) : 1u;
        if (visible == 0u) return;
        if ((size_t)active_index_ < first_visible_)
            first_visible_ = (size_t)active_index_;
        else if ((size_t)active_index_ >= first_visible_ + visible)
            first_visible_ = (size_t)active_index_ - visible + 1u;
    }

    int32_t nextFocusable(int32_t from, int direction) const {
        const MenuLevel* current = currentMenu();
        if (!current || current->items.empty()) return -1;
        const int32_t count = (int32_t)current->items.size();
        int32_t index = from;
        for (int32_t attempt = 0; attempt < count; ++attempt) {
            index += direction;
            if (index < 0) index = count - 1;
            if (index >= count) index = 0;
            if (itemFocusable((size_t)index)) return index;
        }
        return -1;
    }

    ContextMenuRect rowRect(size_t index) const {
        ContextMenuRect row;
        if (!open_ || index < first_visible_ || row_height_ <= 0) return row;
        const size_t visible_index = index - first_visible_;
        if (visible_index > (size_t)(INT32_MAX / row_height_)) return row;
        row.x = bounds_.x + padding_;
        row.y = bounds_.y + padding_ +
                (int32_t)visible_index * row_height_;
        row.width = bounds_.width - 2 * padding_;
        row.height = row_height_;
        const MenuLevel* current = currentMenu();
        if (!current || index >= current->items.size() ||
            row.y < bounds_.y + padding_ ||
            row.y >= bounds_.y + bounds_.height - padding_) return {};
        if (row.y + row.height > bounds_.y + bounds_.height - padding_)
            row.height = bounds_.y + bounds_.height - padding_ - row.y;
        return row;
    }

    void placeRoot() {
        const MenuLevel* current = currentMenu();
        if (!current || screen_width_ <= 0 || screen_height_ <= 0) {
            bounds_ = {};
            return;
        }
        const int32_t maximum_width = screen_width_ > 2 * padding_
            ? screen_width_ - 2 * padding_ : screen_width_;
        int32_t width = menu_width_;
        if (width > maximum_width) width = maximum_width;
        if (width < 1) width = 1;
        int32_t available_height = screen_height_ - 2 * padding_;
        if (available_height < 1) available_height = screen_height_;
        int32_t height = padding_ * 2;
        const int32_t item_count = current->items.size() >
                (size_t)(INT32_MAX / row_height_)
            ? INT32_MAX / row_height_ : (int32_t)current->items.size();
        if (row_height_ > 0 && item_count <=
                (INT32_MAX - height) / row_height_)
            height += item_count * row_height_;
        if (height > available_height) height = available_height;
        int32_t x = anchor_x_;
        int32_t y = anchor_y_;
        const int32_t maximum_x = screen_width_ - width - padding_;
        const int32_t maximum_y = screen_height_ - height - padding_;
        if (x > maximum_x) x = maximum_x;
        if (x < padding_) x = padding_;
        if (y > maximum_y) {
            if (anchor_y_ >= height + padding_)
                y = anchor_y_ - height;
            else
                y = maximum_y;
        }
        if (y > maximum_y) y = maximum_y;
        if (y < padding_) y = padding_;
        bounds_ = {x, y, width, height};
    }

    void placeSubmenu() {
        if (depth_ < 2u) return placeRoot();
        const ContextMenuRect parent_row = parent_row_path_[depth_ - 1u];
        const MenuLevel* current = currentMenu();
        if (!current || parent_row.width <= 0) {
            placeRoot();
            return;
        }
        placeRoot();
        int32_t x = parent_row.x + parent_row.width;
        if (x + bounds_.width > screen_width_ - padding_)
            x = parent_row.x - bounds_.width;
        if (x < padding_) x = padding_;
        int32_t y = parent_row.y;
        if (y + bounds_.height > screen_height_ - padding_)
            y = screen_height_ - bounds_.height - padding_;
        if (y < padding_) y = padding_;
        bounds_.x = x;
        bounds_.y = y;
    }

    bool pushSubmenu(size_t item_index) {
        const MenuLevel* current = currentMenu();
        if (!current || item_index >= current->items.size() ||
            depth_ >= kMaximumDepth) return false;
        const uint64_t submenu_id = current->items[item_index].submenu_id;
        if (submenu_id == 0u || menuIndex(submenu_id) < 0) return false;
        for (size_t level = 0u; level < depth_; ++level)
            if (menu_path_[level] == submenu_id) return false;
        parent_item_path_[depth_] = (int32_t)item_index;
        parent_row_path_[depth_] = rowRect(item_index);
        menu_bounds_path_[depth_ - 1u] = bounds_;
        menu_path_[depth_] = submenu_id;
        ++depth_;
        clearSelection();
        select(nextFocusable(-1, 1));
        placeSubmenu();
        menu_bounds_path_[depth_ - 1u] = bounds_;
        return true;
    }

    bool popSubmenu() {
        if (depth_ <= 1u) return false;
        --depth_;
        clearSelection();
        bounds_ = menu_bounds_path_[depth_ - 1u];
        select(parent_item_path_[depth_]);
        return true;
    }

    uint64_t activateIndex(size_t index) {
        const MenuLevel* current = currentMenu();
        if (!current || index >= current->items.size() ||
            !itemFocusable(index)) return 0u;
        if (current->items[index].submenu_id != 0u) {
            (void)pushSubmenu(index);
            return 0u;
        }
        const uint64_t action_id = current->items[index].action_id;
        if (action_id == 0u) return 0u;
        close();
        return action_id;
    }

public:
    bool addMenu(uint64_t id) {
        if (id == 0u || menuIndex(id) >= 0 || menus_.size() >= kMaximumMenus)
            return false;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        try {
#endif
            MenuLevel level;
            level.id = id;
            menus_.push_back(std::move(level));
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        } catch (const std::bad_alloc&) {
            return false;
        }
#endif
        return true;
    }

    bool addItem(uint64_t menu_id, const ContextMenuItem& item) {
        MenuLevel* target = menu(menu_id);
        if (!target || target->items.size() >= kMaximumItemsPerMenu ||
            !validText(item.label) || !validText(item.shortcut) ||
            (item.separator && (item.action_id != 0u ||
                                item.submenu_id != 0u)))
            return false;
        if (item.submenu_id != 0u && item.action_id != 0u) return false;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        try {
#endif
            target->items.push_back(item);
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        } catch (const std::bad_alloc&) {
            return false;
        }
#endif
        return true;
    }

    bool clear() {
        close();
        menus_.clear();
        ++next_generation_;
        if (next_generation_ == 0u) next_generation_ = 1u;
        return true;
    }

    bool setItemEnabled(uint64_t menu_id, size_t index, bool enabled) {
        MenuLevel* target = menu(menu_id);
        if (!target || index >= target->items.size() ||
            target->items[index].separator) return false;
        target->items[index].enabled = enabled;
        if (open_ && depth_ != 0u &&
            menu_path_[depth_ - 1u] == menu_id &&
            active_index_ == (int32_t)index && !enabled)
            select(nextFocusable(active_index_, 1));
        return true;
    }

    bool setItemChecked(uint64_t menu_id, size_t index, bool checked) {
        MenuLevel* target = menu(menu_id);
        if (!target || index >= target->items.size() ||
            target->items[index].separator) return false;
        target->items[index].checked = checked;
        return true;
    }

    bool open(uint64_t menu_id, uint64_t owner_cookie,
              uint64_t owner_generation, int32_t anchor_x, int32_t anchor_y,
              int32_t screen_width, int32_t screen_height, int32_t width,
              int32_t row_height, int32_t padding) {
        close();
        if (menuIndex(menu_id) < 0 || owner_cookie == 0u ||
            owner_generation == 0u || screen_width <= 0 ||
            screen_height <= 0 || width <= 0 || row_height <= 0 ||
            padding < 0 || screen_width > 32768 || screen_height > 32768 ||
            padding > (screen_width - 1) / 2 ||
            padding > (screen_height - 1) / 2 ||
            row_height > screen_height || width <= 2 * padding ||
            screen_width - 2 * padding <= 2 * padding)
            return false;
        open_ = true;
        owner_cookie_ = owner_cookie;
        owner_generation_ = owner_generation;
        opening_generation_ = next_generation_++;
        if (next_generation_ == 0u) next_generation_ = 1u;
        anchor_x_ = anchor_x;
        anchor_y_ = anchor_y;
        screen_width_ = screen_width;
        screen_height_ = screen_height;
        row_height_ = row_height;
        padding_ = padding;
        menu_width_ = width;
        bounds_ = {0, 0, 0, 0};
        depth_ = 1u;
        menu_path_[0] = menu_id;
        clearSelection();
        placeRoot();
        menu_bounds_path_[0] = bounds_;
        select(nextFocusable(-1, 1));
        return true;
    }

    void close() {
        open_ = false;
        depth_ = 0u;
        active_index_ = -1;
        first_visible_ = 0u;
        opening_generation_ = 0u;
    }

    bool isOpen() const { return open_; }
    uint64_t ownerCookie() const { return owner_cookie_; }
    uint64_t ownerGeneration() const { return owner_generation_; }
    uint64_t openingGeneration() const { return opening_generation_; }
    int32_t activeIndex() const { return active_index_; }
    bool selectItem(size_t index) {
        if (!open_ || !itemFocusable(index)) return false;
        select((int32_t)index);
        return active_index_ == (int32_t)index;
    }
    uint64_t currentMenuId() const {
        return depth_ == 0u ? 0u : menu_path_[depth_ - 1u];
    }
    const ContextMenuRect& bounds() const { return bounds_; }
    const std::vector<ContextMenuItem>& items(uint64_t menu_id) const {
        static const std::vector<ContextMenuItem> empty;
        int32_t index = menuIndex(menu_id);
        return index < 0 ? empty : menus_[(size_t)index].items;
    }
    const std::vector<ContextMenuItem>& currentItems() const {
        const MenuLevel* current = currentMenu();
        static const std::vector<ContextMenuItem> empty;
        return current ? current->items : empty;
    }
    ContextMenuRect itemBounds(size_t index) const { return rowRect(index); }

    int32_t hitTest(int32_t x, int32_t y) const {
        if (!open_ || !bounds_.contains(x, y)) return -1;
        const MenuLevel* current = currentMenu();
        if (!current || row_height_ <= 0) return -1;
        const int32_t relative_y = y - bounds_.y - padding_;
        if (relative_y < 0) return -1;
        const size_t index = first_visible_ +
                             (size_t)(relative_y / row_height_);
        return index < current->items.size() ? (int32_t)index : -1;
    }

    bool pointerFocusLevel(int32_t x, int32_t y) {
        if (!open_ || depth_ == 0u) return false;
        for (size_t level = depth_; level != 0u; --level) {
            const size_t index = level - 1u;
            if (!menu_bounds_path_[index].contains(x, y)) continue;
            if (index + 1u != depth_) {
                depth_ = index + 1u;
                bounds_ = menu_bounds_path_[index];
                clearSelection();
            }
            return true;
        }
        return false;
    }

    bool containsAnyMenuAt(int32_t x, int32_t y) const {
        if (!open_) return false;
        for (size_t level = 0u; level < depth_; ++level)
            if (menu_bounds_path_[level].contains(x, y)) return true;
        return false;
    }

    bool pointerMove(int32_t x, int32_t y) {
        if (!pointerFocusLevel(x, y)) return false;
        const int32_t index = hitTest(x, y);
        if (index < 0 || !itemFocusable((size_t)index)) return false;
        select(index);
        const MenuLevel* current = currentMenu();
        if (current->items[(size_t)index].submenu_id != 0u)
            return pushSubmenu((size_t)index);
        return true;
    }

    uint64_t pointerActivate(int32_t x, int32_t y,
                             uint64_t owner_cookie,
                             uint64_t owner_generation,
                             uint64_t expected_opening_generation) {
        if (!open_ || owner_cookie != owner_cookie_ ||
            owner_generation != owner_generation_ ||
            opening_generation_ == 0u ||
            expected_opening_generation != opening_generation_) {
            close();
            return 0u;
        }
        if (!pointerFocusLevel(x, y)) return 0u;
        const int32_t index = hitTest(x, y);
        return index < 0 ? 0u : activateIndex((size_t)index);
    }

    uint64_t handleKey(ContextMenuKey key, uint64_t owner_cookie,
                       uint64_t owner_generation,
                       uint64_t expected_opening_generation) {
        if (!open_ || owner_cookie != owner_cookie_ ||
            owner_generation != owner_generation_ ||
            opening_generation_ == 0u ||
            expected_opening_generation != opening_generation_) {
            close();
            return 0u;
        }
        switch (key) {
        case ContextMenuKey::Escape:
        case ContextMenuKey::Left:
            if (!popSubmenu()) close();
            return 0u;
        case ContextMenuKey::Up:
            select(nextFocusable(active_index_, -1));
            return 0u;
        case ContextMenuKey::Down:
            select(nextFocusable(active_index_, 1));
            return 0u;
        case ContextMenuKey::Home:
            select(nextFocusable(-1, 1));
            return 0u;
        case ContextMenuKey::End:
            select(nextFocusable(0, -1));
            return 0u;
        case ContextMenuKey::Right:
            if (active_index_ >= 0)
                (void)pushSubmenu((size_t)active_index_);
            return 0u;
        case ContextMenuKey::Enter:
            return active_index_ < 0 ? 0u
                : activateIndex((size_t)active_index_);
        }
        return 0u;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_CONTEXT_MENU_HPP */
