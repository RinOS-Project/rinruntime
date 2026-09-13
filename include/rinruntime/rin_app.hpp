/* SPDX-License-Identifier: MIT */
#ifndef RINRUNTIME_RIN_APP_HPP
#define RINRUNTIME_RIN_APP_HPP

#include <algorithm>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "application_data.hpp"
#include "controls.hpp"
#include "event.hpp"
#include "layout.hpp"
#include "piece_table.hpp"
#include "widgets.hpp"

namespace Rin {

using Rect = RinRuntime::Rect;
using Event = RinRuntime::Event;
using EventType = RinRuntime::EventType;
using Widget = RinRuntime::Widget;
using Button = RinRuntime::Button;
using Label = RinRuntime::Label;
using TextField = RinRuntime::TextField;
using TextArea = RinRuntime::TextArea;
using CheckBox = RinRuntime::CheckBox;
using Slider = RinRuntime::Slider;
using ProgressBar = RinRuntime::ProgressBar;
using Dialog = RinRuntime::Dialog;
using List = RinRuntime::List;
using ScrollView = RinRuntime::ScrollView;
using Table = RinRuntime::Table;
using Tree = RinRuntime::Tree;
using TabView = RinRuntime::TabView;
using ComboBox = RinRuntime::ComboBox;

/* Application lifecycle model. A platform adapter owns the native window;
 * this class owns only lifecycle state and callback ordering. */
class Application final {
public:
    enum class State : uint8_t { Created, Running, QuitRequested, Stopped };

private:
    State state_ = State::Created;
    std::function<void()> started_;
    std::function<void()> stopped_;
    std::function<bool(const Event&)> eventHandler_;

public:
    Application() = default;
    Application(const Application&) = delete;
    Application& operator=(const Application&) = delete;

    bool start() {
        if (state_ != State::Created) return false;
        state_ = State::Running;
        if (started_) started_();
        return true;
    }

    bool dispatch(const Event& event) {
        if (state_ != State::Running || !eventHandler_) return false;
        return eventHandler_(event);
    }

    bool requestQuit() {
        if (state_ != State::Running) return false;
        state_ = State::QuitRequested;
        return true;
    }

    bool stop() {
        if (state_ != State::Running && state_ != State::QuitRequested)
            return false;
        state_ = State::Stopped;
        if (stopped_) stopped_();
        return true;
    }

    State state() const { return state_; }
    void onStarted(std::function<void()> callback) { started_ = std::move(callback); }
    void onStopped(std::function<void()> callback) { stopped_ = std::move(callback); }
    void onEvent(std::function<bool(const Event&)> callback) {
        eventHandler_ = std::move(callback);
    }
};

class FormValidator final {
    struct Rule { std::string field; size_t minimum = 0u; bool required = false; };
    std::vector<Rule> rules_;
    std::vector<std::string> errors_;

public:
    void required(std::string field) {
        rules_.push_back({std::move(field), 0u, true});
    }
    void minimumLength(std::string field, size_t minimum) {
        rules_.push_back({std::move(field), minimum, false});
    }
    bool validate(const std::vector<std::pair<std::string, std::string>>& values) {
        errors_.clear();
        for (const Rule& rule : rules_) {
            std::string value;
            for (const auto& item : values)
                if (item.first == rule.field) { value = item.second; break; }
            if ((rule.required && value.empty()) || value.size() < rule.minimum)
                errors_.push_back(rule.field);
        }
        return errors_.empty();
    }
    const std::vector<std::string>& errors() const { return errors_; }
};

class Document final {
    RinRuntime::PieceTable table_;

public:
    bool setText(const std::string& text) { return table_.setOriginal(text); }
    bool insert(size_t offset, const std::string& text) {
        return table_.insert(offset, text);
    }
    bool erase(size_t offset, size_t length) { return table_.erase(offset, length); }
    std::string text() const { return table_.materialize(); }
    size_t size() const { return table_.size(); }
};

struct PrintSettings {
    enum class Orientation : uint8_t { Portrait, Landscape };
    uint32_t widthMm = 210u;
    uint32_t heightMm = 297u;
    Orientation orientation = Orientation::Portrait;
    uint32_t copies = 1u;
    bool duplex = false;
    bool grayscale = false;

    bool valid() const {
        return widthMm != 0u && heightMm != 0u && copies != 0u && copies <= 999u;
    }
};

class WindowShakeEffect final {
    float intensity_ = 0.0f;
    float decay_ = 0.85f;

public:
    void start(float intensity) {
        if (intensity > 0.0f && intensity <= 100.0f) intensity_ = intensity;
    }
    void advance(float seconds) {
        if (seconds < 0.0f) return;
        while (seconds > 0.0f && intensity_ > 0.01f) {
            intensity_ *= decay_;
            seconds -= 0.016f;
        }
        if (intensity_ <= 0.01f) intensity_ = 0.0f;
    }
    bool active() const { return intensity_ > 0.0f; }
    float intensity() const { return intensity_; }
};

struct ActivityItem {
    std::string title;
    std::string description;
    bool read = false;
};

class ActivityFeed final {
    std::vector<ActivityItem> items_;
    size_t limit_ = 50u;

public:
    explicit ActivityFeed(size_t limit = 50u) : limit_(limit) {}
    bool add(ActivityItem item) {
        if (limit_ == 0u || item.title.empty() || item.title.size() > 256u ||
            item.description.size() > 1024u) return false;
        items_.insert(items_.begin(), std::move(item));
        if (items_.size() > limit_) items_.resize(limit_);
        return true;
    }
    bool markRead(size_t index) {
        if (index >= items_.size()) return false;
        items_[index].read = true;
        return true;
    }
    const std::vector<ActivityItem>& items() const { return items_; }
};

using ApplicationDataPolicy = RinRuntime::ApplicationDataPolicy;
using ApplicationDataIdentity = RinRuntime::ApplicationDataIdentity;

} // namespace Rin

#endif /* RINRUNTIME_RIN_APP_HPP */
