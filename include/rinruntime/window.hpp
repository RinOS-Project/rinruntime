/* SPDX-License-Identifier: MIT */
/* C++ window wrapper using the public C ABI. */
#pragma once

#include <cstdint>
#include <functional>
#include <utility>
#include "events.hpp"
#include "render_context.hpp"

namespace RinRuntime {

struct WindowOptions {
    const char* title = nullptr;
    std::int32_t x = 0;
    std::int32_t y = 0;
    std::int32_t width = 640;
    std::int32_t height = 480;
    std::uint32_t role = RIN_WINDOW_ROLE_NORMAL;
    std::uint32_t flags = RIN_WINDOW_FLAG_OPAQUE;
    bool visible = true;
};

struct WindowSize {
    std::int32_t width = 0;
    std::int32_t height = 0;
};

struct WindowPosition {
    std::int32_t x = 0;
    std::int32_t y = 0;
};

class Window final {
public:
    using Handle = RinWindowHandle;
    using EventHandler = std::function<bool(const WindowEvent&)>;
    using CompletionHandler =
        std::function<void(const RinRuntimeGuiCompletionV1&)>;
    using PaintHandler = std::function<void(AqSurface&)>;
    using PaintHandlerNoArgs = std::function<void()>;

    Window(const char* title, std::int32_t x, std::int32_t y,
           std::int32_t width, std::int32_t height) noexcept
        : handle_(wnd_create(title, x, y, width, height)) {}

    explicit Window(const WindowOptions& options) noexcept {
        handle_ = wnd_create_flags(options.title, options.x, options.y,
                                   options.width, options.height, options.role,
                                   options.flags);
        if (valid() && !options.visible) wnd_show(handle_, 0);
    }

    ~Window() { close(); }

    Window(const Window&) = delete;
    Window& operator=(const Window&) = delete;

    Window(Window&& other) noexcept
        : handle_(std::exchange(other.handle_, RIN_WINDOW_HANDLE_INVALID)),
          event_handler_(std::move(other.event_handler_)),
          paint_handler_(std::move(other.paint_handler_)),
          paint_handler_no_args_(std::move(other.paint_handler_no_args_)),
          completion_handler_(std::move(other.completion_handler_)) {
        updateCompletionCallback();
    }

    Window& operator=(Window&& other) noexcept {
        if (this == &other) return *this;
        close();
        handle_ = std::exchange(other.handle_, RIN_WINDOW_HANDLE_INVALID);
        event_handler_ = std::move(other.event_handler_);
        paint_handler_ = std::move(other.paint_handler_);
        paint_handler_no_args_ = std::move(other.paint_handler_no_args_);
        completion_handler_ = std::move(other.completion_handler_);
        updateCompletionCallback();
        return *this;
    }

    bool valid() const noexcept { return handle_ != RIN_WINDOW_HANDLE_INVALID; }
    Handle handle() const noexcept { return handle_; }

    int requestClose() noexcept {
        if (!valid()) return RIN_ERROR_STALE_HANDLE;
        const int result = wnd_close_async(handle_);
        if (result == RIN_RESULT_OK) handle_ = RIN_WINDOW_HANDLE_INVALID;
        return result;
    }
    void show(bool visible = true) noexcept {
        (void)requestShow(visible);
    }
    int requestShow(bool visible = true) noexcept {
        return valid() ? wnd_show_async(handle_, visible ? 1 : 0)
                       : RIN_ERROR_STALE_HANDLE;
    }
    void setTitle(const char* title) noexcept {
        (void)requestTitle(title);
    }
    int requestTitle(const char* title) noexcept {
        return valid() ? wnd_title_async(handle_, title)
                       : RIN_ERROR_STALE_HANDLE;
    }
    void setIconPath(const char* path) noexcept {
        (void)requestIconPath(path);
    }
    int requestIconPath(const char* path) noexcept {
        return valid() ? wnd_set_icon_path(handle_, path)
                       : RIN_ERROR_STALE_HANDLE;
    }
    void move(std::int32_t x, std::int32_t y) noexcept {
        (void)requestMove(x, y);
    }
    int requestMove(std::int32_t x, std::int32_t y) noexcept {
        return valid() ? wnd_move_async(handle_, x, y)
                       : RIN_ERROR_STALE_HANDLE;
    }
    void resize(std::int32_t width, std::int32_t height) noexcept {
        (void)requestResize(width, height);
    }
    int requestResize(std::int32_t width, std::int32_t height) noexcept {
        return valid() ? wnd_resize_async(handle_, width, height)
                       : RIN_ERROR_STALE_HANDLE;
    }

    int setWindowState(std::uint32_t state, std::uint32_t workspace = 0) noexcept {
        return valid() ? wnd_set_window_state(handle_, state, workspace)
                       : RIN_ERROR_STALE_HANDLE;
    }
    int setPointerCapture(bool enabled) noexcept {
        return valid() ? wnd_set_pointer_capture(handle_, enabled ? 1 : 0)
                       : RIN_ERROR_STALE_HANDLE;
    }
    int setKeyboardGrab(bool enabled) noexcept {
        return valid() ? wnd_set_keyboard_grab(handle_, enabled ? 1 : 0)
                       : RIN_ERROR_STALE_HANDLE;
    }
    int setModal(bool enabled) noexcept {
        return valid() ? wnd_set_modal(handle_, enabled ? 1 : 0)
                       : RIN_ERROR_STALE_HANDLE;
    }
    int setCursor(std::uint32_t cursor) noexcept {
        return valid() ? wnd_set_cursor(handle_, cursor) : RIN_ERROR_STALE_HANDLE;
    }
    bool focused() const noexcept {
        return valid() && wnd_is_focused(handle_) != 0;
    }
    int reconnectCompositor() noexcept {
        return wnd_reconnect_compositor();
    }

    WindowSize size() const noexcept {
        WindowSize result;
        if (valid()) (void)wnd_get_size(handle_, &result.width, &result.height);
        return result;
    }
    WindowPosition position() const noexcept {
        WindowPosition result;
        if (valid()) (void)wnd_get_position(handle_, &result.x, &result.y);
        return result;
    }

    int poll(WindowEvent* event) const noexcept {
        if (!valid() || !event) return RIN_ERROR_INVALID_ARGUMENT;
        RinGuiNativeEventV1 native{};
        std::uint32_t packed = 0u;
        const int result = wnd_poll_native(handle_, &native, &packed);
        if (result <= 0) return result;
        RinWindowEventV1 abi{};
        if (!rin_window_event_from_native(&native, &abi)) return 0;
        return decodeWindowEvent(abi, event) ? 1 : RIN_ERROR_ABI_MISMATCH;
    }

    int dispatch() const noexcept {
        WindowEvent event;
        const int result = poll(&event);
        if (result > 0 && event_handler_) return event_handler_(event) ? 1 : 0;
        return result;
    }

    void onEvent(EventHandler handler) { event_handler_ = std::move(handler); }
    void onCompositorCompletion(CompletionHandler handler) {
        completion_handler_ = std::move(handler);
        updateCompletionCallback();
    }
    void onPaint(PaintHandler handler) {
        paint_handler_no_args_ = {};
        paint_handler_ = std::move(handler);
    }
    void onPaint(PaintHandlerNoArgs handler) {
        paint_handler_ = {};
        paint_handler_no_args_ = std::move(handler);
    }

    int paint() noexcept {
        if (!valid() || (!paint_handler_ && !paint_handler_no_args_))
            return RIN_ERROR_INVALID_ARGUMENT;
        const int begin_result = beginNativeFrame(handle_);
        if (begin_result != RIN_SUCCESS) return begin_result;
        AqSurface* surface = currentRenderSurface();
        if (!surface) {
            (void)endNativeFrame();
            return RIN_ERROR_ABI_MISMATCH;
        }
        if (paint_handler_) paint_handler_(*surface);
        if (paint_handler_no_args_) paint_handler_no_args_();
        return endNativeFrame();
    }

    void close() noexcept {
        if (!valid()) return;
        wnd_close(handle_);
        handle_ = RIN_WINDOW_HANDLE_INVALID;
    }

private:
    static void dispatchCompletion(
        const RinRuntimeGuiCompletionV1* completion, void* context) {
        auto* window = static_cast<Window*>(context);
        if (window && completion && window->completion_handler_)
            window->completion_handler_(*completion);
    }

    void updateCompletionCallback() noexcept {
        if (valid()) {
            (void)wnd_set_compositor_completion_callback(
                handle_, completion_handler_ ? &Window::dispatchCompletion : nullptr,
                completion_handler_ ? this : nullptr);
        }
    }

    Handle handle_ = RIN_WINDOW_HANDLE_INVALID;
    EventHandler event_handler_;
    PaintHandler paint_handler_;
    PaintHandlerNoArgs paint_handler_no_args_;
    CompletionHandler completion_handler_;
};

} // namespace RinRuntime
