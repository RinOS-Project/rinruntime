/* SPDX-License-Identifier: MIT */
/* Implementation of the opaque, thread-local public render context. */
#include <rinruntime/render_context.hpp>

#include <aquamarine.h>
#include <rin/runtime.h>
#include <stdlib.h>
#include <string.h>

namespace RinRuntime {
namespace {

struct RenderContextState {
    RinRuntimeGuiHandle handle = RIN_WINDOW_HANDLE_INVALID;
    RinRenderTarget target{};
    AqSurface surface{};
    AqRect clips[RIN_COMPOSITOR_MAX_CLIP_RECTS]{};
    std::uint32_t clip_depth = 0u;
    bool active = false;
    float scale = 0.0f;
};

thread_local RenderContextState g_context;
std::uint32_t g_system_ui_font_state = 0u;
const AqFont* g_system_ui_font = nullptr;
SystemUiFontLoaderFunction g_system_ui_font_loader = nullptr;
void* g_system_ui_font_loader_context = nullptr;

void* aquamarineAllocate(unsigned size) {
    return malloc(size);
}

void aquamarineFree(void* pointer) {
    free(pointer);
}

const AqFont* loadSystemUiFont() noexcept {
    aq_set_allocator(aquamarineAllocate, aquamarineFree);
    if (g_system_ui_font_loader != nullptr)
        g_system_ui_font =
            g_system_ui_font_loader(g_system_ui_font_loader_context);
    if (g_system_ui_font) {
        aq_set_default_font(g_system_ui_font);
        rin_log("[rinruntime] locale UI font loaded\n");
        return g_system_ui_font;
    }
    aq_set_default_font(aq_font_builtin_8x16());
    rin_log("[rinruntime] UI font resources unavailable; using ASCII font\n");
    return aq_font_builtin_8x16();
}

void clearContext() noexcept {
    g_context = RenderContextState{};
}

} // namespace

int setSystemUiFontLoader(SystemUiFontLoaderFunction loader,
                          void* context) noexcept {
    if (__atomic_load_n(&g_system_ui_font_state, __ATOMIC_ACQUIRE) != 0u)
        return RIN_ERROR_BUSY;
    g_system_ui_font_loader = loader;
    g_system_ui_font_loader_context = context;
    return RIN_SUCCESS;
}

AqSurface* currentRenderSurface() noexcept {
    return g_context.active ? &g_context.surface : nullptr;
}

const AqFont* currentRenderFont() noexcept {
    return g_context.active ? systemUiFont() : nullptr;
}

const AqFont* systemUiFont() noexcept {
    std::uint32_t state = __atomic_load_n(&g_system_ui_font_state,
                                          __ATOMIC_ACQUIRE);
    if (state == 2u)
        return g_system_ui_font ? g_system_ui_font : aq_font_builtin_8x16();
    if (state == 0u) {
        std::uint32_t expected = 0u;
        if (__atomic_compare_exchange_n(&g_system_ui_font_state, &expected,
                                        1u, false, __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE)) {
            const AqFont* font = loadSystemUiFont();
            __atomic_store_n(&g_system_ui_font_state, 2u, __ATOMIC_RELEASE);
            return font;
        }
    }
    /* A concurrent first paint may use the built-in ASCII font for this
     * frame. It never blocks another UI thread on filesystem I/O. */
    return aq_font_builtin_8x16();
}

RinRuntimeGuiHandle currentRenderWindow() noexcept {
    return g_context.active ? g_context.handle : RIN_WINDOW_HANDLE_INVALID;
}

std::int32_t currentFrameWidth() noexcept {
    return g_context.active ? g_context.surface.width : 0;
}

std::int32_t currentFrameHeight() noexcept {
    return g_context.active ? g_context.surface.height : 0;
}

float currentFrameScale() noexcept {
    return g_context.active ? g_context.scale : 0.0f;
}

bool currentFrameValid() noexcept {
    return g_context.active;
}

int beginNativeFrame(RinRuntimeGuiHandle handle) noexcept {
    RinRenderTarget target{};
    if (g_context.active) return RIN_ERROR_BUSY;
    if (handle == RIN_WINDOW_HANDLE_INVALID) return RIN_ERROR_STALE_HANDLE;
    const int acquire_result = wnd_acquire_render_target(handle, &target);
    if (acquire_result != RIN_SUCCESS) return acquire_result;
    RenderContextState next{};
    next.handle = handle;
    next.target = target;
    if (aq_surface_init_from_rin_render_target(&next.surface, &next.target) != 0) {
        (void)wnd_release_render_target(handle, &target);
        return RIN_ERROR_ABI_MISMATCH;
    }
    next.clips[0] = next.surface.clip;
    next.clip_depth = 1u;
    next.active = true;
    (void)systemUiFont();
    /* RinRenderTarget intentionally carries physical pixel geometry only;
     * until a scaled target descriptor is introduced, logical and physical
     * frame units are identical. */
    next.scale = 1.0f;
    g_context = next;
    return RIN_SUCCESS;
}

int endNativeFrame() noexcept {
    if (!g_context.active) return RIN_ERROR_BUSY;
    const int release_result =
        wnd_release_render_target(g_context.handle, &g_context.target);
    const int present_result = release_result == RIN_SUCCESS
        ? wnd_present(g_context.handle)
        : release_result;
    clearContext();
    return present_result;
}

int pushRenderClip(std::int32_t x, std::int32_t y,
                   std::int32_t width, std::int32_t height) noexcept {
    if (!g_context.active || width <= 0 || height <= 0)
        return RIN_ERROR_INVALID_ARGUMENT;
    if (g_context.clip_depth >= RIN_COMPOSITOR_MAX_CLIP_RECTS)
        return RIN_ERROR_BUSY;
    const AqRect requested{x, y, width, height};
    const AqRect parent = g_context.clips[g_context.clip_depth - 1u];
    const AqRect clipped = aq_rect_intersect(parent, requested);
    g_context.clips[g_context.clip_depth] = clipped;
    ++g_context.clip_depth;
    aq_surface_set_clip(&g_context.surface, clipped);
    return RIN_SUCCESS;
}

int popRenderClip() noexcept {
    if (!g_context.active || g_context.clip_depth <= 1u)
        return RIN_ERROR_INVALID_ARGUMENT;
    --g_context.clip_depth;
    aq_surface_set_clip(&g_context.surface,
                        g_context.clips[g_context.clip_depth - 1u]);
    return RIN_SUCCESS;
}

int readRenderPixel(std::int32_t x, std::int32_t y,
                    std::uint32_t* color) noexcept {
    if (!g_context.active || !color) return RIN_ERROR_INVALID_ARGUMENT;
    if (x < 0 || y < 0 || x >= g_context.surface.width ||
        y >= g_context.surface.height)
        return RIN_ERROR_INVALID_ARGUMENT;
    *color = aq_color_to_argb32(aq_get_pixel(&g_context.surface, x, y));
    return RIN_SUCCESS;
}

ScopedRenderClip::ScopedRenderClip(std::int32_t x, std::int32_t y,
                                   std::int32_t width,
                                   std::int32_t height) noexcept
    : active_(pushRenderClip(x, y, width, height) == RIN_SUCCESS) {}

ScopedRenderClip::~ScopedRenderClip() noexcept {
    if (active_) (void)popRenderClip();
}

} // namespace RinRuntime
