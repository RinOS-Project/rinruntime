/* SPDX-License-Identifier: MIT */
#include "rin_desktop_model.h"

#include <string.h>

#define SETTINGS_MAGIC UINT32_C(0x44535431) /* DST1 */
#define SETTINGS_CRC_SIZE ((uint32_t)sizeof(uint32_t))

static uint32_t settings_crc32(const uint8_t* bytes, uint32_t size)
{
    uint32_t crc = UINT32_MAX;
    uint32_t index;
    if (!bytes && size != 0u) return 0u;
    for (index = 0u; index < size; ++index) {
        uint32_t bit;
        crc ^= bytes[index];
        for (bit = 0u; bit < 8u; ++bit)
            crc = (crc >> 1u) ^
                  (UINT32_C(0xedb88320) & (uint32_t)-(int32_t)(crc & 1u));
    }
    return crc ^ UINT32_MAX;
}

static void copy_text(char* dst, uint32_t capacity, const char* src)
{
    uint32_t i = 0u;
    if (!dst || capacity == 0u) return;
    if (src) while (i + 1u < capacity && src[i]) {
        unsigned char c = (unsigned char)src[i];
        dst[i++] = c < 0x20u && c != '\t' ? '?' : (char)c;
    }
    dst[i] = '\0';
}

static int bounded_text(const char* text, uint32_t capacity)
{
    uint32_t i;
    if (!text || capacity == 0u) return 0;
    for (i = 0u; i < capacity; ++i) {
        unsigned char c = (unsigned char)text[i];
        if (c == '\0') return 1;
        if (c < 0x20u && c != '\t') return 0;
    }
    return 0;
}

static int tray_item_valid(const RinDesktopTrayItem* item)
{
    RinTrayItemDescriptorV1 descriptor;
    if (!item || item->version != RIN_TRAY_PROTOCOL_VERSION ||
        item->reserved != 0u || item->reserved_action != 0u ||
        item->menu_count > RIN_TRAY_MAX_MENU_ITEMS ||
        !bounded_text(item->label, RIN_DESKTOP_LABEL_MAX) ||
        !bounded_text(item->tooltip, RIN_DESKTOP_NAME_MAX) ||
        !bounded_text(item->icon_path, RIN_DESKTOP_PATH_MAX) ||
        !bounded_text(item->activation, RIN_DESKTOP_LABEL_MAX) ||
        !bounded_text(item->context_menu, RIN_DESKTOP_LABEL_MAX)) return 0;
    memset(&descriptor, 0, sizeof(descriptor));
    descriptor.struct_size = sizeof(descriptor);
    descriptor.version = RIN_TRAY_PROTOCOL_VERSION;
    descriptor.flags = item->flags & RIN_DESKTOP_TRAY_ATTENTION
        ? RIN_TRAY_ITEM_ATTENTION : 0u;
    descriptor.badge = item->badge;
    descriptor.menu_count = item->menu_count;
    memcpy(descriptor.label, item->label, sizeof(item->label));
    memcpy(descriptor.tooltip, item->tooltip, sizeof(item->tooltip));
    memcpy(descriptor.icon_resource, item->icon_path, sizeof(item->icon_path));
    descriptor.activation_action_id = item->activation_action_id;
    if (item->menu_count) memcpy(descriptor.menu, item->menu,
                                 sizeof(item->menu[0]) * item->menu_count);
    return rin_tray_descriptor_valid(&descriptor);
}

static int text_equal(const char* a, const char* b)
{
    uint32_t i = 0u;
    if (!a || !b) return 0;
    while (a[i] && b[i]) {
        unsigned char left = (unsigned char)a[i];
        unsigned char right = (unsigned char)b[i];
        if (left >= 'A' && left <= 'Z') left = (unsigned char)(left + 32u);
        if (right >= 'A' && right <= 'Z') right = (unsigned char)(right + 32u);
        if (left != right) return 0;
        ++i;
    }
    return a[i] == '\0' && b[i] == '\0';
}

static uint64_t identity_id(const char* text)
{
    uint64_t hash = UINT64_C(1469598103934665603);
    uint32_t i;
    if (!text || !text[0]) return 0u;
    for (i = 0u; text[i]; ++i) {
        unsigned char c = (unsigned char)text[i];
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + 32u);
        hash ^= c;
        hash *= UINT64_C(1099511628211);
    }
    return hash ? hash : 1u;
}

static uint64_t window_identity(const RinDesktopWindow* window)
{
    if (!window) return 0u;
    return window->app_identity_id ? window->app_identity_id :
           identity_id(window->app_identity);
}

static int pin_index(const RinDesktopModel* model, uint64_t id)
{
    uint32_t i;
    for (i = 0u; i < model->pin_count; ++i)
        if (model->pins[i].app_identity_id == id) return (int)i;
    return -1;
}

static int task_index(const RinDesktopModel* model, uint64_t id)
{
    uint32_t i;
    for (i = 0u; i < model->task_count; ++i)
        if (model->tasks[i].app_identity_id == id) return (int)i;
    return -1;
}

static int tray_preference_index(const RinDesktopModel* model,
                                 uint64_t session_id, uint64_t id)
{
    uint32_t i;
    if (!model || !id) return -1;
    for (i = 0u; i < model->tray_preference_count; ++i)
        if (model->tray_preferences[i].app_identity_id == id &&
            model->tray_preferences[i].session_id == session_id) return (int)i;
    return -1;
}

static int tray_preference_lookup(const RinDesktopModel* model,
                                  uint64_t session_id, uint64_t id)
{
    int index = tray_preference_index(model, session_id, id);
    if (index < 0 && session_id != 0u)
        index = tray_preference_index(model, 0u, id);
    return index;
}

static uint32_t tray_preference_flags(const RinDesktopModel* model,
                                      uint64_t session_id, uint64_t id)
{
    const int index = tray_preference_lookup(model, session_id, id);
    return index < 0 ? 0u : model->tray_preferences[index].flags;
}

static int tray_is_visible_candidate(const RinDesktopTrayItem* item)
{
    if (!item || (item->flags & RIN_DESKTOP_TRAY_ALWAYS_OVERFLOW) != 0u)
        return 0;
    if ((item->flags & RIN_DESKTOP_TRAY_HIDE_WHEN_INACTIVE) != 0u &&
        (item->flags & RIN_DESKTOP_TRAY_ATTENTION) == 0u)
        return 0;
    return (item->flags & RIN_DESKTOP_TRAY_BACKGROUND) == 0u;
}

static void add_task_from_pin(RinDesktopModel* model, const RinDesktopPin* pin)
{
    RinDesktopTaskItem* task;
    if (model->task_count >= RIN_DESKTOP_MAX_TASK_ITEMS || !pin) return;
    task = &model->tasks[model->task_count++];
    memset(task, 0, sizeof(*task));
    task->app_identity_id = pin->app_identity_id;
    task->flags = RIN_DESKTOP_TASK_PINNED | RIN_DESKTOP_TASK_LAUNCH_PENDING;
    task->progress = UINT32_MAX;
    copy_text(task->app_identity, sizeof(task->app_identity), pin->app_identity);
    copy_text(task->name, sizeof(task->name), pin->name);
    copy_text(task->icon_path, sizeof(task->icon_path), pin->icon_path);
}

static void add_task_from_window(RinDesktopModel* model,
                                 const RinDesktopWindow* window)
{
    uint64_t id = window_identity(window);
    int index = task_index(model, id);
    RinDesktopTaskItem* task;
    if (!window || id == 0u) return;
    if (index < 0) {
        if (model->task_count >= RIN_DESKTOP_MAX_TASK_ITEMS) return;
        index = (int)model->task_count++;
        task = &model->tasks[index];
        memset(task, 0, sizeof(*task));
        task->app_identity_id = id;
        task->progress = UINT32_MAX;
    } else {
        task = &model->tasks[index];
    }
    task->flags |= RIN_DESKTOP_TASK_RUNNING;
    task->flags &= ~RIN_DESKTOP_TASK_LAUNCH_PENDING;
    if (window->flags & RIN_DESKTOP_WINDOW_ACTIVE)
        task->flags |= RIN_DESKTOP_TASK_ACTIVE;
    if (window->flags & RIN_DESKTOP_WINDOW_ATTENTION)
        task->flags |= RIN_DESKTOP_TASK_ATTENTION;
    if (window->flags & RIN_DESKTOP_WINDOW_CRASHED)
        task->flags |= RIN_DESKTOP_TASK_CRASHED;
    if (window->state & RIN_DESKTOP_WINDOW_MINIMIZED)
        task->flags |= RIN_DESKTOP_TASK_MINIMIZED;
    if (task->window_count < RIN_DESKTOP_MAX_GROUP_WINDOWS)
        task->window_ids[task->window_count++] = window->surface_id;
    if (task->window_count > 1u) task->flags |= RIN_DESKTOP_TASK_MULTIPLE;
    if (!task->name[0]) copy_text(task->name, sizeof(task->name), window->title);
    if (!task->icon_path[0])
        copy_text(task->icon_path, sizeof(task->icon_path), window->icon_path);
    if (!task->app_identity[0])
        copy_text(task->app_identity, sizeof(task->app_identity),
                  window->app_identity);
}

static void rebuild_tasks(RinDesktopModel* model)
{
    uint32_t i;
    memset(model->tasks, 0, sizeof(model->tasks));
    model->task_count = 0u;
    for (i = 0u; i < model->pin_count; ++i) add_task_from_pin(model, &model->pins[i]);
    for (i = 0u; i < model->window_count; ++i)
        add_task_from_window(model, &model->windows[i]);
}

typedef struct RinDesktopSettingsV1 {
    uint32_t version;
    uint32_t flags;
    uint8_t taskbar_visible;
    uint8_t tray_visible;
    uint8_t auto_hide;
    uint8_t show_on_all_outputs;
    uint8_t clock_24_hour;
    uint8_t dnd;
    uint8_t notification_privacy;
    uint8_t reserved;
    uint32_t position;
    uint32_t output_mode;
    uint32_t theme_id;
    uint32_t reduced_motion;
    uint32_t high_contrast;
    uint32_t reduced_transparency;
    uint32_t system_icon_visibility;
    uint32_t tray_policy;
} RinDesktopSettingsV1;

void rin_desktop_model_init(RinDesktopModel* model)
{
    if (!model) return;
    memset(model, 0, sizeof(*model));
    model->version = RIN_DESKTOP_MODEL_VERSION;
    model->settings.version = RIN_DESKTOP_MODEL_VERSION;
    model->settings.taskbar_visible = 1u;
    model->settings.tray_visible = 1u;
    model->settings.clock_24_hour = 1u;
    model->settings.taskbar_use_accent_color = 1u;
    model->settings.taskbar_transparency_percent = 80u;
    model->settings.taskbar_corner_radius_px = 8u;
    model->settings.notification_privacy = RIN_DESKTOP_NOTIFICATION_HIDE_BACKGROUND;
    model->settings.position = RIN_DESKTOP_TASKBAR_BOTTOM;
    model->settings.output_mode = RIN_DESKTOP_OUTPUT_PRIMARY_ONLY;
    model->settings.theme_id = 0u;
    model->settings.system_icon_visibility = RIN_DESKTOP_SYSTEM_ICON_ALL;
    model->settings.tray_policy =
        RIN_DESKTOP_TRAY_POLICY_SHOW_OVERFLOW_BUTTON;
    model->next_notification_id = 1u;
    model->next_tray_id = 1u;
}

int rin_desktop_model_set_windows(RinDesktopModel* model,
                                  const RinDesktopWindow* windows,
                                  uint32_t count)
{
    uint32_t index;
    if (!model || count > RIN_DESKTOP_MAX_WINDOWS || (count && !windows)) return -1;
    for (index = 0u; index < count; ++index)
        if (windows[index].surface_id == 0u ||
            (windows[index].app_identity_id == 0u &&
             !windows[index].app_identity[0]) ||
            !bounded_text(windows[index].app_identity, RIN_DESKTOP_IDENTITY_MAX) ||
            !bounded_text(windows[index].title, RIN_DESKTOP_NAME_MAX) ||
            !bounded_text(windows[index].icon_path, RIN_DESKTOP_PATH_MAX)) return -1;
    if (count) memcpy(model->windows, windows, count * sizeof(*windows));
    model->window_count = count;
    rebuild_tasks(model);
    ++model->generation;
    return 0;
}

int rin_desktop_model_pin(RinDesktopModel* model, const RinDesktopPin* pin)
{
    RinDesktopPin copy;
    if (!model || !pin || pin->app_identity_id == 0u ||
        !bounded_text(pin->app_identity, RIN_DESKTOP_IDENTITY_MAX) ||
        !bounded_text(pin->name, RIN_DESKTOP_NAME_MAX) ||
        !bounded_text(pin->executable_path, RIN_DESKTOP_PATH_MAX) ||
        !bounded_text(pin->icon_path, RIN_DESKTOP_PATH_MAX) ||
        pin_index(model, pin->app_identity_id) >= 0) return -1;
    if (model->pin_count >= RIN_DESKTOP_MAX_PINS) return -2;
    copy = *pin;
    copy_text(copy.app_identity, sizeof(copy.app_identity), pin->app_identity);
    copy_text(copy.name, sizeof(copy.name), pin->name);
    copy_text(copy.executable_path, sizeof(copy.executable_path), pin->executable_path);
    copy_text(copy.icon_path, sizeof(copy.icon_path), pin->icon_path);
    model->pins[model->pin_count++] = copy;
    rebuild_tasks(model);
    ++model->generation;
    return 0;
}

int rin_desktop_model_unpin(RinDesktopModel* model, uint64_t id)
{
    int index;
    uint32_t i;
    if (!model || id == 0u || (index = pin_index(model, id)) < 0) return -1;
    for (i = (uint32_t)index + 1u; i < model->pin_count; ++i)
        model->pins[i - 1u] = model->pins[i];
    --model->pin_count;
    rebuild_tasks(model);
    ++model->generation;
    return 0;
}

int rin_desktop_model_reorder_pin(RinDesktopModel* model, uint32_t from,
                                  uint32_t to)
{
    RinDesktopPin moved;
    uint32_t i;
    if (!model || from >= model->pin_count || to >= model->pin_count) return -1;
    if (from == to) return 0;
    moved = model->pins[from];
    if (from < to) for (i = from; i < to; ++i) model->pins[i] = model->pins[i + 1u];
    else for (i = from; i > to; --i) model->pins[i] = model->pins[i - 1u];
    model->pins[to] = moved;
    rebuild_tasks(model);
    ++model->generation;
    return 0;
}

int rin_desktop_model_remove_stale_pins(RinDesktopModel* model)
{
    uint32_t read = 0u, write = 0u;
    int removed = 0;
    if (!model) return -1;
    for (read = 0u; read < model->pin_count; ++read) {
        int stale = 0;
        uint32_t app;
        for (app = 0u; app < model->app_count; ++app)
            if (model->apps[app].app_identity_id == model->pins[read].app_identity_id)
                stale = (model->apps[app].flags & 2u) != 0u;
        if (stale) { removed = 1; continue; }
        model->pins[write++] = model->pins[read];
    }
    if (removed) { model->pin_count = write; rebuild_tasks(model); ++model->generation; }
    return removed;
}

int rin_desktop_model_task_action(const RinDesktopModel* model, uint32_t index)
{
    const RinDesktopTaskItem* item;
    if (!model || index >= model->task_count) return RIN_DESKTOP_TASK_ACTION_NONE;
    item = &model->tasks[index];
    if (!(item->flags & RIN_DESKTOP_TASK_RUNNING)) return RIN_DESKTOP_TASK_ACTION_LAUNCH;
    if (item->window_count > 1u) return RIN_DESKTOP_TASK_ACTION_SELECT_WINDOWS;
    if (item->flags & RIN_DESKTOP_TASK_MINIMIZED) return RIN_DESKTOP_TASK_ACTION_RESTORE;
    if (item->flags & RIN_DESKTOP_TASK_ACTIVE) return RIN_DESKTOP_TASK_ACTION_MINIMIZE;
    return RIN_DESKTOP_TASK_ACTION_ACTIVATE;
}

int rin_desktop_model_context_action(const RinDesktopModel* model,
                                     uint32_t index, uint32_t action)
{
    const RinDesktopTaskItem* item;
    if (!model || index >= model->task_count) return 0;
    item = &model->tasks[index];
    switch (action) {
        case RIN_DESKTOP_CONTEXT_OPEN:
        case RIN_DESKTOP_CONTEXT_NEW_WINDOW:
            return 1;
        case RIN_DESKTOP_CONTEXT_CLOSE_WINDOW:
        case RIN_DESKTOP_CONTEXT_CLOSE_ALL_WINDOWS:
            return (item->flags & RIN_DESKTOP_TASK_RUNNING) != 0u;
        case RIN_DESKTOP_CONTEXT_PIN:
            return (item->flags & RIN_DESKTOP_TASK_PINNED) == 0u;
        case RIN_DESKTOP_CONTEXT_UNPIN:
            return (item->flags & RIN_DESKTOP_TASK_PINNED) != 0u;
        default:
            return 0;
    }
}

int rin_desktop_model_set_task_visual_state(RinDesktopModel* model,
                                            uint32_t index, uint32_t flags,
                                            uint32_t progress, uint32_t badge)
{
    if (!model || index >= model->task_count ||
        (flags & ~(RIN_DESKTOP_TASK_HOVER | RIN_DESKTOP_TASK_PRESSED |
                   RIN_DESKTOP_TASK_KEYBOARD_FOCUS | RIN_DESKTOP_TASK_ATTENTION |
                   RIN_DESKTOP_TASK_CRASHED)) != 0u ||
        (progress > 1000u && progress != UINT32_MAX))
        return -1;
    model->tasks[index].flags = (model->tasks[index].flags &
        ~(RIN_DESKTOP_TASK_HOVER | RIN_DESKTOP_TASK_PRESSED |
          RIN_DESKTOP_TASK_KEYBOARD_FOCUS | RIN_DESKTOP_TASK_ATTENTION |
          RIN_DESKTOP_TASK_CRASHED)) | flags;
    model->tasks[index].progress = progress;
    model->tasks[index].badge = badge;
    ++model->generation;
    return 0;
}

int rin_desktop_model_add_app(RinDesktopModel* model, const RinDesktopApp* app)
{
    uint32_t i;
    if (!model || !app || app->app_identity_id == 0u ||
        !bounded_text(app->app_identity, RIN_DESKTOP_IDENTITY_MAX) ||
        !bounded_text(app->name, RIN_DESKTOP_NAME_MAX) ||
        !bounded_text(app->localized_name, RIN_DESKTOP_NAME_MAX) ||
        !bounded_text(app->executable_path, RIN_DESKTOP_PATH_MAX) ||
        !bounded_text(app->icon_path, RIN_DESKTOP_PATH_MAX)) return -1;
    for (i = 0u; i < model->app_count; ++i)
        if (model->apps[i].app_identity_id == app->app_identity_id) {
            model->apps[i] = *app;
            return 0;
        }
    if (model->app_count >= RIN_DESKTOP_MAX_APPS) return -2;
    model->apps[model->app_count] = *app;
    copy_text(model->apps[model->app_count].app_identity,
              RIN_DESKTOP_IDENTITY_MAX, app->app_identity);
    copy_text(model->apps[model->app_count].name, RIN_DESKTOP_NAME_MAX, app->name);
    copy_text(model->apps[model->app_count].localized_name, RIN_DESKTOP_NAME_MAX, app->localized_name);
    copy_text(model->apps[model->app_count].executable_path,
              RIN_DESKTOP_PATH_MAX, app->executable_path);
    copy_text(model->apps[model->app_count].icon_path,
              RIN_DESKTOP_PATH_MAX, app->icon_path);
    ++model->app_count;
    return 0;
}

int rin_desktop_model_mark_app_stale(RinDesktopModel* model, uint64_t id, int stale)
{
    uint32_t i;
    if (!model || id == 0u) return -1;
    for (i = 0u; i < model->app_count; ++i)
        if (model->apps[i].app_identity_id == id) {
            if (stale) model->apps[i].flags |= 2u;
            else model->apps[i].flags &= ~2u;
            return 0;
        }
    return -1;
}

static int fuzzy_match(const char* text, const char* query)
{
    uint32_t i = 0u, j = 0u;
    if (!query || !query[0]) return 1;
    if (!text) return 0;
    while (text[i] && query[j]) {
        unsigned char a = (unsigned char)text[i++];
        unsigned char b = (unsigned char)query[j];
        if (a >= 'A' && a <= 'Z') a = (unsigned char)(a + 32u);
        if (b >= 'A' && b <= 'Z') b = (unsigned char)(b + 32u);
        if (a == b) ++j;
    }
    return query[j] == '\0';
}

uint32_t rin_desktop_model_search(RinDesktopModel* model, const char* query, int fuzzy)
{
    uint32_t i;
    if (!model) return 0u;
    model->launcher_match_count = 0u;
    for (i = 0u; i < model->app_count; ++i) {
        RinDesktopApp* app = &model->apps[i];
        if ((app->flags & 2u) != 0u) continue;
        if ((fuzzy ? (fuzzy_match(app->name, query) || fuzzy_match(app->localized_name, query))
                   : (text_equal(app->name, query) || text_equal(app->localized_name, query) ||
                      (query && strstr(app->name, query) != NULL))) == 0) continue;
        if (model->launcher_match_count < RIN_DESKTOP_MAX_APPS)
            model->launcher_matches[model->launcher_match_count++] = i;
    }
    model->launcher_selection = 0u;
    return model->launcher_match_count;
}

int rin_desktop_model_record_launch(RinDesktopModel* model, uint64_t id, uint64_t now_ms)
{
    uint32_t i;
    if (!model || id == 0u) return -1;
    for (i = 0u; i < model->app_count; ++i)
        if (model->apps[i].app_identity_id == id) {
            ++model->apps[i].launch_count;
            model->apps[i].last_used_ms = now_ms;
            return 0;
        }
    return -1;
}

int rin_desktop_model_register_tray(RinDesktopModel* model, const RinDesktopTrayItem* item,
                                    uint64_t session_id, uint64_t app_id, uint64_t* id)
{
    RinDesktopTrayItem copy;
    if (!model || !item || session_id == 0u || app_id == 0u ||
        model->tray_count >= RIN_DESKTOP_MAX_TRAY_ITEMS ||
        !tray_item_valid(item)) return -1;
    copy = *item;
    copy.item_id = model->next_tray_id++;
    if (!copy.item_id) copy.item_id = model->next_tray_id++;
    copy.session_id = session_id;
    copy.app_identity_id = app_id;
    if ((tray_preference_flags(model, session_id, app_id) &
         RIN_DESKTOP_TRAY_PREF_ALWAYS_OVERFLOW) != 0u)
        copy.flags |= RIN_DESKTOP_TRAY_ALWAYS_OVERFLOW;
    if ((tray_preference_flags(model, session_id, app_id) &
         RIN_DESKTOP_TRAY_PREF_HIDE_WHEN_INACTIVE) != 0u)
        copy.flags |= RIN_DESKTOP_TRAY_HIDE_WHEN_INACTIVE;
    model->tray[model->tray_count++] = copy;
    {
        const int preference = tray_preference_lookup(model, session_id, app_id);
        if (preference >= 0 && model->tray_preferences[preference].order <
                model->tray_count - 1u) {
            uint32_t target = model->tray_preferences[preference].order;
            RinDesktopTrayItem moved = model->tray[model->tray_count - 1u];
            uint32_t cursor;
            for (cursor = model->tray_count - 1u; cursor > target; --cursor)
                model->tray[cursor] = model->tray[cursor - 1u];
            model->tray[target] = moved;
        }
    }
    if (id) *id = copy.item_id;
    ++model->generation;
    return 0;
}

int rin_desktop_model_update_tray(RinDesktopModel* model, const RinDesktopTrayItem* item, uint64_t session_id)
{
    uint32_t i;
    if (!model || !item || !session_id || !item->item_id) return -1;
    for (i = 0u; i < model->tray_count; ++i)
        if (model->tray[i].item_id == item->item_id && model->tray[i].session_id == session_id) {
            RinDesktopTrayItem replacement = *item;
            replacement.session_id = session_id;
            replacement.app_identity_id = model->tray[i].app_identity_id;
            replacement.owner_process_id = model->tray[i].owner_process_id;
            replacement.owner_instance_cookie = model->tray[i].owner_instance_cookie;
            replacement.owner_connection_id = model->tray[i].owner_connection_id;
            replacement.flags = (replacement.flags &
                                 ~(RIN_DESKTOP_TRAY_ALWAYS_OVERFLOW |
                                   RIN_DESKTOP_TRAY_HIDE_WHEN_INACTIVE)) |
                (model->tray[i].flags &
                 (RIN_DESKTOP_TRAY_ALWAYS_OVERFLOW |
                  RIN_DESKTOP_TRAY_HIDE_WHEN_INACTIVE));
            model->tray[i] = replacement;
            ++model->generation;
            return 0;
        }
    return -1;
}

int rin_desktop_model_remove_tray_owner(RinDesktopModel* model,
                                        uint64_t session_id,
                                        uint64_t app_identity_id,
                                        uint64_t process_id,
                                        uint64_t instance_cookie,
                                        uint64_t connection_id)
{
    uint32_t i = 0u, j;
    uint32_t removed = 0u;
    if (!model || !session_id || !app_identity_id || !process_id ||
        !instance_cookie || !connection_id) return -1;
    while (i < model->tray_count) {
        RinDesktopTrayItem* item = &model->tray[i];
        if (item->session_id != session_id || item->app_identity_id != app_identity_id ||
            item->owner_process_id != process_id ||
            item->owner_instance_cookie != instance_cookie ||
            item->owner_connection_id != connection_id) {
            ++i;
            continue;
        }
        for (j = i + 1u; j < model->tray_count; ++j)
            model->tray[j - 1u] = model->tray[j];
        --model->tray_count;
        removed = 1u;
    }
    if (removed) ++model->generation;
    return removed ? 0 : -1;
}

int rin_desktop_model_remove_tray_session(RinDesktopModel* model,
                                          uint64_t session_id)
{
    uint32_t read_index = 0u;
    uint32_t write_index = 0u;
    if (!model || session_id == 0u) return -1;
    while (read_index < model->tray_count) {
        const RinDesktopTrayItem* item = &model->tray[read_index++];
        if (item->session_id == session_id) continue;
        if (write_index != read_index - 1u)
            model->tray[write_index] = *item;
        ++write_index;
    }
    if (write_index == model->tray_count) return -1;
    model->tray_count = write_index;
    ++model->generation;
    return 0;
}

int rin_desktop_model_set_tray_visual_state(RinDesktopModel* model,
                                            uint64_t item_id, uint32_t flags)
{
    uint32_t i;
    const uint32_t allowed = RIN_DESKTOP_TRAY_ATTENTION |
                             RIN_DESKTOP_TRAY_BACKGROUND |
                             RIN_DESKTOP_TRAY_ALWAYS_OVERFLOW |
                             RIN_DESKTOP_TRAY_HIDE_WHEN_INACTIVE |
                             RIN_DESKTOP_TRAY_HOVER |
                             RIN_DESKTOP_TRAY_PRESSED |
                             RIN_DESKTOP_TRAY_KEYBOARD_FOCUS;
    if (!model || !item_id || (flags & ~allowed) != 0u) return -1;
    for (i = 0u; i < model->tray_count; ++i) {
        if (model->tray[i].item_id != item_id) continue;
        model->tray[i].flags = (model->tray[i].flags &
                                (RIN_DESKTOP_TRAY_ATTENTION |
                                 RIN_DESKTOP_TRAY_BACKGROUND |
                                 RIN_DESKTOP_TRAY_ALWAYS_OVERFLOW |
                                 RIN_DESKTOP_TRAY_HIDE_WHEN_INACTIVE)) |
                               (flags & (RIN_DESKTOP_TRAY_HOVER |
                                         RIN_DESKTOP_TRAY_PRESSED |
                                         RIN_DESKTOP_TRAY_KEYBOARD_FOCUS));
        ++model->generation;
        return 0;
    }
    return -1;
}

int rin_desktop_model_set_tray_preference(
    RinDesktopModel* model, uint64_t session_id, uint64_t app_identity_id,
    uint32_t flags, uint32_t order)
{
    int index;
    uint32_t i;
    const uint32_t known = RIN_DESKTOP_TRAY_PREF_ALWAYS_SHOW |
                           RIN_DESKTOP_TRAY_PREF_HIDE_WHEN_INACTIVE |
                           RIN_DESKTOP_TRAY_PREF_ALWAYS_OVERFLOW;
    if (!model || session_id == 0u || app_identity_id == 0u ||
        (flags & ~known) != 0u ||
        order >= RIN_DESKTOP_MAX_TRAY_ITEMS)
        return -1;
    index = tray_preference_index(model, session_id, app_identity_id);
    if (index < 0) {
        if (model->tray_preference_count >= RIN_DESKTOP_MAX_TRAY_PREFERENCES)
            return -1;
        index = (int)model->tray_preference_count++;
        model->tray_preferences[index].session_id = session_id;
        model->tray_preferences[index].app_identity_id = app_identity_id;
    }
    model->tray_preferences[index].flags = flags;
    model->tray_preferences[index].order = order;
    for (i = 0u; i < model->tray_count; ++i) {
        if (model->tray[i].session_id != session_id ||
            model->tray[i].app_identity_id != app_identity_id) continue;
        model->tray[i].flags &= ~(RIN_DESKTOP_TRAY_ALWAYS_OVERFLOW |
                                  RIN_DESKTOP_TRAY_HIDE_WHEN_INACTIVE);
        if ((flags & RIN_DESKTOP_TRAY_PREF_ALWAYS_OVERFLOW) != 0u)
            model->tray[i].flags |= RIN_DESKTOP_TRAY_ALWAYS_OVERFLOW;
        if ((flags & RIN_DESKTOP_TRAY_PREF_HIDE_WHEN_INACTIVE) != 0u)
            model->tray[i].flags |= RIN_DESKTOP_TRAY_HIDE_WHEN_INACTIVE;
    }
    ++model->generation;
    return 0;
}

int rin_desktop_model_reorder_tray(RinDesktopModel* model, uint32_t from,
                                   uint32_t to)
{
    RinDesktopTrayItem item;
    uint32_t i;
    if (!model || from >= model->tray_count || to >= model->tray_count)
        return -1;
    if (from == to) return 0;
    item = model->tray[from];
    if (from < to) {
        for (i = from; i < to; ++i) model->tray[i] = model->tray[i + 1u];
    } else {
        for (i = from; i > to; --i) model->tray[i] = model->tray[i - 1u];
    }
    model->tray[to] = item;
    for (i = 0u; i < model->tray_count; ++i) {
        const int preference = tray_preference_lookup(
            model, model->tray[i].session_id,
            model->tray[i].app_identity_id);
        if (preference >= 0) {
            model->tray_preferences[preference].order = i;
        } else if (model->tray_preference_count <
                   RIN_DESKTOP_MAX_TRAY_PREFERENCES) {
            RinDesktopTrayPreference* created =
                &model->tray_preferences[model->tray_preference_count++];
            created->session_id = model->tray[i].session_id;
            created->app_identity_id = model->tray[i].app_identity_id;
            created->flags = 0u;
            created->order = i;
        }
    }
    ++model->generation;
    return 0;
}

int rin_desktop_model_unregister_tray(RinDesktopModel* model, uint64_t id, uint64_t session_id)
{
    uint32_t i, j;
    if (!model || !id || !session_id) return -1;
    for (i = 0u; i < model->tray_count; ++i) if (model->tray[i].item_id == id && model->tray[i].session_id == session_id) {
        for (j = i + 1u; j < model->tray_count; ++j) model->tray[j - 1u] = model->tray[j];
        --model->tray_count;
        ++model->generation;
        return 0;
    }
    return -1;
}

int rin_desktop_model_set_foreground_session(RinDesktopModel* model, uint64_t session_id)
{
    uint32_t i;
    if (!model) return -1;
    model->foreground_session_id = session_id;
    for (i = 0u; i < model->tray_count; ++i)
        if (session_id == 0u || model->tray[i].session_id != session_id)
            model->tray[i].flags |= RIN_DESKTOP_TRAY_BACKGROUND;
        else model->tray[i].flags &= ~RIN_DESKTOP_TRAY_BACKGROUND;
    if (model->settings.notification_privacy == RIN_DESKTOP_NOTIFICATION_HIDE_BACKGROUND) {
        /* Notification ownership is represented by app identity; the shell
         * may still retain history, but background entries stay hidden. */
    }
    ++model->generation;
    return 0;
}

int rin_desktop_model_post_notification(RinDesktopModel* model, const RinDesktopNotification* item, uint64_t now_ms)
{
    RinDesktopNotification copy;
    uint32_t i;
    if (!model || !item || !item->app_identity_id || !item->title[0] || !item->body[0] ||
        !bounded_text(item->app_name, RIN_DESKTOP_NAME_MAX) ||
        !bounded_text(item->icon_path, RIN_DESKTOP_PATH_MAX) ||
        !bounded_text(item->title, RIN_DESKTOP_NAME_MAX) ||
        !bounded_text(item->body, RIN_DESKTOP_PATH_MAX) ||
        !bounded_text(item->action, RIN_DESKTOP_LABEL_MAX)) return -1;
    if (model->settings.notification_privacy ==
            RIN_DESKTOP_NOTIFICATION_HIDE_BACKGROUND &&
        model->foreground_session_id != 0u && item->session_id != 0u &&
        item->session_id != model->foreground_session_id) return -3;
    if (model->notification_count >= RIN_DESKTOP_MAX_NOTIFICATIONS) {
        for (i = 0u; i < model->notification_count; ++i)
            if (model->notifications[i].flags & RIN_DESKTOP_NOTIFICATION_READ) break;
        if (i == model->notification_count) i = 0u;
        for (; i + 1u < model->notification_count; ++i) model->notifications[i] = model->notifications[i + 1u];
        --model->notification_count;
    }
    copy = *item;
    copy.id = model->next_notification_id++;
    if (!copy.id) copy.id = model->next_notification_id++;
    copy.timestamp_ms = now_ms;
    copy.flags &= ~(RIN_DESKTOP_NOTIFICATION_READ | RIN_DESKTOP_NOTIFICATION_DISMISSED);
    model->notifications[model->notification_count++] = copy;
    ++model->unread_notifications;
    ++model->generation;
    return 0;
}

int rin_desktop_model_dismiss_notification(RinDesktopModel* model, uint64_t id)
{
    uint32_t i, j;
    if (!model || !id) return -1;
    for (i = 0u; i < model->notification_count; ++i) if (model->notifications[i].id == id) {
        if (!(model->notifications[i].flags & RIN_DESKTOP_NOTIFICATION_READ) && model->unread_notifications)
            --model->unread_notifications;
        for (j = i + 1u; j < model->notification_count; ++j) model->notifications[j - 1u] = model->notifications[j];
        --model->notification_count;
        ++model->generation;
        return 0;
    }
    return -1;
}

void rin_desktop_model_mark_notifications_read(RinDesktopModel* model)
{
    uint32_t i;
    if (!model) return;
    for (i = 0u; i < model->notification_count; ++i) model->notifications[i].flags |= RIN_DESKTOP_NOTIFICATION_READ;
    model->unread_notifications = 0u;
    ++model->generation;
}

uint32_t rin_desktop_model_battery_alert_level(const RinDesktopStatus* status)
{
    if (!status || !status->battery_present || status->charging ||
        status->battery_state != RIN_DESKTOP_BATTERY_DISCHARGING)
        return 0u;
    if (status->critical_battery) return 2u;
    return status->low_battery ? 1u : 0u;
}

int rin_desktop_model_battery_percent_valid(int32_t battery_percent)
{
    return battery_percent >= 0 && battery_percent <= 100;
}

uint32_t rin_desktop_model_battery_alert_transition(
    uint32_t previous_level, const RinDesktopStatus* status)
{
    const uint32_t current_level =
        rin_desktop_model_battery_alert_level(status);
    if (previous_level > 2u || current_level <= previous_level) return 0u;
    return current_level;
}

uint32_t rin_desktop_model_provider_presence_transition(
    int previous_valid, int previous_present, int current_present)
{
    const int current = current_present != 0;
    if (!previous_valid || (previous_present != 0) == current)
        return RIN_DESKTOP_PROVIDER_PRESENCE_NONE;
    return current ? RIN_DESKTOP_PROVIDER_PRESENCE_CONNECTED
                   : RIN_DESKTOP_PROVIDER_PRESENCE_REMOVED;
}

uint32_t rin_desktop_model_battery_presence_transition(
    int previous_valid, int previous_present, const RinDesktopStatus* status)
{
    const int current_present = status != NULL && status->battery_present != 0u;
    return rin_desktop_model_provider_presence_transition(
        previous_valid, previous_present, current_present);
}

int rin_desktop_model_output_has_taskbar(const RinDesktopModel* model,
                                         uint32_t output_ordinal)
{
    if (!model || output_ordinal >=
            (uint32_t)(sizeof(model->layouts) / sizeof(model->layouts[0])))
        return 0;
    if (model->settings.show_on_all_outputs != 0u) return 1;
    if (model->settings.output_mode == RIN_DESKTOP_OUTPUT_PRIMARY_ONLY)
        return output_ordinal == 0u;
    return 1;
}

void rin_desktop_model_set_status(RinDesktopModel* model, const RinDesktopStatus* status)
{
    if (!model || !status) return;
    model->status = *status;
    if (model->status.network_state > RIN_DESKTOP_NETWORK_STATE_UNKNOWN)
        model->status.network_state = RIN_DESKTOP_NETWORK_STATE_UNKNOWN;
    /* Keep the copied status self-consistent even when a provider disappears
     * between polls.  In particular, do not retain a stale percentage or
     * charging flag that could make a later notification decision actionable.
     * A present battery can also report an unknown percentage while its
     * provider is reconnecting; the display fallback must stay non-actionable
     * until a real discharge sample arrives. */
    if (!model->status.battery_present) {
        model->status.battery_percent = 0u;
        model->status.charging = 0u;
        model->status.battery_state = RIN_DESKTOP_BATTERY_UNKNOWN;
        model->status.battery_minutes_remaining = -1;
        model->status.low_battery = 0u;
        model->status.critical_battery = 0u;
        model->status.battery_label[0] = '\0';
    } else if (model->status.battery_percent > 100u ||
               model->status.battery_state > RIN_DESKTOP_BATTERY_FULL) {
        /* A producer must not be able to turn an out-of-range/stale sample
         * into a threshold alert.  Keep the battery present, but expose an
         * explicitly unknown gauge until a bounded sample arrives. */
        model->status.battery_percent = 0u;
        model->status.charging = 0u;
        model->status.battery_state = RIN_DESKTOP_BATTERY_UNKNOWN;
        model->status.battery_minutes_remaining = -1;
        model->status.low_battery = 0u;
        model->status.critical_battery = 0u;
        model->status.battery_label[0] = '-';
        model->status.battery_label[1] = '-';
        model->status.battery_label[2] = '\0';
    } else if (model->status.battery_state == RIN_DESKTOP_BATTERY_UNKNOWN) {
        /* UNKNOWN is a provider boundary, not a displayable 0% reading.
         * A producer may carry a stale percentage or label while its gauge
         * is reconnecting; retain presence for the tray topology indicator,
         * but clear all actionable/display values until a real state arrives. */
        model->status.battery_percent = 0u;
        model->status.charging = 0u;
        model->status.battery_minutes_remaining = -1;
        model->status.low_battery = 0u;
        model->status.critical_battery = 0u;
        model->status.battery_label[0] = '-';
        model->status.battery_label[1] = '-';
        model->status.battery_label[2] = '\0';
    } else if (model->status.charging ||
               model->status.battery_state != RIN_DESKTOP_BATTERY_DISCHARGING) {
        model->status.low_battery = 0u;
        model->status.critical_battery = 0u;
    } else {
        model->status.low_battery = model->status.battery_percent <= 20u;
        model->status.critical_battery = model->status.battery_percent <= 5u;
    }
    ++model->generation;
}

uint32_t rin_desktop_model_network_state(int device_ready, int configured,
                                         int link_known, int link_up)
{
    return rin_desktop_model_network_state_with_reachability(
        device_ready, configured, link_known, link_up,
        RIN_DESKTOP_NETWORK_REACHABILITY_UNKNOWN);
}

uint32_t rin_desktop_model_network_state_with_reachability(
    int device_ready, int configured, int link_known, int link_up,
    uint32_t reachability)
{
    if (device_ready < 0 || configured < 0 || link_known < 0 || link_up < 0)
        return RIN_DESKTOP_NETWORK_STATE_UNKNOWN;
    if (reachability > RIN_DESKTOP_NETWORK_REACHABILITY_UNREACHABLE)
        return RIN_DESKTOP_NETWORK_STATE_UNKNOWN;
    if (!device_ready) return RIN_DESKTOP_NETWORK_STATE_DISCONNECTED;
    if (!configured || (link_known && !link_up))
        return RIN_DESKTOP_NETWORK_STATE_LIMITED;
    if (reachability == RIN_DESKTOP_NETWORK_REACHABILITY_UNREACHABLE)
        return RIN_DESKTOP_NETWORK_STATE_NO_INTERNET;
    return RIN_DESKTOP_NETWORK_STATE_CONNECTED;
}

int rin_desktop_model_compute_layout(RinDesktopModel* model, uint32_t output_id, uint32_t width,
                                     uint32_t height, uint32_t scale_numerator, uint32_t scale_denominator)
{
    RinDesktopLayout* layout;
    uint32_t i, base, available, thickness;
    if (!model || !width || !height || !scale_numerator || !scale_denominator) return -1;
    for (i = 0u; i < model->layout_count; ++i) if (model->layouts[i].output_id == output_id) break;
    if (i == model->layout_count) {
        if (i >= 8u) return -2;
        ++model->layout_count;
    }
    layout = &model->layouts[i];
    memset(layout, 0, sizeof(*layout));
    layout->output_id = output_id; layout->width = width; layout->height = height;
    layout->scale_numerator = scale_numerator; layout->scale_denominator = scale_denominator;
    base = (48u * scale_numerator + scale_denominator - 1u) / scale_denominator;
    thickness = base < 40u ? 40u : base > 96u ? 96u : base;
    layout->taskbar_thickness = thickness;
    layout->icon_size = (32u * scale_numerator + scale_denominator - 1u) / scale_denominator;
    if (layout->icon_size < 16u) layout->icon_size = 16u;
    layout->position = (uint8_t)model->settings.position;
    layout->hidden = model->settings.auto_hide && !model->edge_reveal && !model->notification_center_open;
    layout->launcher_open = model->launcher_open;
    layout->notification_center_open = model->notification_center_open;
    if (!model->settings.taskbar_visible || layout->hidden) thickness = 1u;
    if (layout->position == RIN_DESKTOP_TASKBAR_TOP) layout->reserved_top = thickness;
    else if (layout->position == RIN_DESKTOP_TASKBAR_LEFT) layout->reserved_left = thickness;
    else if (layout->position == RIN_DESKTOP_TASKBAR_RIGHT) layout->reserved_right = thickness;
    else layout->reserved_bottom = thickness;
    available = (layout->position == RIN_DESKTOP_TASKBAR_LEFT || layout->position == RIN_DESKTOP_TASKBAR_RIGHT) ? height : width;
    if (available > 220u) available -= 220u; else available = 0u;
    layout->item_width = model->task_count ? available / model->task_count : 0u;
    if (layout->item_width > 160u) layout->item_width = 160u;
    if (layout->item_width < 52u && model->task_count) layout->item_width = 52u;
    layout->visible_items = layout->item_width ? available / layout->item_width : 0u;
    if (layout->visible_items > model->task_count) layout->visible_items = model->task_count;
    layout->overflow_items = model->task_count - layout->visible_items;
    layout->tray_item_width = 36u;
    if (available > 28u) {
        layout->tray_visible_items = (available - 28u) / layout->tray_item_width;
        if (layout->tray_visible_items > RIN_DESKTOP_MAX_TRAY_ITEMS)
            layout->tray_visible_items = RIN_DESKTOP_MAX_TRAY_ITEMS;
    } else {
        layout->tray_visible_items = 0u;
    }
    {
        uint32_t candidates = 0u;
        uint32_t displayable = 0u;
        for (i = 0u; i < model->tray_count; ++i)
            if ((model->tray[i].flags & RIN_DESKTOP_TRAY_BACKGROUND) == 0u) {
                ++displayable;
                if (tray_is_visible_candidate(&model->tray[i])) ++candidates;
            }
        if (layout->tray_visible_items > candidates)
            layout->tray_visible_items = candidates;
        layout->tray_overflow_items = displayable -
                                      layout->tray_visible_items;
    }
    ++model->generation;
    return 0;
}

int rin_desktop_model_edge_reveal(RinDesktopModel* model, uint32_t output_id, int pointer_at_edge, int important_ui)
{
    (void)output_id;
    if (!model) return -1;
    model->edge_reveal = (uint8_t)(pointer_at_edge || important_ui);
    ++model->generation;
    return 0;
}

uint32_t rin_desktop_model_build_accessibility(RinDesktopModel* model)
{
    uint32_t i, node = 0u;
    if (!model) return 0u;
    memset(model->accessibility, 0, sizeof(model->accessibility));
    model->accessibility[node++] = (RinDesktopAccessibilityNode){1u, 0u, 1u, 0u, "Taskbar"};
    model->accessibility[node++] = (RinDesktopAccessibilityNode){2u, 1u, 2u, 0u, "Start"};
    for (i = 0u; i < model->task_count && node < RIN_DESKTOP_MAX_ACCESSIBILITY_NODES; ++i) {
        uint32_t state = 0u;
        if (model->tasks[i].flags & RIN_DESKTOP_TASK_ACTIVE) state |= 1u;
        if (model->tasks[i].flags & RIN_DESKTOP_TASK_MINIMIZED) state |= 2u;
        if (model->tasks[i].flags & RIN_DESKTOP_TASK_ATTENTION) state |= 4u;
        model->accessibility[node++] = (RinDesktopAccessibilityNode){100u + i, 1u, 3u, state, {0}};
        copy_text(model->accessibility[node - 1u].name, RIN_DESKTOP_NAME_MAX, model->tasks[i].name);
    }
    for (i = 0u; i < model->tray_count && node < RIN_DESKTOP_MAX_ACCESSIBILITY_NODES; ++i) {
        if (model->locked) continue;
        if (model->tray[i].flags & RIN_DESKTOP_TRAY_BACKGROUND) continue;
        uint32_t state = model->tray[i].flags & RIN_DESKTOP_TRAY_ATTENTION ? 4u : 0u;
        if (model->tray[i].flags & RIN_DESKTOP_TRAY_KEYBOARD_FOCUS) state |= 1u;
        if (model->tray[i].flags & RIN_DESKTOP_TRAY_PRESSED) state |= 2u;
        model->accessibility[node++] = (RinDesktopAccessibilityNode){1000u + i, 1u, 4u,
            state, {0}};
        copy_text(model->accessibility[node - 1u].name, RIN_DESKTOP_NAME_MAX, model->tray[i].label);
    }
    if (!model->locked && model->layout_count != 0u &&
        model->layouts[0].tray_overflow_items != 0u &&
        node < RIN_DESKTOP_MAX_ACCESSIBILITY_NODES)
        model->accessibility[node++] = (RinDesktopAccessibilityNode){
            3000u, 1u, 2u, 0u, "More tray items"};
    if (!model->locked) {
        model->accessibility[node++] = (RinDesktopAccessibilityNode){2000u, 1u, 5u, 0u, "Clock"};
        model->accessibility[node++] = (RinDesktopAccessibilityNode){2001u, 1u, 5u, 0u, "Network"};
        model->accessibility[node++] = (RinDesktopAccessibilityNode){2002u, 1u, 5u, 0u, "Audio"};
        if (model->status.battery_present && node < RIN_DESKTOP_MAX_ACCESSIBILITY_NODES)
            model->accessibility[node++] = (RinDesktopAccessibilityNode){2003u, 1u, 5u, 0u, "Battery"};
    }
    model->accessibility_count = node;
    return node;
}

int rin_desktop_model_serialize_settings(const RinDesktopModel* model, uint8_t* output,
                                         uint32_t capacity, uint32_t* size)
{
    uint32_t payload_bytes;
    uint32_t bytes;
    uint32_t checksum;
    /* Serialization is a caller-owned output boundary.  A failed size or
     * model validation must not leave a previous settings image looking
     * usable to an atomic-save or push caller. */
    if (size != NULL) *size = 0u;
    if (output == NULL || size == NULL) return -1;
    if (capacity != 0u) {
        const uint32_t clear_capacity =
            capacity > RIN_DESKTOP_SERIALIZED_SETTINGS_MAX
                ? RIN_DESKTOP_SERIALIZED_SETTINGS_MAX
                : capacity;
        /* Never scrub beyond the bounded serialization contract.  The caller
         * may pass a hostile or stale capacity value, so it is not itself a
         * safe write bound. */
        memset(output, 0, clear_capacity);
    }
    if (model == NULL) return -1;
    /* magic/version, pin count, and preference count are four wire words.
     * Keep the size calculation identical to the two count writes below so
     * a non-empty preference table is never truncated before deserialize. */
    payload_bytes = (uint32_t)(sizeof(uint32_t) * 4u +
                               sizeof(RinDesktopSettings) +
                               sizeof(RinDesktopPin) * model->pin_count +
                               sizeof(RinDesktopTrayPreference) *
                                   model->tray_preference_count);
    if (payload_bytes > UINT32_MAX - SETTINGS_CRC_SIZE)
        return -2;
    bytes = payload_bytes + SETTINGS_CRC_SIZE;
    if (bytes > capacity || bytes > RIN_DESKTOP_SERIALIZED_SETTINGS_MAX ||
        model->pin_count > RIN_DESKTOP_MAX_PINS ||
        model->tray_preference_count > RIN_DESKTOP_MAX_TRAY_PREFERENCES)
        return -2;
    memset(output, 0, payload_bytes);
    memcpy(output, &(uint32_t){SETTINGS_MAGIC}, sizeof(uint32_t));
    memcpy(output + 4u,
           &(uint32_t){RIN_DESKTOP_SETTINGS_FORMAT_VERSION},
           sizeof(uint32_t));
    memcpy(output + 8u, &model->settings, sizeof(model->settings));
    memcpy(output + 8u + sizeof(model->settings), &model->pin_count, sizeof(model->pin_count));
    if (model->pin_count) memcpy(output + 12u + sizeof(model->settings), model->pins,
                                 sizeof(RinDesktopPin) * model->pin_count);
    memcpy(output + 12u + sizeof(model->settings) +
               sizeof(RinDesktopPin) * model->pin_count,
           &model->tray_preference_count, sizeof(model->tray_preference_count));
    if (model->tray_preference_count)
        memcpy(output + 16u + sizeof(model->settings) +
               sizeof(RinDesktopPin) * model->pin_count,
               model->tray_preferences,
               sizeof(RinDesktopTrayPreference) * model->tray_preference_count);
    checksum = settings_crc32(output, payload_bytes);
    memcpy(output + payload_bytes, &checksum, sizeof(checksum));
    *size = bytes;
    return 0;
}

int rin_desktop_model_deserialize_settings(RinDesktopModel* model, const uint8_t* input, uint32_t size)
{
    uint32_t magic, version, settings_version, count, preference_count;
    uint32_t expected, index;
    uint32_t payload_size;
    uint32_t preference_bytes;
    uint32_t stored_checksum;
    uint32_t settings_bytes;
    int legacy_preferences = 0;
    RinDesktopSettings settings;
    RinDesktopPin decoded_pins[RIN_DESKTOP_MAX_PINS];
    RinDesktopTrayPreference decoded_preferences[RIN_DESKTOP_MAX_TRAY_PREFERENCES];
    if (!model || !input || size < 16u + sizeof(RinDesktopSettingsV1))
        return -1;
    memcpy(&magic, input, 4u); memcpy(&version, input + 4u, 4u);
    if (version == RIN_DESKTOP_SETTINGS_FORMAT_VERSION) {
        if (size < SETTINGS_CRC_SIZE + 16u + sizeof(RinDesktopSettingsV1))
            return -1;
        payload_size = size - SETTINGS_CRC_SIZE;
        memcpy(&stored_checksum, input + payload_size, sizeof(stored_checksum));
        if (stored_checksum != settings_crc32(input, payload_size)) return -2;
    } else if (version == RIN_DESKTOP_SETTINGS_LEGACY_FORMAT_VERSION) {
        /* v1 had no trailer. It is accepted only for migration through the
         * same structural validator; all new writes are v2. */
        payload_size = size;
    } else {
        return -2;
    }
    memcpy(&settings_version, input + 8u, sizeof(settings_version));
    memset(&settings, 0, sizeof(settings));
    if (settings_version == 1u) {
        RinDesktopSettingsV1 old_settings;
        memcpy(&old_settings, input + 8u, sizeof(old_settings));
        if (old_settings.reserved != 0u) return -2;
        settings.version = RIN_DESKTOP_MODEL_VERSION;
        settings.flags = old_settings.flags;
        settings.taskbar_visible = old_settings.taskbar_visible;
        settings.tray_visible = old_settings.tray_visible;
        settings.auto_hide = old_settings.auto_hide;
        settings.show_on_all_outputs = old_settings.show_on_all_outputs;
        settings.clock_24_hour = old_settings.clock_24_hour;
        settings.dnd = old_settings.dnd;
        settings.notification_privacy = old_settings.notification_privacy;
        settings.position = old_settings.position;
        settings.output_mode = old_settings.output_mode;
        settings.theme_id = old_settings.theme_id;
        settings.reduced_motion = old_settings.reduced_motion;
        settings.high_contrast = old_settings.high_contrast;
        settings.reduced_transparency = old_settings.reduced_transparency;
        settings.system_icon_visibility = old_settings.system_icon_visibility;
        settings.tray_policy = old_settings.tray_policy;
        settings.taskbar_use_accent_color = 1u;
        settings.taskbar_transparency_percent = 80u;
        settings.taskbar_corner_radius_px = 8u;
        settings_bytes = (uint32_t)sizeof(old_settings);
    } else if (settings_version == RIN_DESKTOP_MODEL_VERSION) {
        if (size < 16u + sizeof(settings)) return -1;
        memcpy(&settings, input + 8u, sizeof(settings));
        settings_bytes = (uint32_t)sizeof(settings);
    } else {
        return -2;
    }
    memcpy(&count, input + 8u + settings_bytes, 4u);
    if (count > RIN_DESKTOP_MAX_PINS) return -2;
    expected = 12u + settings_bytes +
               count * (uint32_t)sizeof(RinDesktopPin);
    if (expected > payload_size - sizeof(preference_count)) return -2;
    memcpy(&preference_count, input + expected, sizeof(preference_count));
    if (preference_count > RIN_DESKTOP_MAX_TRAY_PREFERENCES) return -2;
    expected += sizeof(preference_count);
    preference_bytes = payload_size - expected;
    if (preference_count == 0u) {
        if (preference_bytes != 0u) return -2;
    } else if (preference_bytes ==
               preference_count * (uint32_t)sizeof(RinDesktopTrayPreference)) {
        legacy_preferences = 0;
    } else if (preference_bytes == preference_count *
               (uint32_t)(sizeof(RinDesktopTrayPreference) - sizeof(uint64_t))) {
        legacy_preferences = 1;
    } else {
        return -2;
    }
    if (magic != SETTINGS_MAGIC ||
        (version != RIN_DESKTOP_SETTINGS_FORMAT_VERSION &&
         version != RIN_DESKTOP_SETTINGS_LEGACY_FORMAT_VERSION) ||
        settings.version != RIN_DESKTOP_MODEL_VERSION ||
        settings.flags != 0u || settings.taskbar_visible > 1u ||
        settings.tray_visible > 1u || settings.auto_hide > 1u ||
        settings.show_on_all_outputs > 1u || settings.clock_24_hour > 1u ||
        settings.clock_show_seconds > 1u ||
        settings.dnd > 1u ||
        settings.notification_privacy > RIN_DESKTOP_NOTIFICATION_HIDE_BACKGROUND ||
        settings.position > RIN_DESKTOP_TASKBAR_RIGHT ||
        settings.output_mode > RIN_DESKTOP_OUTPUT_ALL_WINDOWS ||
        settings.reduced_motion > 1u || settings.high_contrast > 1u ||
        settings.reduced_transparency > 1u ||
        settings.taskbar_use_accent_color > 1u ||
        settings.taskbar_transparency_percent > 100u ||
        settings.taskbar_corner_radius_px > 20u ||
        (settings.system_icon_visibility & ~RIN_DESKTOP_SYSTEM_ICON_ALL) != 0u ||
        (settings.tray_policy & ~RIN_DESKTOP_TRAY_POLICY_SHOW_OVERFLOW_BUTTON) != 0u ||
        count > RIN_DESKTOP_MAX_PINS)
        return -2;
    for (index = 0u; index < count; ++index) {
        memcpy(&decoded_pins[index], input + 12u + settings_bytes +
               index * sizeof(RinDesktopPin), sizeof(decoded_pins[index]));
        if (decoded_pins[index].app_identity_id == 0u ||
            !bounded_text(decoded_pins[index].app_identity, RIN_DESKTOP_IDENTITY_MAX) ||
            !bounded_text(decoded_pins[index].name, RIN_DESKTOP_NAME_MAX) ||
            !bounded_text(decoded_pins[index].executable_path, RIN_DESKTOP_PATH_MAX) ||
            !bounded_text(decoded_pins[index].icon_path, RIN_DESKTOP_PATH_MAX)) return -2;
    }
    for (index = 0u; index < preference_count; ++index) {
        const uint8_t* preference_input = input + expected +
            index * (legacy_preferences ?
                (sizeof(RinDesktopTrayPreference) - sizeof(uint64_t)) :
                sizeof(RinDesktopTrayPreference));
        if (legacy_preferences) {
            decoded_preferences[index].session_id = 0u;
            memcpy(&decoded_preferences[index].app_identity_id,
                   preference_input, sizeof(uint64_t));
            memcpy(&decoded_preferences[index].flags,
                   preference_input + sizeof(uint64_t), sizeof(uint32_t));
            memcpy(&decoded_preferences[index].order,
                   preference_input + sizeof(uint64_t) + sizeof(uint32_t),
                   sizeof(uint32_t));
        } else {
            memcpy(&decoded_preferences[index], preference_input,
                   sizeof(decoded_preferences[index]));
        }
        const RinDesktopTrayPreference* preference = &decoded_preferences[index];
        if (preference->session_id == UINT64_MAX ||
            preference->app_identity_id == 0u ||
            (preference->flags & ~(RIN_DESKTOP_TRAY_PREF_ALWAYS_SHOW |
                                   RIN_DESKTOP_TRAY_PREF_HIDE_WHEN_INACTIVE |
                                   RIN_DESKTOP_TRAY_PREF_ALWAYS_OVERFLOW)) != 0u ||
            preference->order >= RIN_DESKTOP_MAX_TRAY_ITEMS)
            return -2;
    }
    if (count) memcpy(model->pins, decoded_pins, count * sizeof(RinDesktopPin));
    memcpy(model->tray_preferences, decoded_preferences,
           preference_count * sizeof(RinDesktopTrayPreference));
    model->settings = settings;
    model->pin_count = count;
    model->tray_preference_count = preference_count;
    rebuild_tasks(model);
    ++model->generation;
    return 0;
}
