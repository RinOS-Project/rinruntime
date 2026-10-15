/* SPDX-License-Identifier: MIT */
/*
 * Desktop shell model shared by desktop.rin and host tests.
 *
 * The model is intentionally allocation-free and bounded.  The compositor is
 * the authority for authenticated window snapshots; this layer owns only
 * presentation state (pins, grouping, launcher/tray/notification state and
 * per-output layout).  In particular, an executable path is never the sole
 * application identity.
 */
#ifndef RINOS_SHARED_RIN_DESKTOP_MODEL_H
#define RINOS_SHARED_RIN_DESKTOP_MODEL_H

#include <stdint.h>

#include "rin_tray_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RIN_DESKTOP_MODEL_VERSION 2u
#define RIN_DESKTOP_MAX_WINDOWS 64u
#define RIN_DESKTOP_MAX_TASK_ITEMS 64u
#define RIN_DESKTOP_MAX_PINS 32u
#define RIN_DESKTOP_MAX_APPS 96u
#define RIN_DESKTOP_MAX_TRAY_ITEMS 32u
#define RIN_DESKTOP_MAX_NOTIFICATIONS 64u
#define RIN_DESKTOP_MAX_ACCESSIBILITY_NODES 128u
#define RIN_DESKTOP_MAX_GROUP_WINDOWS 16u
#define RIN_DESKTOP_NAME_MAX 96u
#define RIN_DESKTOP_PATH_MAX 160u
#define RIN_DESKTOP_IDENTITY_MAX 96u
#define RIN_DESKTOP_LABEL_MAX 64u
#define RIN_DESKTOP_NETWORK_SSID_MAX 33u
#define RIN_DESKTOP_SEARCH_MAX 64u
#define RIN_DESKTOP_SERIALIZED_SETTINGS_MAX 32768u
#define RIN_DESKTOP_MAX_TRAY_PREFERENCES 32u
/* The first wire version had no integrity trailer and remains readable for
 * one-way migration. New writes use the CRC-protected format. */
#define RIN_DESKTOP_SETTINGS_FORMAT_VERSION 2u
#define RIN_DESKTOP_SETTINGS_LEGACY_FORMAT_VERSION 1u

enum RinDesktopSystemIconVisibility {
    RIN_DESKTOP_SYSTEM_ICON_NETWORK = 1u << 0,
    RIN_DESKTOP_SYSTEM_ICON_AUDIO = 1u << 1,
    RIN_DESKTOP_SYSTEM_ICON_BATTERY = 1u << 2,
    RIN_DESKTOP_SYSTEM_ICON_INPUT = 1u << 3,
    RIN_DESKTOP_SYSTEM_ICON_CLOCK = 1u << 4,
    RIN_DESKTOP_SYSTEM_ICON_NOTIFICATION = 1u << 5,
    RIN_DESKTOP_SYSTEM_ICON_ALL = (1u << 6) - 1u,
};

enum RinDesktopTrayPreferenceFlags {
    RIN_DESKTOP_TRAY_PREF_ALWAYS_SHOW = 1u << 0,
    RIN_DESKTOP_TRAY_PREF_HIDE_WHEN_INACTIVE = 1u << 1,
    RIN_DESKTOP_TRAY_PREF_ALWAYS_OVERFLOW = 1u << 2,
};

enum RinDesktopTrayPolicy {
    RIN_DESKTOP_TRAY_POLICY_SHOW_OVERFLOW_BUTTON = 1u << 0,
};

enum RinDesktopWindowFlags {
    RIN_DESKTOP_WINDOW_ACTIVE = 1u << 0,
    RIN_DESKTOP_WINDOW_ATTENTION = 1u << 1,
    RIN_DESKTOP_WINDOW_CRASHED = 1u << 2,
    RIN_DESKTOP_WINDOW_UNRESPONSIVE = 1u << 3,
};

enum RinDesktopWindowState {
    RIN_DESKTOP_WINDOW_MINIMIZED = 1u << 0,
    RIN_DESKTOP_WINDOW_MAXIMIZED = 1u << 1,
    RIN_DESKTOP_WINDOW_FULLSCREEN = 1u << 2,
};

enum RinDesktopTaskItemFlags {
    RIN_DESKTOP_TASK_PINNED = 1u << 0,
    RIN_DESKTOP_TASK_RUNNING = 1u << 1,
    RIN_DESKTOP_TASK_ACTIVE = 1u << 2,
    RIN_DESKTOP_TASK_MINIMIZED = 1u << 3,
    RIN_DESKTOP_TASK_ATTENTION = 1u << 4,
    RIN_DESKTOP_TASK_MULTIPLE = 1u << 5,
    RIN_DESKTOP_TASK_LAUNCH_PENDING = 1u << 6,
    RIN_DESKTOP_TASK_CRASHED = 1u << 7,
    RIN_DESKTOP_TASK_HOVER = 1u << 8,
    RIN_DESKTOP_TASK_PRESSED = 1u << 9,
    RIN_DESKTOP_TASK_KEYBOARD_FOCUS = 1u << 10,
};

enum RinDesktopTaskAction {
    RIN_DESKTOP_TASK_ACTION_NONE = 0,
    RIN_DESKTOP_TASK_ACTION_LAUNCH,
    RIN_DESKTOP_TASK_ACTION_ACTIVATE,
    RIN_DESKTOP_TASK_ACTION_MINIMIZE,
    RIN_DESKTOP_TASK_ACTION_RESTORE,
    RIN_DESKTOP_TASK_ACTION_SELECT_WINDOWS,
};

enum RinDesktopContextAction {
    RIN_DESKTOP_CONTEXT_OPEN = 1,
    RIN_DESKTOP_CONTEXT_NEW_WINDOW,
    RIN_DESKTOP_CONTEXT_CLOSE_WINDOW,
    RIN_DESKTOP_CONTEXT_CLOSE_ALL_WINDOWS,
    RIN_DESKTOP_CONTEXT_PIN,
    RIN_DESKTOP_CONTEXT_UNPIN,
};

enum RinDesktopTaskbarPosition {
    RIN_DESKTOP_TASKBAR_BOTTOM = 0,
    RIN_DESKTOP_TASKBAR_TOP = 1,
    RIN_DESKTOP_TASKBAR_LEFT = 2,
    RIN_DESKTOP_TASKBAR_RIGHT = 3,
};

enum RinDesktopOutputMode {
    RIN_DESKTOP_OUTPUT_PRIMARY_ONLY = 0,
    RIN_DESKTOP_OUTPUT_ALL = 1,
    RIN_DESKTOP_OUTPUT_PER_MONITOR = 2,
    RIN_DESKTOP_OUTPUT_ALL_WINDOWS = 3,
};

enum RinDesktopTrayFlags {
    RIN_DESKTOP_TRAY_ATTENTION = 1u << 0,
    RIN_DESKTOP_TRAY_BACKGROUND = 1u << 1,
    RIN_DESKTOP_TRAY_HOVER = 1u << 2,
    RIN_DESKTOP_TRAY_PRESSED = 1u << 3,
    RIN_DESKTOP_TRAY_KEYBOARD_FOCUS = 1u << 4,
    RIN_DESKTOP_TRAY_ALWAYS_OVERFLOW = 1u << 5,
    RIN_DESKTOP_TRAY_HIDE_WHEN_INACTIVE = 1u << 6,
};

enum RinDesktopNotificationFlags {
    RIN_DESKTOP_NOTIFICATION_READ = 1u << 0,
    RIN_DESKTOP_NOTIFICATION_DISMISSED = 1u << 1,
    RIN_DESKTOP_NOTIFICATION_ACTION = 1u << 2,
};

enum RinDesktopNotificationPrivacy {
    RIN_DESKTOP_NOTIFICATION_SHOW_ALL = 0,
    RIN_DESKTOP_NOTIFICATION_HIDE_LOCKED = 1,
    RIN_DESKTOP_NOTIFICATION_HIDE_BACKGROUND = 2,
};

enum RinDesktopNetworkKind {
    RIN_DESKTOP_NETWORK_DISCONNECTED = 0,
    RIN_DESKTOP_NETWORK_ETHERNET = 1,
    RIN_DESKTOP_NETWORK_WIFI = 2,
    RIN_DESKTOP_NETWORK_CELLULAR = 3,
    RIN_DESKTOP_NETWORK_BLUETOOTH_PAN = 4,
    RIN_DESKTOP_NETWORK_VIRTUAL = 5,
    RIN_DESKTOP_NETWORK_UNKNOWN = 6,
};

/* Network reachability is deliberately separate from link kind.  A device
 * can be present while it is still unconfigured or its link is down; those
 * states must not be rendered as a healthy connection.  This is not an
 * internet reachability probe: UNKNOWN remains the only honest value when a
 * provider has not supplied that evidence. */
enum RinDesktopNetworkState {
    RIN_DESKTOP_NETWORK_STATE_DISCONNECTED = 0,
    RIN_DESKTOP_NETWORK_STATE_LIMITED = 1,
    RIN_DESKTOP_NETWORK_STATE_CONNECTED = 2,
    RIN_DESKTOP_NETWORK_STATE_NO_INTERNET = 3,
    RIN_DESKTOP_NETWORK_STATE_UNKNOWN = 4,
};

enum RinDesktopNetworkReachability {
    RIN_DESKTOP_NETWORK_REACHABILITY_UNKNOWN = 0,
    RIN_DESKTOP_NETWORK_REACHABILITY_REACHABLE = 1,
    RIN_DESKTOP_NETWORK_REACHABILITY_UNREACHABLE = 2,
};

enum RinDesktopBatteryState {
    RIN_DESKTOP_BATTERY_UNKNOWN = 0,
    RIN_DESKTOP_BATTERY_DISCHARGING = 1,
    RIN_DESKTOP_BATTERY_CHARGING = 2,
    RIN_DESKTOP_BATTERY_FULL = 3,
};

/* Shared startup-silent provider presence transition values.  A provider
 * becoming unavailable is distinct from a normal disconnected/unknown
 * status, so the shell can report hotplug without replaying threshold alerts.
 */
#define RIN_DESKTOP_PROVIDER_PRESENCE_NONE      0u
#define RIN_DESKTOP_PROVIDER_PRESENCE_CONNECTED 1u
#define RIN_DESKTOP_PROVIDER_PRESENCE_REMOVED   2u

typedef struct RinDesktopWindow {
    uint32_t surface_id;
    uint32_t output_id;
    uint32_t state;
    uint32_t flags;
    uint32_t workspace;
    int32_t x;
    int32_t y;
    uint32_t width;
    uint32_t height;
    uint64_t app_identity_id;
    char app_identity[RIN_DESKTOP_IDENTITY_MAX];
    char title[RIN_DESKTOP_NAME_MAX];
    char icon_path[RIN_DESKTOP_PATH_MAX];
} RinDesktopWindow;

typedef struct RinDesktopPin {
    uint64_t app_identity_id;
    char app_identity[RIN_DESKTOP_IDENTITY_MAX];
    char name[RIN_DESKTOP_NAME_MAX];
    char executable_path[RIN_DESKTOP_PATH_MAX];
    char icon_path[RIN_DESKTOP_PATH_MAX];
} RinDesktopPin;

typedef struct RinDesktopTaskItem {
    uint64_t app_identity_id;
    uint32_t flags;
    uint32_t window_count;
    uint32_t window_ids[RIN_DESKTOP_MAX_GROUP_WINDOWS];
    uint32_t progress; /* 0..1000, UINT32_MAX means no progress */
    uint32_t badge;
    char app_identity[RIN_DESKTOP_IDENTITY_MAX];
    char name[RIN_DESKTOP_NAME_MAX];
    char icon_path[RIN_DESKTOP_PATH_MAX];
} RinDesktopTaskItem;

typedef struct RinDesktopApp {
    uint64_t app_identity_id;
    uint32_t flags; /* bit0: system, bit1: stale, bit2: pinned */
    uint32_t category;
    uint32_t launch_count;
    uint64_t last_used_ms;
    char app_identity[RIN_DESKTOP_IDENTITY_MAX];
    char name[RIN_DESKTOP_NAME_MAX];
    char localized_name[RIN_DESKTOP_NAME_MAX];
    char executable_path[RIN_DESKTOP_PATH_MAX];
    char icon_path[RIN_DESKTOP_PATH_MAX];
} RinDesktopApp;

typedef struct RinDesktopTrayItem {
    uint64_t item_id;
    uint64_t app_identity_id;
    uint64_t session_id;
    uint32_t version;
    uint32_t flags;
    uint32_t badge;
    char label[RIN_DESKTOP_LABEL_MAX];
    char tooltip[RIN_DESKTOP_NAME_MAX];
    char icon_path[RIN_DESKTOP_PATH_MAX];
    char activation[RIN_DESKTOP_LABEL_MAX];
    char context_menu[RIN_DESKTOP_LABEL_MAX];
    uint32_t menu_count;
    uint32_t reserved;
    uint32_t activation_action_id;
    uint32_t reserved_action;
    uint64_t owner_process_id;
    uint64_t owner_instance_cookie;
    uint64_t owner_connection_id;
    RinTrayMenuItemV1 menu[RIN_TRAY_MAX_MENU_ITEMS];
} RinDesktopTrayItem;

typedef struct RinDesktopNotification {
    uint64_t id;
    uint64_t app_identity_id;
    uint64_t session_id;
    uint64_t timestamp_ms;
    uint32_t flags;
    uint32_t group_id;
    char app_name[RIN_DESKTOP_NAME_MAX];
    char icon_path[RIN_DESKTOP_PATH_MAX];
    char title[RIN_DESKTOP_NAME_MAX];
    char body[RIN_DESKTOP_PATH_MAX];
    char action[RIN_DESKTOP_LABEL_MAX];
} RinDesktopNotification;

typedef struct RinDesktopLayout {
    uint32_t output_id;
    uint32_t width;
    uint32_t height;
    uint32_t scale_numerator;
    uint32_t scale_denominator;
    uint32_t taskbar_thickness;
    uint32_t icon_size;
    uint32_t item_width;
    uint32_t visible_items;
    uint32_t overflow_items;
    uint32_t tray_item_width;
    uint32_t tray_visible_items;
    uint32_t tray_overflow_items;
    uint32_t reserved_left;
    uint32_t reserved_top;
    uint32_t reserved_right;
    uint32_t reserved_bottom;
    uint8_t position;
    uint8_t hidden;
    uint8_t launcher_open;
    uint8_t notification_center_open;
} RinDesktopLayout;

typedef struct RinDesktopStatus {
    uint64_t timestamp_ms;
    uint32_t network_kind;
    uint32_t network_connected;
    uint32_t network_state;
    uint32_t network_signal_percent;
    uint32_t audio_volume;
    uint32_t audio_muted;
    uint32_t microphone_active;
    uint32_t battery_percent;
    uint32_t battery_present;
    uint32_t charging;
    uint32_t low_battery;
    uint32_t critical_battery;
    uint32_t battery_state;
    int32_t battery_minutes_remaining;
    uint32_t input_language;
    uint32_t ime_active;
    char clock_text[32];
    char date_text[32];
    char network_label[RIN_DESKTOP_LABEL_MAX];
    char network_ssid[RIN_DESKTOP_NETWORK_SSID_MAX];
    char audio_label[RIN_DESKTOP_LABEL_MAX];
    char battery_label[RIN_DESKTOP_LABEL_MAX];
    char input_label[RIN_DESKTOP_LABEL_MAX];
    char keyboard_layout_label[RIN_DESKTOP_LABEL_MAX];
    char input_method_label[RIN_DESKTOP_LABEL_MAX];
} RinDesktopStatus;

typedef struct RinDesktopAccessibilityNode {
    uint64_t node_id;
    uint64_t parent_id;
    uint32_t role;
    uint32_t state;
    char name[RIN_DESKTOP_NAME_MAX];
} RinDesktopAccessibilityNode;

typedef struct RinDesktopSettings {
    uint32_t version;
    uint32_t flags;
    uint8_t taskbar_visible;
    uint8_t tray_visible;
    uint8_t auto_hide;
    uint8_t show_on_all_outputs;
    uint8_t clock_24_hour;
    uint8_t dnd;
    uint8_t notification_privacy;
    uint8_t clock_show_seconds;
    uint32_t position;
    uint32_t output_mode;
    uint32_t theme_id;
    uint32_t reduced_motion;
    uint32_t high_contrast;
    uint32_t reduced_transparency;
    uint32_t system_icon_visibility;
    uint32_t tray_policy;
    uint32_t taskbar_use_accent_color;
    uint32_t taskbar_transparency_percent;
    uint32_t taskbar_corner_radius_px;
} RinDesktopSettings;

typedef struct RinDesktopTrayPreference {
    uint64_t session_id;
    uint64_t app_identity_id;
    uint32_t flags;
    uint32_t order;
} RinDesktopTrayPreference;

typedef struct RinDesktopModel {
    uint32_t version;
    uint64_t generation;
    RinDesktopSettings settings;
    RinDesktopWindow windows[RIN_DESKTOP_MAX_WINDOWS];
    uint32_t window_count;
    RinDesktopPin pins[RIN_DESKTOP_MAX_PINS];
    uint32_t pin_count;
    RinDesktopTrayPreference tray_preferences[RIN_DESKTOP_MAX_TRAY_PREFERENCES];
    uint32_t tray_preference_count;
    RinDesktopTaskItem tasks[RIN_DESKTOP_MAX_TASK_ITEMS];
    uint32_t task_count;
    RinDesktopApp apps[RIN_DESKTOP_MAX_APPS];
    uint32_t app_count;
    RinDesktopTrayItem tray[RIN_DESKTOP_MAX_TRAY_ITEMS];
    uint32_t tray_count;
    RinDesktopNotification notifications[RIN_DESKTOP_MAX_NOTIFICATIONS];
    uint32_t notification_count;
    uint64_t next_notification_id;
    uint64_t next_tray_id;
    uint32_t unread_notifications;
    uint64_t foreground_session_id;
    uint32_t focused_task;
    uint32_t launcher_selection;
    uint32_t launcher_match_count;
    uint32_t launcher_matches[RIN_DESKTOP_MAX_APPS];
    uint8_t launcher_open;
    uint8_t notification_center_open;
    uint8_t locked;
    uint8_t edge_reveal;
    RinDesktopStatus status;
    RinDesktopLayout layouts[8];
    uint32_t layout_count;
    RinDesktopAccessibilityNode accessibility[RIN_DESKTOP_MAX_ACCESSIBILITY_NODES];
    uint32_t accessibility_count;
} RinDesktopModel;

void rin_desktop_model_init(RinDesktopModel* model);
int rin_desktop_model_set_windows(RinDesktopModel* model,
                                  const RinDesktopWindow* windows,
                                  uint32_t count);
int rin_desktop_model_pin(RinDesktopModel* model, const RinDesktopPin* pin);
int rin_desktop_model_unpin(RinDesktopModel* model, uint64_t app_identity_id);
int rin_desktop_model_reorder_pin(RinDesktopModel* model, uint32_t from,
                                  uint32_t to);
int rin_desktop_model_remove_stale_pins(RinDesktopModel* model);
int rin_desktop_model_task_action(const RinDesktopModel* model,
                                  uint32_t task_index);
int rin_desktop_model_context_action(const RinDesktopModel* model,
                                    uint32_t task_index,
                                    uint32_t action);
int rin_desktop_model_set_task_visual_state(RinDesktopModel* model,
                                            uint32_t task_index,
                                            uint32_t flags, uint32_t progress,
                                            uint32_t badge);
int rin_desktop_model_add_app(RinDesktopModel* model, const RinDesktopApp* app);
int rin_desktop_model_mark_app_stale(RinDesktopModel* model,
                                     uint64_t app_identity_id, int stale);
uint32_t rin_desktop_model_search(RinDesktopModel* model, const char* query,
                                  int fuzzy);
int rin_desktop_model_record_launch(RinDesktopModel* model,
                                    uint64_t app_identity_id,
                                    uint64_t now_ms);
int rin_desktop_model_register_tray(RinDesktopModel* model,
                                    const RinDesktopTrayItem* item,
                                    uint64_t session_id,
                                    uint64_t app_identity_id,
                                    uint64_t* item_id);
int rin_desktop_model_update_tray(RinDesktopModel* model,
                                  const RinDesktopTrayItem* item,
                                  uint64_t session_id);
int rin_desktop_model_unregister_tray(RinDesktopModel* model,
                                     uint64_t item_id, uint64_t session_id);
int rin_desktop_model_remove_tray_owner(RinDesktopModel* model,
                                        uint64_t session_id,
                                        uint64_t app_identity_id,
                                        uint64_t process_id,
                                        uint64_t instance_cookie,
                                        uint64_t connection_id);
/* Remove every application tray item belonging to one ended session. */
int rin_desktop_model_remove_tray_session(RinDesktopModel* model,
                                          uint64_t session_id);
int rin_desktop_model_set_tray_visual_state(RinDesktopModel* model,
                                            uint64_t item_id, uint32_t flags);
int rin_desktop_model_set_tray_preference(
    RinDesktopModel* model, uint64_t session_id, uint64_t app_identity_id,
    uint32_t flags, uint32_t order);
int rin_desktop_model_reorder_tray(RinDesktopModel* model, uint32_t from,
                                   uint32_t to);
int rin_desktop_model_set_foreground_session(RinDesktopModel* model,
                                             uint64_t session_id);
int rin_desktop_model_post_notification(RinDesktopModel* model,
                                        const RinDesktopNotification* item,
                                        uint64_t now_ms);
int rin_desktop_model_dismiss_notification(RinDesktopModel* model,
                                           uint64_t id);
void rin_desktop_model_mark_notifications_read(RinDesktopModel* model);
void rin_desktop_model_set_status(RinDesktopModel* model,
                                  const RinDesktopStatus* status);

/* Classify link evidence and, when explicitly supplied, an authenticated
 * reachability result. Unknown reachability never becomes a healthy or
 * failed internet state. */
uint32_t rin_desktop_model_network_state(int device_ready, int configured,
                                         int link_known, int link_up);
uint32_t rin_desktop_model_network_state_with_reachability(
    int device_ready, int configured, int link_known, int link_up,
    uint32_t reachability);
/* Returns 0 for no actionable alert, 1 for low, and 2 for critical. */
uint32_t rin_desktop_model_battery_alert_level(
    const RinDesktopStatus* status);
int rin_desktop_model_battery_percent_valid(int32_t battery_percent);
/* Returns the newly entered alert level, or 0 when no new alert is due. */
uint32_t rin_desktop_model_battery_alert_transition(
    uint32_t previous_level, const RinDesktopStatus* status);
uint32_t rin_desktop_model_provider_presence_transition(
    int previous_valid, int previous_present, int current_present);
/* Presence transitions are separate from low/critical alerts. The first
 * sample is intentionally silent so startup cannot look like a hotplug. */
#define RIN_DESKTOP_BATTERY_PRESENCE_NONE      RIN_DESKTOP_PROVIDER_PRESENCE_NONE
#define RIN_DESKTOP_BATTERY_PRESENCE_CONNECTED RIN_DESKTOP_PROVIDER_PRESENCE_CONNECTED
#define RIN_DESKTOP_BATTERY_PRESENCE_REMOVED   RIN_DESKTOP_PROVIDER_PRESENCE_REMOVED
uint32_t rin_desktop_model_battery_presence_transition(
    int previous_valid, int previous_present, const RinDesktopStatus* status);
/* Returns whether an output ordinal owns the taskbar/status area under the
 * current settings.  Ordinal zero is the compositor's primary output. */
int rin_desktop_model_output_has_taskbar(const RinDesktopModel* model,
                                         uint32_t output_ordinal);
int rin_desktop_model_compute_layout(RinDesktopModel* model, uint32_t output_id,
                                     uint32_t width, uint32_t height,
                                     uint32_t scale_numerator,
                                     uint32_t scale_denominator);
int rin_desktop_model_edge_reveal(RinDesktopModel* model, uint32_t output_id,
                                  int pointer_at_edge, int important_ui);
uint32_t rin_desktop_model_build_accessibility(RinDesktopModel* model);
int rin_desktop_model_serialize_settings(const RinDesktopModel* model,
                                         uint8_t* output, uint32_t capacity,
                                         uint32_t* size);
int rin_desktop_model_deserialize_settings(RinDesktopModel* model,
                                           const uint8_t* input, uint32_t size);

#ifdef __cplusplus
}
#endif

#endif
