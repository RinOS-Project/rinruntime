/* SPDX-License-Identifier: MIT */
/* Public application-side Audio Service client.  PCM travels through RinSHM. */
#ifndef RINRUNTIME_RIN_AUDIO_SERVICE_CLIENT_H
#define RINRUNTIME_RIN_AUDIO_SERVICE_CLIENT_H

#include <stdint.h>

#include <rin/audio/service_abi.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The process owns one authenticated client session.  Its descriptor,
 * connection cookie, stream table, and SHM mappings remain private to the
 * implementation; callers use this lifecycle rather than touching transport
 * state. */
int rin_audio_service_client_init(void);
int rin_audio_service_client_connect(void);
int rin_audio_service_client_disconnect(void);
int rin_audio_service_client_is_connected(void);
void rin_audio_service_client_reset(void);
int rin_audio_service_stream_create(uint32_t sample_rate, uint32_t channels,
                                    uint32_t sample_format,
                                    uint32_t capacity_frames);
int rin_audio_service_stream_create_category(
    uint32_t sample_rate, uint32_t channels, uint32_t sample_format,
    uint32_t capacity_frames, uint32_t category);
/* A non-zero device_id requests that exact generation-bound route.  The
 * service rejects it when no matching backend is currently selected/bound. */
int rin_audio_service_stream_create_category_for_device(
    uint32_t sample_rate, uint32_t channels, uint32_t sample_format,
    uint32_t capacity_frames, uint64_t device_id, uint32_t category);
int rin_audio_service_capture_stream_create(uint32_t sample_rate,
                                            uint32_t channels,
                                            uint32_t sample_format,
                                            uint32_t capacity_frames);
int rin_audio_service_capture_stream_create_for_device(
    uint32_t sample_rate, uint32_t channels, uint32_t sample_format,
    uint32_t capacity_frames, uint64_t device_id);
int rin_audio_service_stream_destroy(int stream);
int rin_audio_service_stream_write(int stream, const void* samples,
                                   uint32_t bytes);
int rin_audio_service_capture_stream_read(int stream, void* samples,
                                          uint32_t bytes);
int rin_audio_service_stream_start(int stream);
int rin_audio_service_stream_pause(int stream);
int rin_audio_service_stream_resume(int stream);
int rin_audio_service_stream_drain(int stream);
int rin_audio_service_stream_flush(int stream);
int rin_audio_service_stream_set_volume(int stream, uint32_t volume);
int rin_audio_service_stream_set_mute(int stream, uint32_t muted);
int rin_audio_service_stream_set_pan(int stream, int32_t pan);
int rin_audio_service_client_set_policy(
    const RinRuntimeAudioPolicyCatalogV1* policy);
int rin_audio_service_client_set_application_volume(uint32_t volume);
int rin_audio_service_client_set_application_mute(uint32_t muted);
int rin_audio_service_client_set_master_volume(uint32_t volume);
int rin_audio_service_client_set_master_mute(uint32_t muted);
int rin_audio_service_client_set_input_volume(uint32_t volume);
int rin_audio_service_client_set_input_mute(uint32_t muted);
int rin_audio_service_client_set_category_volume(uint32_t category,
                                                 uint32_t volume);
int rin_audio_service_client_set_category_mute(uint32_t category,
                                               uint32_t muted);
int rin_audio_service_stream_status(int stream,
                                    RinAudioServiceStatusV1* status);
int rin_audio_service_probe(RinAudioServiceStatusV1* status);
int rin_audio_service_client_devices(RinAudioServiceDeviceListV1* devices);
int rin_audio_service_select_output(uint64_t device_id, uint64_t generation);
int rin_audio_service_select_input(uint64_t device_id, uint64_t generation);
int rin_audio_service_test_tone(void);
int rin_audio_service_system_notification_tone(void);
int rin_audio_service_system_login_tone(void);
int rin_audio_service_system_logout_tone(void);
int rin_audio_service_system_error_tone(void);
int rin_audio_service_client_poll_events(RinAudioServiceEventBatchV1* events);
int rin_audio_service_client_diagnostics(RinAudioServiceDiagnosticsV1* diagnostics);
int rin_audio_service_client_applications(
    RinAudioServiceApplicationSnapshotListV1* applications);
int rin_audio_service_client_set_application_volume_for(
    uint64_t application_id, uint64_t application_generation,
    uint32_t volume);
int rin_audio_service_client_set_application_mute_for(
    uint64_t application_id, uint64_t application_generation,
    uint32_t muted);

/* Operations that change process-wide or another application's state require
 * the service-issued system-admin capability.  These names make that policy
 * explicit; the older names below remain source-compatible aliases. */
int rin_audio_admin_set_policy(const RinRuntimeAudioPolicyCatalogV1* policy);
int rin_audio_admin_set_master_volume(uint32_t volume);
int rin_audio_admin_set_master_mute(uint32_t muted);
int rin_audio_admin_set_input_volume(uint32_t volume);
int rin_audio_admin_set_input_mute(uint32_t muted);
int rin_audio_admin_set_category_volume(uint32_t category, uint32_t volume);
int rin_audio_admin_set_category_mute(uint32_t category, uint32_t muted);
int rin_audio_admin_select_output(uint64_t device_id, uint64_t generation);
int rin_audio_admin_select_input(uint64_t device_id, uint64_t generation);
int rin_audio_admin_applications(
    RinAudioServiceApplicationSnapshotListV1* applications);
int rin_audio_admin_set_application_volume_for(
    uint64_t application_id, uint64_t application_generation,
    uint32_t volume);
int rin_audio_admin_set_application_mute_for(
    uint64_t application_id, uint64_t application_generation,
    uint32_t muted);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_RIN_AUDIO_SERVICE_CLIENT_H */
