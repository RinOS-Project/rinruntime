/* SPDX-License-Identifier: MIT */
/* RinRuntime clients for Installer's capability-backed storage syscalls. */

#ifndef RINRUNTIME_INSTALLER_RUNTIME_H
#define RINRUNTIME_INSTALLER_RUNTIME_H

#include <stdint.h>

#include <rin/contract_abi.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns the visible block-device count, or a negative RinResultCode. */
int32_t rin_app_block_count(void);

/* Enumerates the stable V1 inventory ABI used by existing applications. */
RinResultCode rin_app_block_enumerate(uint32_t index,
                                      RinBlockInfoV1* info_out);

/* Returns the live V2 snapshot. A root ID may describe only a registration;
 * callers that need physical-media separation must also require the
 * MEDIA_UNIQUE_ATTESTED flag. */
RinResultCode rin_app_block_get_info_v2(uint32_t block_id,
                                        RinBlockInfoV2* info_out);

/* V3 includes both the registration-root coordinate and conservative alias
 * group used to correlate reported media identifiers. */
RinResultCode rin_app_block_get_info_v3(uint32_t block_id,
                                        RinBlockInfoV3* info_out);

/* Returns the alias-group ID only when generation, ancestry, and unique
 * physical-medium attestation are all present. Equal IDs are a conservative
 * alias signal; distinct IDs still require the attestation flags. */
RinResultCode rin_app_block_physical_device_id(
    uint32_t block_id, uint32_t* physical_device_id_out);

RinResultCode rin_app_install_target_open(
    uint32_t block_id, uint64_t minimum_blocks,
    RinInstallTargetSessionV1* session_out);
/* Opens a read-only lease that can include removable backup media. The
 * returned handle has no writable transaction path. */
RinResultCode rin_app_install_backup_source_open(
    uint32_t block_id, uint64_t minimum_blocks,
    RinInstallTargetSessionV1* session_out);
/* Registers the lifetime of one user-space RinFS cache on this target root.
 * A live lease prevents a destructive maintenance transaction from starting. */
RinResultCode rin_app_install_target_rinfs_mount_begin(
    uint64_t target_handle, uint64_t first_lba, uint64_t sector_count,
    uint64_t* mount_lease_token_out);
RinResultCode rin_app_install_target_rinfs_mount_end(
    uint64_t target_handle, uint64_t mount_lease_token);
/* Registers any user-space RinFS cache against the live block-root range.
 * The owner-bound lease is released only after mount owners and mappings drain. */
RinResultCode rin_app_rinfs_cache_lease_begin(
    uint32_t block_id, uint64_t first_lba, uint64_t sector_count,
    uint64_t* mount_lease_token_out);
/* Binds fork eligibility to the caller's exact writable full SHM mapping.
 * The kernel resolves the mapping to its own segment ID and generation. */
RinResultCode rin_app_rinfs_cache_lease_begin_shared(
    uint32_t block_id, uint64_t first_lba, uint64_t sector_count,
    const void* mapping_base, uint64_t mapping_size,
    uint64_t* mount_lease_token_out);
enum {
    RINFS_SHARED_LEASE_READY = 1u,
    RINFS_SHARED_LEASE_RELEASE_UNMOUNTED = 2u,
    RINFS_SHARED_LEASE_BEGIN_UNMOUNT = 3u,
    RINFS_SHARED_LEASE_FINISH = 4u
};
RinResultCode rin_app_rinfs_cache_lease_shared_transition(
    const void* mapping_base, uint64_t mapping_size, uint32_t action,
    uint64_t mount_lease_token, uint32_t* final_owner_out);
RinResultCode rin_app_rinfs_cache_lease_end(uint64_t mount_lease_token);
RinResultCode rin_app_install_target_validate(uint64_t handle);
RinResultCode rin_app_install_target_close(uint64_t handle);
RinResultCode rin_app_install_target_authorize(uint64_t target_handle,
                                                uint64_t source_handle);
RinResultCode rin_app_install_target_read(uint64_t handle, uint64_t lba,
                                          uint32_t block_count,
                                          void* output);
RinResultCode rin_app_install_target_write(uint64_t handle, uint64_t lba,
                                           uint32_t block_count,
                                           const void* input,
                                           uint16_t flags);
RinResultCode rin_app_install_target_flush(uint64_t handle);
RinResultCode rin_app_install_target_end(uint64_t handle);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_INSTALLER_RUNTIME_H */
