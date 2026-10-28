/* SPDX-License-Identifier: MIT */
/* Public adapters for kernel-owned installer target sessions. */

#include "../include/rinruntime/rin_installer_runtime.h"
#include "../include/rinruntime/rinfs/rinfs.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include <rin/syscall_abi.h>

#if !defined(_WIN32)
#include <libc/sys/syscall.h>
#endif

static RinResultCode installer_runtime_result(intptr_t result)
{
    if (result == 0) return RIN_RESULT_OK;
    if (result < 0 && result >= INT32_MIN)
        return (RinResultCode)(int32_t)result;
    return RIN_RESULT_IO;
}

static void installer_runtime_zero(void* memory, size_t size)
{
    volatile uint8_t* bytes = (volatile uint8_t*)memory;
    if (bytes == NULL) return;
    while (size != 0u) {
        *bytes++ = 0u;
        --size;
    }
}

#if !defined(_WIN32)
static intptr_t installer_runtime_syscall(
    uintptr_t syscall_number,
    const uint64_t* arguments,
    uint32_t argument_count,
    uint32_t wide_argument_mask,
    int ia32_carrier,
    uint64_t* wide_return_out)
{
    if (wide_return_out != NULL) *wide_return_out = 0u;
    if ((argument_count != 0u && arguments == NULL) || argument_count > 5u)
        return (intptr_t)RIN_RESULT_INVALID_ARGUMENT;
#if UINTPTR_MAX == UINT32_MAX
    if (ia32_carrier) {
        RinSyscallWideArgsV1 carrier;
        intptr_t result;
        uint32_t index;
        installer_runtime_zero(&carrier, sizeof(carrier));
        carrier.struct_size = (uint32_t)sizeof(carrier);
        carrier.version = RIN_CONTRACT_STRUCT_VERSION_1;
        carrier.argument_count = (uint16_t)argument_count;
        for (index = 0u; index < argument_count; ++index)
            carrier.arguments[index] = arguments[index];
        result = _syscall1(syscall_number, (uintptr_t)&carrier);
        if (result >= 0 && wide_return_out != NULL)
            *wide_return_out = carrier.result;
        installer_runtime_zero(&carrier, sizeof(carrier));
        return result;
    }
    {
        uint32_t raw[6] = {0u};
        uint32_t raw_count = 0u;
        uint32_t index;
        for (index = 0u; index < argument_count; ++index) {
            const uint64_t value = arguments[index];
            if ((wide_argument_mask & (1u << index)) != 0u) {
                if (raw_count > 4u)
                    return (intptr_t)RIN_RESULT_INVALID_ARGUMENT;
                raw[raw_count++] = (uint32_t)value;
                raw[raw_count++] = (uint32_t)(value >> 32);
            } else {
                if (value > UINT32_MAX || raw_count >= 6u)
                    return (intptr_t)RIN_RESULT_INVALID_ARGUMENT;
                raw[raw_count++] = (uint32_t)value;
            }
        }
        switch (raw_count) {
            case 0u: return _syscall0(syscall_number);
            case 1u: return _syscall1(syscall_number, raw[0]);
            case 2u: return _syscall2(syscall_number, raw[0], raw[1]);
            case 3u: return _syscall3(syscall_number, raw[0], raw[1], raw[2]);
            case 4u: return _syscall4(syscall_number, raw[0], raw[1], raw[2], raw[3]);
            case 5u: return _syscall5(syscall_number, raw[0], raw[1], raw[2], raw[3], raw[4]);
            case 6u: return _syscall6(syscall_number, raw[0], raw[1], raw[2], raw[3], raw[4], raw[5]);
            default: return (intptr_t)RIN_RESULT_INVALID_ARGUMENT;
        }
    }
#else
    intptr_t result;
    (void)wide_argument_mask;
    (void)ia32_carrier;
    switch (argument_count) {
        case 0u: result = _syscall0(syscall_number); break;
        case 1u: result = _syscall1(syscall_number, (uintptr_t)arguments[0]); break;
        case 2u:
            result = _syscall2(syscall_number, (uintptr_t)arguments[0],
                               (uintptr_t)arguments[1]);
            break;
        case 3u:
            result = _syscall3(syscall_number, (uintptr_t)arguments[0],
                               (uintptr_t)arguments[1],
                               (uintptr_t)arguments[2]);
            break;
        case 4u:
            result = _syscall4(syscall_number, (uintptr_t)arguments[0],
                               (uintptr_t)arguments[1],
                               (uintptr_t)arguments[2],
                               (uintptr_t)arguments[3]);
            break;
        case 5u:
            result = _syscall5(syscall_number, (uintptr_t)arguments[0],
                               (uintptr_t)arguments[1],
                               (uintptr_t)arguments[2],
                               (uintptr_t)arguments[3],
                               (uintptr_t)arguments[4]);
            break;
        default:
            return (intptr_t)RIN_RESULT_INVALID_ARGUMENT;
    }
    if (result >= 0 && wide_return_out != NULL)
        *wide_return_out = (uint64_t)result;
    return result;
#endif
}
#endif

static int installer_block_info_v1_valid(const RinBlockInfoV1* info)
{
    return info != NULL && info->struct_size == sizeof(*info) &&
           info->version == RIN_CONTRACT_STRUCT_VERSION_1 &&
           info->block_id != 0u && info->logical_block_size != 0u &&
           info->physical_block_size >= info->logical_block_size &&
           info->block_count != 0u && info->max_transfer_blocks != 0u;
}

int32_t rin_app_block_count(void)
{
#if defined(_WIN32)
    return (int32_t)RIN_RESULT_NOT_SUPPORTED;
#else
    intptr_t result = _syscall0((uintptr_t)RIN_SYS_BLOCK_GET_COUNT);
    if (result < 0) return result >= INT32_MIN ? (int32_t)result
                                               : (int32_t)RIN_RESULT_IO;
    if (result > INT32_MAX) return (int32_t)RIN_RESULT_LIMIT_EXCEEDED;
    return (int32_t)result;
#endif
}

RinResultCode rin_app_block_enumerate(uint32_t index,
                                      RinBlockInfoV1* info_out)
{
    RinBlockInfoV1 result_info;
    intptr_t result;
    if (info_out == NULL) return RIN_RESULT_INVALID_ARGUMENT;
    installer_runtime_zero(info_out, sizeof(*info_out));
    installer_runtime_zero(&result_info, sizeof(result_info));
    result_info.struct_size = (uint32_t)sizeof(result_info);
    result_info.version = RIN_CONTRACT_STRUCT_VERSION_1;
#if defined(_WIN32)
    (void)index;
    return RIN_RESULT_NOT_SUPPORTED;
#else
    result = _syscall3((uintptr_t)RIN_SYS_BLOCK_ENUMERATE,
                       (uintptr_t)index, (uintptr_t)&result_info,
                       (uintptr_t)sizeof(result_info));
    if (installer_runtime_result(result) != RIN_RESULT_OK)
        return installer_runtime_result(result);
    if (!installer_block_info_v1_valid(&result_info))
        return RIN_RESULT_CORRUPT_DATA;
    *info_out = result_info;
    return RIN_RESULT_OK;
#endif
}

RinResultCode rin_app_block_get_info_v2(uint32_t block_id,
                                        RinBlockInfoV2* info_out)
{
    RinBlockInfoV2 info;
    intptr_t result;
    if (info_out != NULL) installer_runtime_zero(info_out, sizeof(*info_out));
    if (block_id == 0u || info_out == NULL)
        return RIN_RESULT_INVALID_ARGUMENT;
    installer_runtime_zero(&info, sizeof(info));
    info.struct_size = (uint32_t)sizeof(info);
    info.version = RIN_BLOCK_INFO_VERSION_2;
#if defined(_WIN32)
    return RIN_RESULT_NOT_SUPPORTED;
#else
    result = _syscall3((uintptr_t)RIN_SYS_BLOCK_GET_INFO,
                       (uintptr_t)block_id, (uintptr_t)&info,
                       (uintptr_t)sizeof(info));
    if (installer_runtime_result(result) != RIN_RESULT_OK)
        return installer_runtime_result(result);
    if (info.struct_size != sizeof(info) ||
        info.version != RIN_BLOCK_INFO_VERSION_2 ||
        info.block_id != block_id ||
        info.physical_device_id == 0u ||
        (info.identity_flags & ~RIN_BLOCK_IDENTITY_FLAG_MASK) != 0u ||
        info.reserved0 != 0u) {
        installer_runtime_zero(&info, sizeof(info));
        return RIN_RESULT_CORRUPT_DATA;
    }
    *info_out = info;
    installer_runtime_zero(&info, sizeof(info));
    return RIN_RESULT_OK;
#endif
}

RinResultCode rin_app_block_get_info_v3(uint32_t block_id,
                                        RinBlockInfoV3* info_out)
{
    RinBlockInfoV3 info;
    intptr_t result;
    if (info_out != NULL) installer_runtime_zero(info_out, sizeof(*info_out));
    if (block_id == 0u || info_out == NULL)
        return RIN_RESULT_INVALID_ARGUMENT;
    installer_runtime_zero(&info, sizeof(info));
    info.struct_size = (uint32_t)sizeof(info);
    info.version = RIN_BLOCK_INFO_VERSION_3;
#if defined(_WIN32)
    return RIN_RESULT_NOT_SUPPORTED;
#else
    result = _syscall3((uintptr_t)RIN_SYS_BLOCK_GET_INFO,
                       (uintptr_t)block_id, (uintptr_t)&info,
                       (uintptr_t)sizeof(info));
    if (installer_runtime_result(result) != RIN_RESULT_OK)
        return installer_runtime_result(result);
    if (info.struct_size != sizeof(info) ||
        info.version != RIN_BLOCK_INFO_VERSION_3 ||
        info.block_id != block_id || info.root_registration_id == 0u ||
        (info.identity_flags & ~RIN_BLOCK_IDENTITY_FLAG_MASK) != 0u ||
        ((info.physical_device_id == 0u) !=
         (info.identity_flags == 0u)) ||
        info.reserved0 != 0u || info.reserved1 != 0u) {
        installer_runtime_zero(&info, sizeof(info));
        return RIN_RESULT_CORRUPT_DATA;
    }
    *info_out = info;
    installer_runtime_zero(&info, sizeof(info));
    return RIN_RESULT_OK;
#endif
}

RinResultCode rin_app_block_physical_device_id(
    uint32_t block_id, uint32_t* physical_device_id_out)
{
    RinBlockInfoV3 info;
    const uint32_t required_flags =
        RIN_BLOCK_IDENTITY_FLAG_GENERATION_BOUND |
        RIN_BLOCK_IDENTITY_FLAG_ANCESTRY_COMPLETE |
        RIN_BLOCK_IDENTITY_FLAG_MEDIA_UNIQUE_ATTESTED;
    RinResultCode result;
    if (physical_device_id_out != NULL) *physical_device_id_out = 0u;
    if (physical_device_id_out == NULL)
        return RIN_RESULT_INVALID_ARGUMENT;
    installer_runtime_zero(&info, sizeof(info));
    result = rin_app_block_get_info_v3(block_id, &info);
    if (result != RIN_RESULT_OK) return result;
    if (info.physical_device_id == 0u ||
        (info.identity_flags & required_flags) != required_flags) {
        installer_runtime_zero(&info, sizeof(info));
        return RIN_RESULT_NOT_SUPPORTED;
    }
    *physical_device_id_out = info.physical_device_id;
    installer_runtime_zero(&info, sizeof(info));
    return RIN_RESULT_OK;
}

static RinResultCode installer_target_open_with_syscall(
    uintptr_t syscall_number,
    uint32_t block_id, uint64_t minimum_blocks,
    RinInstallTargetSessionV1* session_out)
{
    RinInstallTargetSessionV1 session;
    intptr_t result;
    if (session_out == NULL) return RIN_RESULT_INVALID_ARGUMENT;
    installer_runtime_zero(session_out, sizeof(*session_out));
    if (block_id == 0u || minimum_blocks == 0u)
        return RIN_RESULT_INVALID_ARGUMENT;
    installer_runtime_zero(&session, sizeof(session));
    session.struct_size = (uint32_t)sizeof(session);
    session.version = RIN_CONTRACT_STRUCT_VERSION_1;
#if defined(_WIN32)
    (void)syscall_number;
    return RIN_RESULT_NOT_SUPPORTED;
#else
    {
        const uint64_t arguments[3] = {
            block_id, minimum_blocks, (uintptr_t)&session
        };
        result = installer_runtime_syscall(
            syscall_number, arguments, 3u, 1u << 1, 0, NULL);
    }
    if (installer_runtime_result(result) != RIN_RESULT_OK)
        return installer_runtime_result(result);
    if (session.struct_size != sizeof(session) ||
        session.version != RIN_CONTRACT_STRUCT_VERSION_1 ||
        session.handle == 0u ||
        session.block_id != block_id ||
        session.block_count < minimum_blocks ||
        session.logical_block_size == 0u ||
        session.physical_block_size < session.logical_block_size ||
        session.max_transfer_blocks == 0u) {
        if (session.handle != 0u) {
            const uint64_t close_arguments[1] = {session.handle};
            (void)installer_runtime_syscall(
                (uintptr_t)RIN_SYS_INSTALL_TARGET_CLOSE,
                close_arguments, 1u, 1u, 0, NULL);
        }
        installer_runtime_zero(&session, sizeof(session));
        return RIN_RESULT_CORRUPT_DATA;
    }
    *session_out = session;
    installer_runtime_zero(&session, sizeof(session));
    return RIN_RESULT_OK;
#endif
}

RinResultCode rin_app_install_target_open(
    uint32_t block_id, uint64_t minimum_blocks,
    RinInstallTargetSessionV1* session_out)
{
    return installer_target_open_with_syscall(
        (uintptr_t)RIN_SYS_INSTALL_TARGET_OPEN, block_id, minimum_blocks,
        session_out);
}

RinResultCode rin_app_install_backup_destination_open(
    uint32_t block_id, uint64_t minimum_blocks,
    RinInstallTargetSessionV1* session_out)
{
    return installer_target_open_with_syscall(
        (uintptr_t)RIN_SYS_INSTALL_BACKUP_DESTINATION_OPEN, block_id,
        minimum_blocks, session_out);
}

RinResultCode rin_app_install_backup_source_open(
    uint32_t block_id, uint64_t minimum_blocks,
    RinInstallTargetSessionV1* session_out)
{
    return installer_target_open_with_syscall(
        (uintptr_t)RIN_SYS_INSTALL_BACKUP_SOURCE_OPEN, block_id,
        minimum_blocks, session_out);
}

RinResultCode rin_app_install_target_rinfs_mount_begin(
    uint64_t target_handle, uint64_t first_lba, uint64_t sector_count,
    uint64_t* mount_lease_token_out)
{
#if !defined(_WIN32)
    intptr_t result;
    uint64_t mount_lease_token = 0u;
#endif
    if (mount_lease_token_out) *mount_lease_token_out = 0u;
    if (target_handle == 0u || sector_count == 0u || !mount_lease_token_out)
        return RIN_RESULT_INVALID_ARGUMENT;
#if defined(_WIN32)
    return RIN_RESULT_NOT_SUPPORTED;
#else
    {
        const uint64_t arguments[3] = {
            target_handle, first_lba, sector_count
        };
        result = installer_runtime_syscall(
            (uintptr_t)RIN_SYS_INSTALL_TARGET_RINFS_MOUNT_BEGIN,
            arguments, 3u, 0x7u, 1, &mount_lease_token);
    }
    if (result < 0) return installer_runtime_result(result);
    if (mount_lease_token == 0u) return RIN_RESULT_IO;
    *mount_lease_token_out = mount_lease_token;
    return RIN_RESULT_OK;
#endif
}

RinResultCode rin_app_install_target_rinfs_mount_end(
    uint64_t target_handle, uint64_t mount_lease_token)
{
    if (target_handle == 0u || mount_lease_token == 0u)
        return RIN_RESULT_INVALID_HANDLE;
#if defined(_WIN32)
    return RIN_RESULT_NOT_SUPPORTED;
#else
    {
        const uint64_t arguments[2] = {target_handle, mount_lease_token};
        return installer_runtime_result(installer_runtime_syscall(
            (uintptr_t)RIN_SYS_INSTALL_TARGET_RINFS_MOUNT_END,
            arguments, 2u, 0x3u, 0, NULL));
    }
#endif
}

RinResultCode rin_app_rinfs_cache_lease_begin(
    uint32_t block_id, uint64_t first_lba, uint64_t sector_count,
    uint64_t* mount_lease_token_out)
{
#if !defined(_WIN32)
    intptr_t result;
    uint64_t mount_lease_token = 0u;
#endif
    if (mount_lease_token_out) *mount_lease_token_out = 0u;
    if (block_id == 0u || !mount_lease_token_out ||
        (sector_count != 0u && first_lba > UINT64_MAX - sector_count))
        return RIN_RESULT_INVALID_ARGUMENT;
#if defined(_WIN32)
    return RIN_RESULT_NOT_SUPPORTED;
#else
    {
        const uint64_t arguments[3] = {block_id, first_lba, sector_count};
        result = installer_runtime_syscall(
            (uintptr_t)RIN_SYS_RINFS_CACHE_LEASE_BEGIN,
            arguments, 3u, (1u << 1) | (1u << 2), 1,
            &mount_lease_token);
    }
    if (result < 0) return installer_runtime_result(result);
    if (mount_lease_token == 0u) return RIN_RESULT_IO;
    *mount_lease_token_out = mount_lease_token;
    return RIN_RESULT_OK;
#endif
}

RinResultCode rin_app_rinfs_cache_lease_begin_shared(
    uint32_t block_id, uint64_t first_lba, uint64_t sector_count,
    const void* mapping_base, uint64_t mapping_size,
    uint64_t* mount_lease_token_out)
{
#if !defined(_WIN32)
    intptr_t result;
#endif
    if (mount_lease_token_out) *mount_lease_token_out = 0u;
    if (block_id == 0u || !mapping_base || mapping_size == 0u ||
        !mount_lease_token_out ||
        (sector_count != 0u && first_lba > UINT64_MAX - sector_count) ||
        mapping_size > (uint64_t)UINTPTR_MAX ||
        (uintptr_t)mapping_base > UINTPTR_MAX - (uintptr_t)mapping_size)
        return RIN_RESULT_INVALID_ARGUMENT;
#if defined(_WIN32)
    return RIN_RESULT_NOT_SUPPORTED;
#else
    {
        const uint64_t arguments[5] = {
            block_id, first_lba, sector_count,
            (uintptr_t)mapping_base, mapping_size
        };
        result = installer_runtime_syscall(
            (uintptr_t)RIN_SYS_RINFS_CACHE_LEASE_BEGIN_SHARED,
            arguments, 5u, 0x1eu, 1, mount_lease_token_out);
    }
    if (result < 0) return installer_runtime_result(result);
    if (*mount_lease_token_out == 0u) return RIN_RESULT_IO;
    return RIN_RESULT_OK;
#endif
}

RinResultCode rin_app_rinfs_cache_lease_shared_transition(
    const void* mapping_base, uint64_t mapping_size, uint32_t action,
    uint64_t mount_lease_token, uint32_t* final_owner_out)
{
#if !defined(_WIN32)
    intptr_t result;
#endif
    if (final_owner_out) *final_owner_out = 0u;
    if (!mapping_base || mapping_size == 0u || mount_lease_token == 0u ||
        !final_owner_out ||
        mapping_size > (uint64_t)UINTPTR_MAX ||
        (uintptr_t)mapping_base > UINTPTR_MAX - (uintptr_t)mapping_size ||
        action < RINFS_SHARED_LEASE_READY ||
        action > RINFS_SHARED_LEASE_EXEC_RESUME)
        return RIN_RESULT_INVALID_ARGUMENT;
#if defined(_WIN32)
    return RIN_RESULT_NOT_SUPPORTED;
#else
    {
        const uint64_t arguments[4] = {
            (uintptr_t)mapping_base, mapping_size, action, mount_lease_token
        };
        result = installer_runtime_syscall(
            (uintptr_t)RIN_SYS_RINFS_CACHE_LEASE_SHARED_TRANSITION,
            arguments, 4u, (1u << 0) | (1u << 1) | (1u << 3), 1, NULL);
    }
    if (result < 0) return installer_runtime_result(result);
    if (action == RINFS_SHARED_LEASE_OWNER_QUERY) {
        if (result <= 0 || result > (intptr_t)RINFS_SHARED_OWNER_CAPACITY)
            return RIN_RESULT_IO;
    } else if (result > 1 || (result == 1 &&
                              action != RINFS_SHARED_LEASE_BEGIN_UNMOUNT)) {
        return RIN_RESULT_IO;
    }
    *final_owner_out = (uint32_t)result;
    return RIN_RESULT_OK;
#endif
}

RinResultCode rin_app_rinfs_cache_lease_end(uint64_t mount_lease_token)
{
    if (mount_lease_token == 0u)
        return RIN_RESULT_INVALID_ARGUMENT;
#if defined(_WIN32)
    return RIN_RESULT_NOT_SUPPORTED;
#else
    {
        const uint64_t arguments[1] = {mount_lease_token};
        return installer_runtime_result(installer_runtime_syscall(
            (uintptr_t)RIN_SYS_RINFS_CACHE_LEASE_END,
            arguments, 1u, 1u, 0, NULL));
    }
#endif
}

RinResultCode rin_app_install_target_validate(uint64_t handle)
{
    if (handle == 0u)
        return RIN_RESULT_INVALID_HANDLE;
#if defined(_WIN32)
    return RIN_RESULT_NOT_SUPPORTED;
#else
    {
        const uint64_t arguments[1] = {handle};
        return installer_runtime_result(installer_runtime_syscall(
            (uintptr_t)RIN_SYS_INSTALL_TARGET_VALIDATE,
            arguments, 1u, 1u, 0, NULL));
    }
#endif
}

RinResultCode rin_app_install_target_close(uint64_t handle)
{
    if (handle == 0u)
        return RIN_RESULT_INVALID_HANDLE;
#if defined(_WIN32)
    return RIN_RESULT_NOT_SUPPORTED;
#else
    {
        const uint64_t arguments[1] = {handle};
        return installer_runtime_result(installer_runtime_syscall(
            (uintptr_t)RIN_SYS_INSTALL_TARGET_CLOSE,
            arguments, 1u, 1u, 0, NULL));
    }
#endif
}

RinResultCode rin_app_install_target_authorize(uint64_t target_handle,
                                                uint64_t source_handle)
{
    if (target_handle == 0u || source_handle == 0u)
        return RIN_RESULT_INVALID_HANDLE;
#if defined(_WIN32)
    return RIN_RESULT_NOT_SUPPORTED;
#else
    {
        const uint64_t arguments[2] = {target_handle, source_handle};
        return installer_runtime_result(installer_runtime_syscall(
            (uintptr_t)RIN_SYS_INSTALL_TARGET_AUTHORIZE,
            arguments, 2u, 0x3u, 0, NULL));
    }
#endif
}

static RinResultCode installer_target_io(uintptr_t syscall_number,
                                         uint64_t handle, uint64_t lba,
                                         uint32_t block_count,
                                         const void* buffer,
                                         uint16_t flags)
{
    RinInstallTargetReadV1 request;
    uint64_t byte_count;
    intptr_t result;
    if (handle == 0u)
        return RIN_RESULT_INVALID_HANDLE;
    if (buffer == NULL || block_count == 0u || block_count > 128u ||
        lba > UINT64_MAX - block_count ||
        (flags & ~(RIN_STORAGE_IO_FUA | RIN_STORAGE_IO_BARRIER)) != 0u)
        return RIN_RESULT_INVALID_ARGUMENT;
    byte_count = (uint64_t)block_count * UINT64_C(512);
    if (byte_count > UINTPTR_MAX - (uintptr_t)buffer)
        return RIN_RESULT_INVALID_ARGUMENT;
#if defined(_WIN32)
    (void)syscall_number;
    (void)lba;
    (void)byte_count;
    return RIN_RESULT_NOT_SUPPORTED;
#else
    installer_runtime_zero(&request, sizeof(request));
    request.struct_size = (uint32_t)sizeof(request);
    request.version = RIN_CONTRACT_STRUCT_VERSION_1;
    request.handle = handle;
    request.flags = flags;
    request.lba = lba;
    request.buffer = (uint64_t)(uintptr_t)buffer;
    request.block_count = block_count;
    {
        const uint64_t arguments[2] = {
            (uintptr_t)&request, sizeof(request)
        };
        result = installer_runtime_syscall(
            syscall_number, arguments, 2u, 1u << 1, 0, NULL);
    }
    installer_runtime_zero(&request, sizeof(request));
    return installer_runtime_result(result);
#endif
}

RinResultCode rin_app_install_target_read(uint64_t handle, uint64_t lba,
                                          uint32_t block_count,
                                          void* output)
{
    return installer_target_io((uintptr_t)RIN_SYS_INSTALL_TARGET_READ,
                               handle, lba, block_count, output, 0u);
}

RinResultCode rin_app_install_target_write(uint64_t handle, uint64_t lba,
                                           uint32_t block_count,
                                           const void* input,
                                           uint16_t flags)
{
    return installer_target_io((uintptr_t)RIN_SYS_INSTALL_TARGET_WRITE,
                               handle, lba, block_count, input, flags);
}

RinResultCode rin_app_install_target_flush(uint64_t handle)
{
    if (handle == 0u)
        return RIN_RESULT_INVALID_HANDLE;
#if defined(_WIN32)
    return RIN_RESULT_NOT_SUPPORTED;
#else
    {
        const uint64_t arguments[1] = {handle};
        return installer_runtime_result(installer_runtime_syscall(
            (uintptr_t)RIN_SYS_INSTALL_TARGET_FLUSH,
            arguments, 1u, 1u, 0, NULL));
    }
#endif
}

RinResultCode rin_app_install_target_end(uint64_t handle)
{
    if (handle == 0u)
        return RIN_RESULT_INVALID_HANDLE;
#if defined(_WIN32)
    return RIN_RESULT_NOT_SUPPORTED;
#else
    {
        const uint64_t arguments[1] = {handle};
        return installer_runtime_result(installer_runtime_syscall(
            (uintptr_t)RIN_SYS_INSTALL_TARGET_END,
            arguments, 1u, 1u, 0, NULL));
    }
#endif
}
