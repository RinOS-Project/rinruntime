/* SPDX-License-Identifier: MIT */
/* Public keyring client owner. Transport failures are returned to callers. */
#ifndef RINRUNTIME_KEYRING_CLIENT_H
#define RINRUNTIME_KEYRING_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include <rin/keyring.h>
#include <rin/net/socket_abi.h>

static inline uint32_t rin_keyring_client_secret_name_size(const char* name)
{
    size_t index;
    if (name == NULL) return 0u;
    for (index = 0u; index <= RIN_KEYRING_MAX_SECRET_NAME; ++index)
        if (name[index] == '\0') return (uint32_t)index;
    return 0u;
}

static inline int rin_keyring_client_service_identity_valid(
    const rin_unix_service_identity_v1* identity,
    uint32_t expected_slot_id)
{
    return identity != NULL && expected_slot_id != 0u &&
           identity->slot_id == expected_slot_id &&
           identity->owner_uid == RIN_KEYRING_SERVICE_OWNER_UID &&
           identity->scope == RIN_KEYRING_SERVICE_SCOPE &&
           identity->flags == RIN_UNIX_SERVICE_IDENTITY_FLAG_PUBLISHED;
}

#ifdef __cplusplus
extern "C" {
#endif

int rin_keyring_client_status(void);
int rin_keyring_client_put(const char* name, const void* secret,
                           uint32_t secret_size, uint64_t* generation);
int rin_keyring_client_get(const char* name, void* secret,
                           uint32_t secret_capacity, uint32_t* secret_size,
                           uint64_t* generation);
int rin_keyring_client_remove(const char* name);
int rin_keyring_client_acquire_handle(const char* name,
                                      RinKeyringHandleV1* handle);
int rin_keyring_client_get_handle(const RinKeyringHandleV1* handle,
                                  void* secret, uint32_t secret_capacity,
                                  uint32_t* secret_size,
                                  uint64_t* generation);
int rin_keyring_client_remove_handle(const RinKeyringHandleV1* handle);
void rin_keyring_client_clear(void* memory, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_KEYRING_CLIENT_H */
