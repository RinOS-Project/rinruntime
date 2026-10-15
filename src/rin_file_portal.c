/* SPDX-License-Identifier: MIT */

#include <rin/file_portal.h>

#include <rinwire/capability.h>
#include <crypto/hmac.h>

#include <stddef.h>

static void portal_zero(void* output, uint32_t size)
{
    uint8_t* bytes = (uint8_t*)output;
    for (uint32_t index = 0u; index < size; ++index) bytes[index] = 0u;
}

static void portal_copy(void* output, const void* input, uint32_t size)
{
    uint8_t* destination = (uint8_t*)output;
    const uint8_t* source = (const uint8_t*)input;
    for (uint32_t index = 0u; index < size; ++index) {
        destination[index] = source[index];
    }
}

static int portal_all_zero(const uint8_t* bytes, uint32_t size)
{
    uint8_t value = 0u;
    if (bytes == NULL) return 1;
    for (uint32_t index = 0u; index < size; ++index) value |= bytes[index];
    return value == 0u;
}

static int portal_equal(const uint8_t* left, const uint8_t* right,
                        uint32_t size)
{
    uint8_t difference = 0u;
    for (uint32_t index = 0u; index < size; ++index) {
        difference |= (uint8_t)(left[index] ^ right[index]);
    }
    return difference == 0u;
}

static int portal_package_name_valid(
    const char name[RIN_FILE_PORTAL_PACKAGE_NAME_SIZE])
{
    uint32_t length = 0u;
    while (length < RIN_FILE_PORTAL_PACKAGE_NAME_SIZE &&
           name[length] != '\0') {
        uint8_t character = (uint8_t)name[length];
        if (character < 0x20u || character == 0x7fu || character == '/' ||
            character == '\\' || character == ':') return 0;
        ++length;
    }
    if (length == 0u || length == RIN_FILE_PORTAL_PACKAGE_NAME_SIZE ||
        (length == 1u && name[0] == '.') ||
        (length == 2u && name[0] == '.' && name[1] == '.')) return 0;
    for (uint32_t index = length + 1u;
         index < RIN_FILE_PORTAL_PACKAGE_NAME_SIZE; ++index) {
        if (name[index] != '\0') return 0;
    }
    return 1;
}

int rin_file_portal_identity_valid(const RinFilePortalIdentityV1* identity)
{
    return identity != NULL &&
           portal_package_name_valid(identity->package_name) &&
           identity->publisher_key_generation != 0u &&
           !portal_all_zero(identity->publisher_key_id,
                            sizeof(identity->publisher_key_id));
}

int rin_file_portal_identity_equal(const RinFilePortalIdentityV1* left,
                                   const RinFilePortalIdentityV1* right)
{
    return rin_file_portal_identity_valid(left) &&
           rin_file_portal_identity_valid(right) &&
           left->uid == right->uid &&
           left->publisher_key_generation ==
               right->publisher_key_generation &&
           portal_equal((const uint8_t*)left->package_name,
                        (const uint8_t*)right->package_name,
                        sizeof(left->package_name)) &&
           portal_equal(left->publisher_key_id, right->publisher_key_id,
                        sizeof(left->publisher_key_id));
}

static int portal_rights_valid(uint32_t rights)
{
    return rights != 0u && (rights & ~RIN_FILE_PORTAL_RIGHT_ALL) == 0u;
}

static void portal_authentication_tag(
    const RinFilePortalTokenV1* token,
    const uint8_t key[RIN_FILE_PORTAL_KEY_SIZE],
    uint8_t tag[RIN_FILE_PORTAL_TAG_SIZE])
{
    RinFilePortalTokenV1 checked;
    hmac_sha256_ctx context;
    portal_copy(&checked, token, sizeof(checked));
    portal_zero(checked.authentication_tag,
                sizeof(checked.authentication_tag));
    hmac_sha256_init(&context, key, RIN_FILE_PORTAL_KEY_SIZE);
    hmac_sha256_update(&context, (const uint8_t*)&checked, sizeof(checked));
    hmac_sha256_final(&context, tag);
    portal_zero(&context, sizeof(context));
    portal_zero(&checked, sizeof(checked));
}

static void portal_initialize_result(RinFilePortalOpenResultV1* result)
{
    portal_zero(result, sizeof(*result));
    result->struct_size = sizeof(*result);
    result->version = RIN_FILE_PORTAL_VERSION;
}

RinFilePortalStatus rin_file_portal_issue(
    const RinFilePortalIssueRequestV1* request,
    const uint8_t authentication_key[RIN_FILE_PORTAL_KEY_SIZE],
    RinFilePortalTokenV1* token)
{
    uint8_t tag[RIN_FILE_PORTAL_TAG_SIZE];
    if (token != NULL) portal_zero(token, sizeof(*token));
    if (request == NULL || authentication_key == NULL || token == NULL ||
        request->struct_size != sizeof(*request) ||
        request->version != RIN_FILE_PORTAL_VERSION ||
        !rin_file_portal_identity_valid(&request->identity) ||
        !portal_rights_valid(request->rights) || request->flags != 0u ||
        request->file_object_id == 0u || request->not_before_epoch == 0u ||
        request->expires_at_epoch < request->not_before_epoch ||
        rin_wire_capability_generation_valid(request->policy_generation) !=
            RIN_WIRE_CAPABILITY_OK ||
        portal_all_zero(request->nonce, sizeof(request->nonce)) ||
        !portal_all_zero(request->reserved, sizeof(request->reserved)) ||
        portal_all_zero(authentication_key, RIN_FILE_PORTAL_KEY_SIZE)) {
        return RIN_FILE_PORTAL_INVALID_ARGUMENT;
    }

    token->magic = RIN_FILE_PORTAL_TOKEN_MAGIC;
    token->version = RIN_FILE_PORTAL_TOKEN_VERSION;
    token->token_size = sizeof(*token);
    portal_copy(&token->identity, &request->identity,
                sizeof(token->identity));
    token->rights = request->rights;
    token->file_object_id = request->file_object_id;
    token->not_before_epoch = request->not_before_epoch;
    token->expires_at_epoch = request->expires_at_epoch;
    token->policy_generation = request->policy_generation;
    portal_copy(token->nonce, request->nonce, sizeof(token->nonce));
    portal_authentication_tag(token, authentication_key, tag);
    portal_copy(token->authentication_tag, tag, sizeof(tag));
    portal_zero(tag, sizeof(tag));
    return RIN_FILE_PORTAL_OK;
}

RinFilePortalStatus rin_file_portal_authorize(
    const RinFilePortalTokenV1* token,
    const RinFilePortalOpenRequestV1* request,
    const uint8_t authentication_key[RIN_FILE_PORTAL_KEY_SIZE],
    RinFilePortalOpenResultV1* result)
{
    uint8_t expected_tag[RIN_FILE_PORTAL_TAG_SIZE];
    if (result == NULL) return RIN_FILE_PORTAL_INVALID_ARGUMENT;
    portal_initialize_result(result);
    if (token == NULL || request == NULL || authentication_key == NULL ||
        request->struct_size != sizeof(*request) ||
        request->version != RIN_FILE_PORTAL_VERSION ||
        !rin_file_portal_identity_valid(&request->identity) ||
        !portal_rights_valid(request->requested_rights) ||
        request->reserved0 != 0u || request->current_epoch == 0u ||
        rin_wire_capability_generation_valid(request->minimum_policy_generation) !=
            RIN_WIRE_CAPABILITY_OK ||
        !portal_all_zero(request->reserved, sizeof(request->reserved)) ||
        portal_all_zero(authentication_key, RIN_FILE_PORTAL_KEY_SIZE)) {
        return RIN_FILE_PORTAL_INVALID_ARGUMENT;
    }
    if (token->magic != RIN_FILE_PORTAL_TOKEN_MAGIC ||
        token->version != RIN_FILE_PORTAL_TOKEN_VERSION ||
        rin_wire_capability_token_size_valid(
            token, token->token_size, sizeof(*token), sizeof(*token)) !=
            RIN_WIRE_CAPABILITY_OK) {
        return RIN_FILE_PORTAL_BAD_FORMAT;
    }

    portal_authentication_tag(token, authentication_key, expected_tag);
    if (!portal_equal(expected_tag, token->authentication_tag,
                      sizeof(expected_tag))) {
        portal_zero(expected_tag, sizeof(expected_tag));
        return RIN_FILE_PORTAL_INTEGRITY_FAILED;
    }
    portal_zero(expected_tag, sizeof(expected_tag));

    if (!rin_file_portal_identity_valid(&token->identity) ||
        !portal_rights_valid(token->rights) || token->flags != 0u ||
        token->file_object_id == 0u || token->not_before_epoch == 0u ||
        token->expires_at_epoch < token->not_before_epoch ||
        rin_wire_capability_generation_valid(token->policy_generation) !=
            RIN_WIRE_CAPABILITY_OK ||
        portal_all_zero(token->nonce, sizeof(token->nonce)) ||
        !portal_all_zero(token->reserved, sizeof(token->reserved))) {
        return RIN_FILE_PORTAL_BAD_FORMAT;
    }
    if (!rin_file_portal_identity_equal(&token->identity,
                                        &request->identity)) {
        return RIN_FILE_PORTAL_IDENTITY_MISMATCH;
    }
    if (rin_wire_capability_not_revoked(
            token->policy_generation, request->minimum_policy_generation) ==
        RIN_WIRE_CAPABILITY_REVOKED) {
        return RIN_FILE_PORTAL_REVOKED;
    }
    const RinWireCapabilityStatus expiry = rin_wire_capability_expiry_valid(
        token->not_before_epoch, token->expires_at_epoch,
        request->current_epoch);
    if (expiry == RIN_WIRE_CAPABILITY_NOT_YET_VALID) {
        return RIN_FILE_PORTAL_NOT_YET_VALID;
    }
    if (expiry == RIN_WIRE_CAPABILITY_EXPIRED) {
        return RIN_FILE_PORTAL_EXPIRED;
    }
    if ((request->requested_rights & ~token->rights) != 0u) {
        return RIN_FILE_PORTAL_RIGHTS_DENIED;
    }

    result->granted_rights = request->requested_rights;
    result->file_object_id = token->file_object_id;
    result->expires_at_epoch = token->expires_at_epoch;
    return RIN_FILE_PORTAL_OK;
}
