/* SPDX-License-Identifier: MIT */

#include <assert.h>
#include <rin/file_portal_call.h>
#include <rinruntime/backup_restore.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum {
    FAKE_PORTAL_OK = 0,
    FAKE_PORTAL_TRANSPORT_FAILURE = 1,
    FAKE_PORTAL_MALFORMED_RESPONSE = 2
};

static int fake_mode;

int rin_file_portal_call(RinFilePortalCallV1* call)
{
    static const uint8_t read_bytes[] = { 'a', 'b', 'c' };

    assert(call != NULL);
    assert(call->struct_size == sizeof(*call));
    assert(call->version == RIN_FILE_PORTAL_CALL_VERSION);
    assert(call->descriptor == 4);
    assert(call->process_fd == -1);
    assert(call->payload.struct_size == sizeof(call->payload));
    assert(call->payload.version == RIN_FILE_PORTAL_PAYLOAD_VERSION);
    if (fake_mode == FAKE_PORTAL_TRANSPORT_FAILURE) return -1;
    if (call->operation == RIN_FILE_PORTAL_OPERATION_PAYLOAD_READ) {
        assert(call->payload.payload_size == 4u);
        memcpy(call->payload.bytes, read_bytes, sizeof(read_bytes));
        call->payload.result_size = fake_mode == FAKE_PORTAL_MALFORMED_RESPONSE
            ? call->payload.payload_size + 1u
            : sizeof(read_bytes);
    } else if (call->operation == RIN_FILE_PORTAL_OPERATION_PAYLOAD_WRITE) {
        assert(call->payload.payload_size == 3u);
        assert(memcmp(call->payload.bytes, "xyz", 3u) == 0);
        call->payload.result_size = 3u;
    } else {
        assert(call->operation == RIN_FILE_PORTAL_OPERATION_PAYLOAD_SYNC ||
               call->operation == RIN_FILE_PORTAL_OPERATION_PAYLOAD_TRUNCATE);
        assert(call->payload.payload_size == 0u);
        call->payload.result_size = 0u;
    }
    return 0;
}

static void assert_zero(const uint8_t* bytes, size_t size)
{
    size_t index;
    for (index = 0u; index < size; ++index) assert(bytes[index] == 0u);
}

int main(void)
{
    uint8_t output[4];
    uint8_t oversized[ RIN_FILE_PORTAL_PAYLOAD_DATA_SIZE + 1u ];
    uint32_t transferred = 99u;

    memset(output, 0xa5, sizeof(output));
    fake_mode = FAKE_PORTAL_OK;
    assert(rinruntime_backup_payload_read(4, 0u, output, sizeof(output),
                                           &transferred) ==
           RINRUNTIME_BACKUP_OK);
    assert(transferred == 3u && memcmp(output, "abc", 3u) == 0 &&
           output[3] == 0u);

    memset(output, 0xa5, sizeof(output));
    transferred = 99u;
    fake_mode = FAKE_PORTAL_TRANSPORT_FAILURE;
    assert(rinruntime_backup_payload_read(4, 0u, output, sizeof(output),
                                           &transferred) ==
           RINRUNTIME_BACKUP_TRANSPORT_FAILED);
    assert(transferred == 0u);
    assert_zero(output, sizeof(output));

    memset(output, 0xa5, sizeof(output));
    transferred = 99u;
    fake_mode = FAKE_PORTAL_MALFORMED_RESPONSE;
    assert(rinruntime_backup_payload_read(4, 0u, output, sizeof(output),
                                           &transferred) ==
           RINRUNTIME_BACKUP_TRANSPORT_FAILED);
    assert(transferred == 0u);
    assert_zero(output, sizeof(output));

    memset(oversized, 0xa5, sizeof(oversized));
    transferred = 99u;
    fake_mode = FAKE_PORTAL_OK;
    assert(rinruntime_backup_payload_read(
               4, 0u, oversized, sizeof(oversized), &transferred) ==
           RINRUNTIME_BACKUP_INVALID_ARGUMENT);
    assert(transferred == 0u);
    assert_zero(oversized, sizeof(oversized));

    transferred = 99u;
    assert(rinruntime_backup_payload_write(
               4, 0u, (const uint8_t*)"xyz", 3u, &transferred) ==
           RINRUNTIME_BACKUP_OK);
    assert(transferred == 3u);

    transferred = 99u;
    assert(rinruntime_backup_payload_sync(4) == RINRUNTIME_BACKUP_OK);
    assert(rinruntime_backup_payload_truncate(4, 7u) == RINRUNTIME_BACKUP_OK);
    puts("rinruntime_backup_payload_contract_test: OK");
    return 0;
}
