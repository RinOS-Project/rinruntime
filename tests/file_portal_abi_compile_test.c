/* SPDX-License-Identifier: MIT */
#include <assert.h>

#include <rinruntime/durable_file_portal.h>
#include <rinruntime/file_chooser_portal.h>
#include <rinruntime/file_operation_service.h>
#include <rinruntime/file_portal.h>

int main(void)
{
    RinFilePortalTokenV1 token = {0};
    RinFilePortalCallV1 call = {0};
    RinRuntimeFileChooserFrameV1 frame = {0};
    RinRuntimeFileOperationServiceHeaderV1 operation = {0};
    assert(sizeof(token) == RIN_FILE_PORTAL_TOKEN_SIZE);
    assert(sizeof(call) == 296u);
    assert(sizeof(frame) == 20u);
    assert(sizeof(operation) == 32u);
    return 0;
}
