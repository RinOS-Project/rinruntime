/* SPDX-License-Identifier: MIT */
#include <assert.h>

#include <rinruntime/accessibility_service_client.h>

int main(void)
{
    RinAccessibilityServiceClientV1 client = {0};
    RinAccessibilityServiceMessageHeaderV1 header = {0};
    RinAccessibilityServiceActionV2 action = {0};
    assert(sizeof(header) == 32u);
    assert(sizeof(action) == 256u);
    assert(client.socket_fd == 0);
    return 0;
}
