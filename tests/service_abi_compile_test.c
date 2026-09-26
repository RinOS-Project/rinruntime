/* SPDX-License-Identifier: MIT */

#include <assert.h>

#include <rin/service.h>

int main(void)
{
    assert(RIN_SERVICE_SCOPE_SYSTEM == 1);
    assert(RIN_SERVICE_SCOPE_USER == 2);
    /* The public adapter must export both declared service entry points. */
    assert(rin_service_start != NULL);
    assert(rin_service_find_system_slot != NULL);
    return 0;
}
