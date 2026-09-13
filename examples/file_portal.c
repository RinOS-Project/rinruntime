/* SPDX-License-Identifier: MIT */
#include <rinruntime/portal.h>

int main(void) {
    return rinruntime_portal_label_validate("document.rin", 12u, 128u) == 0 ? 0 : 1;
}
