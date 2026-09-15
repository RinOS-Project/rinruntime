/* SPDX-License-Identifier: MIT */

#include <assert.h>
#include <stdint.h>

#include <rin/contract_abi.h>
#include <rinruntime/clipboard.h>

_Static_assert(RINRUNTIME_CLIPBOARD_FORMAT_UTF8_TEXT == 1u,
               "public clipboard format drift");
_Static_assert(RINRUNTIME_CLIPBOARD_MAX_BYTES ==
                   RIN_GUI_V2_MAX_CLIPBOARD_BYTES,
               "public clipboard limit drift");
_Static_assert(RINRUNTIME_CLIPBOARD_OK == RIN_RESULT_OK,
               "public clipboard success drift");
_Static_assert(RINRUNTIME_CLIPBOARD_BUFFER_TOO_SMALL ==
                   RIN_RESULT_BUFFER_TOO_SMALL,
               "public clipboard short-buffer drift");

int main(void)
{
    assert(RINRUNTIME_CLIPBOARD_FORMAT_UTF8_TEXT == 1u);
    assert(RINRUNTIME_CLIPBOARD_MAX_BYTES == 4096u);
    return 0;
}
