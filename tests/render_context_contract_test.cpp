/* SPDX-License-Identifier: MIT */

#include <assert.h>
#include <stdexcept>

#include <rin/runtime.h>
#include <rinruntime/render_context.hpp>

/* The public runtime leaves diagnostic logging to the host/application. */
extern "C" void rin_log(const char*) {}

static const AqFont* throwing_font_loader(void*) {
    throw std::runtime_error("font loader failure");
}

int main() {
    assert(RinRuntime::setSystemUiFontLoader(throwing_font_loader) ==
           RIN_SUCCESS);
    assert(RinRuntime::systemUiFont() != nullptr);
    assert(RinRuntime::setSystemUiFontLoader(nullptr) == RIN_ERROR_BUSY);
    return 0;
}
