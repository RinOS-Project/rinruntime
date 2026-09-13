/* SPDX-License-Identifier: MIT */
#include <rinruntime/rin_app_ui.hpp>
int main() {
    Rin::Rect rect(0, 0, 10, 10);
    return rect.contains(5, 5) && !rect.contains(10, 10) ? 0 : 1;
}
