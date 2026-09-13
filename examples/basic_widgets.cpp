/* SPDX-License-Identifier: MIT */
#include <rinruntime/rin_app_widgets.hpp>
int main() {
    Rin::Button button("Open");
    return button.text() == "Open" && button.minimumLayoutSize().width >= 88 ? 0 : 1;
}
