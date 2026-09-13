/* SPDX-License-Identifier: MIT */
#include <rinruntime/rin_app_documents.hpp>
int main() {
    Rin::Document document;
    return document.setText("hello") && document.insert(5u, " RinOS") ? 0 : 1;
}
