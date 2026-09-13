/* SPDX-License-Identifier: MIT */
#include <rinruntime/rin_app_system.hpp>
int main() {
    return Rin::ApplicationDataPolicy::validApplicationId("org.rinos.demo") ? 0 : 1;
}
