/* SPDX-License-Identifier: MIT */
#ifndef RINRUNTIME_CORE_HPP
#define RINRUNTIME_CORE_HPP

/* Stable runtime primitives and policy helpers. */
#include "abi_feature_manifest.hpp"
#include "abi_policy.hpp"
#include "abi_symbol_policy.hpp"
#include "cancellation.h"
#include "event.hpp"
#include "event_loop.hpp"
#include "event_loop_rin.hpp"
#include "path.h"
#include "poll_wait.h"
#include "text_codec.h"
#include "unicode.h"
#include "unicode.hpp"

#if !defined(_WIN32)
#include "event_loop_poll.hpp"
#endif

#endif /* RINRUNTIME_CORE_HPP */
