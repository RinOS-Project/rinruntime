/* SPDX-License-Identifier: MIT */
#ifndef RINRUNTIME_CXX_COMPAT_H
#define RINRUNTIME_CXX_COMPAT_H

#if defined(__cplusplus)
#define RINRUNTIME_STATIC_ASSERT(condition, message) \
    static_assert((condition), message)
#else
#define RINRUNTIME_STATIC_ASSERT(condition, message) \
    _Static_assert((condition), message)
#endif

#endif /* RINRUNTIME_CXX_COMPAT_H */
