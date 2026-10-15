/* SPDX-License-Identifier: MIT */
#ifndef RIN_SHARED_USER_AGENT_H
#define RIN_SHARED_USER_AGENT_H

#if defined(__x86_64__) || defined(_M_X64)
#define RIN_ARCH_TOKEN "x86_64"
#elif defined(__i386__) || defined(__i686__) || defined(_M_IX86) || \
      (defined(__SIZEOF_POINTER__) && __SIZEOF_POINTER__ == 4)
#define RIN_ARCH_TOKEN "x86"
#else
#define RIN_ARCH_TOKEN "unknown"
#endif

#define RIN_USER_AGENT_VERSION "1.0"
#define RIN_USER_AGENT_PLATFORM "RinOS"
#define RIN_USER_AGENT \
    "Mozilla/5.0 (" RIN_USER_AGENT_PLATFORM "; " RIN_ARCH_TOKEN ") " \
    "AppleWebKit/537.36 (KHTML, like Gecko) " \
    "RinBrowser/" RIN_USER_AGENT_VERSION " Safari/537.36"

#ifdef __cplusplus
namespace Browser {
inline const char* browserUserAgent() { return RIN_USER_AGENT; }
inline const char* browserPlatform() { return RIN_USER_AGENT_PLATFORM; }
}  // namespace Browser
#endif

#endif
