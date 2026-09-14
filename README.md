# RinRuntime public window API

`rinruntime` exposes the native-window transport through `window.h` and the
C++ `RinRuntime::Window` wrapper.  Rendering is a borrowed-frame operation:

```cpp
#include <rinruntime/window.hpp>
#include <aquamarine.h>

RinRuntime::Window window("Hello", 0, 0, 640, 480);
window.onPaint([](AqSurface& surface) {
    aq_surface_clear(&surface, AQ_RGB(24, 32, 48));
});
window.paint();
```

`currentRenderSurface()` and `currentRenderFont()` are valid only on the
thread and during the callback's active frame.  The compositor owns the
surface mapping; applications must not retain those pointers or inspect a
physical framebuffer.  The C API in `render.h` provides the same acquire,
release, and present lifecycle without exposing a frame-context structure.

The CMake build enables the real Unix compositor client with
`RINRUNTIME_BUILD_GUI=ON` (the default on non-Windows hosts).  It consumes the
public SDK headers and the standalone `Aquamarine::Aquamarine` target only.

For a RinOS target image, opt into `RINRUNTIME_BUILD_RLL` (or Meson's
`-Dbuild_rll=true`).  The route invokes RinCompiler `rcc` for every configured
C source, links with `rld --shared`, and requires `rinsign`, a private key, a
matching public key, and explicit dependency `.rll` images.  The signed image
is atomically published only after the complete route succeeds; missing
toolchain inputs or dependencies are errors, and no host-library or unsigned
fallback is emitted.

The public C++ runtime also provides the backend-independent bounded
`EventLoop` model in `event_loop.hpp`.  POSIX hosts may opt into the
`PollEventLoopBackend` adapter in `event_loop_poll.hpp`; it owns only the
userspace `poll(2)` translation, while RinOS wait syscalls and production IPC
owners remain target-side adapters through `EventLoop::WaitFunction`.

The public runtime also provides the bounded `DownloadPartialReceipt`,
`DownloadRangeRequest`, and `DownloadRangeTransportAdapter` contracts. A
caller may omit cancellation entirely; when supplied, its callback preserves
`Cancelled` as a distinct state and the owner is aborted after admission.
Browser portal/storage and HTTPS/TLS owners remain outside this generic
transport contract.
