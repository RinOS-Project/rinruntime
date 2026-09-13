# Stream lifecycle

1. Call `rin_audio_service_client_init()` once for a clean process client.
2. Call `rin_audio_service_client_connect()`; authentication is performed by
   the kernel-owned service socket identity.
3. Create a playback or capture stream and retain only the returned opaque
   stream index. The service validates the format, capacity, device generation,
   and shared ring before accepting it.
4. Use `start`, `pause`, `resume`, `drain`, `flush`, and `destroy` as needed.
   A stale handle is rejected by the service and never reused by the client.
5. Call `rin_audio_service_client_disconnect()` or `reset()` to release all
   streams and mappings.
