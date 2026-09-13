# Rin Audio Service client

`rinruntime` is the public application client for RinOS Audio Service. Include
`<rinruntime/rin_audio_service_client.h>` and link the runtime. The SDK headers
under `<rin/audio/>` define the versioned wire and shared-memory ABI.

An application can connect, enumerate the stable device snapshot, create a
playback or capture stream, exchange PCM frames through RinSHM, control its
stream, and disconnect. Hardware handles, socket options, and mixer internals
are not public API.
