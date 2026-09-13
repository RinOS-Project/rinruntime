# Device enumeration

`rin_audio_service_client_devices()` returns a bounded snapshot of stable
device IDs, names, direction, availability, channel range, sample-rate range,
and the snapshot generation. Use the generation with device selection; a
changed generation must be enumerated again. No kernel, USB, backend, or
physical topology pointer is exposed to applications.
