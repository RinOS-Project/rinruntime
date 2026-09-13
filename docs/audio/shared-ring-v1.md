# Shared ring v1

`RinAudioServiceSharedRingV1` is a fixed-width, little-endian header followed
by `capacity_frames * frame_bytes` PCM bytes. The application is producer for
playback and consumer for capture; Audio Service owns the opposite side.

`producer_frames` and `consumer_frames` are monotonic frame counters, not
wrapped indexes. The consumer loads producer with acquire ordering, the
producer publishes data with release ordering, and every participant rejects
counter distances greater than capacity. Header, generation, format, capacity,
and reserved-zero checks are mandatory before calculating an offset.
