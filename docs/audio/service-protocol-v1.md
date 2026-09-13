# Audio Service protocol v1

The public protocol is declared in
`RinOS-SDK/include/rin/audio/service_abi.h`. It uses fixed-width integer
fields, packed versioned structures, explicit payload sizes, monotonically
increasing request IDs, opaque stream handles, and zeroed reserved fields.
All integer values are little-endian. PCM formats are explicitly S16LE or
IEEE-754 binary32 F32LE.

The socket endpoint and authenticated socket options are transport policy and
remain private to the runtime/service implementation.
