# Capture permissions

Capture stream creation is authorized by Audio Service using the authenticated
socket capability set. The client does not grant itself microphone access and
does not treat a client-side check as security. A missing microphone capability
is returned as the service policy error; the service also validates the capture
device and generation.
