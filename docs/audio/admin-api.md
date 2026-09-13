# Administrative API

Functions named `rin_audio_admin_*` change process-wide mixer state, update the
policy catalog, enumerate other applications, or target another application.
Audio Service requires the authenticated system-admin capability for these
operations. Renaming a function or adding a client-side guard cannot grant the
capability; authorization is enforced again in the service dispatch path.
