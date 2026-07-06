# Android Client

Android app and instrumentation tests for the Mycellium SDK.

The messaging e2e test expects host-side dev services reachable from the
emulator at `10.0.2.2`, with default ports `18080` and `18090`. Start the
directory with a dev JSON config so email verification returns a dev code.

Instrumentation runner arguments can override `host`, `dirPort`, and
`queuePort`.
