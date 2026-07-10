# mycellium-engine

The native headless Mycellium peer engine.

The engine owns identity orchestration, signed-record import/export, direct
device delivery, local outbox retry, contacts, verification, history, groups,
backups, and local organization. Frontends initialize `mycellium-storage` with
an explicit `ClientConfig`; the engine reads display name, identity, and local
storage paths from that process-local config.
