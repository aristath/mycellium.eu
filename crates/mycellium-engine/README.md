# mycellium-engine

The native headless Mycellium peer engine.

The engine owns identity orchestration, signed-record publishing, direct and
mailbox delivery, contacts, history, groups, pairing, backups, and local
organization. Frontends initialize `mycellium-storage` with an explicit
`ClientConfig`; the engine reads queue URL, display name, identity, and local
storage paths from that process-local config.
