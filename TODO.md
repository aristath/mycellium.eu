# TODO

## Add registry backups for long-term Bunny deployment

This is not required for the first live registry run.

Bunny Magic Containers are acceptable for the first deployment when the registry
runs as one instance in one region with a persistent volume. The Brevo HTTPS
email transport avoids the SMTP-egress blocker.

Before treating Bunny as the permanent home for account infrastructure, add a
boring backup/export path for the registry data directory:

- `registry.redb`
- `blobs/`

The backup should go to durable object storage, run periodically, and have a
tested restore path. This is an endurance/durability item, not a first-run
blocker. The recovery master key must be backed up separately from those files;
it must never be copied into the same storage location.
