# mycellium-observe

Small observability helpers shared by services.

It provides Prometheus counters and redacted access-log formatting. Services
decide whether access logs are emitted through their explicit HTTP config.
