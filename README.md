# Construct Delivery API

Transactional email with per-domain DKIM signing, an SMTP relay on port 587, suppression lists, templates, web push and mobile push notifications, and tenant API keys (`cd_live_*`). Go, PostgreSQL.

Part of [Construct](https://github.com/construct-space), the platform behind construct.space, published as it ran in September 2026. The organisation README maps the other services.

## Run

```
go run .
```

A `Dockerfile` and a `captain-definition` are included: the service ran on CapRover.

## License

MIT, see `LICENSE`.