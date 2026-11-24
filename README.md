# Trader Desk (StockWithMe r1 creation)

Static page for Anthony's Rabbit r1, served by GitHub Pages at
https://dayxtraderx333.github.io/trader-desk/ (install QR: `/trader-desk/install.html`).

**This repo holds no secrets.** The page pairs once with a 256-bit device key
typed on the r1 and kept in `creationStorage` on the device. The bridge on the
desk machine holds the same key in a mode-0600 file.

Protocol v1 (HMAC-SHA256 keyed with the device key K):
- AES-256-GCM key = HMAC(K, "aes-v1")
- request channel = `td-` + hex(HMAC(K, "req-v1"))[:32] on https://ppng.io
- reply channel = `td-` + hex(HMAC(K, "res-v1" + id))[:32]
- AAD `req|1|id|ts|cmd` and `res|1|id|ts|cmd`; replies are bound to the request id
- bridge: ±60 s timestamps, 5-minute replay cache, 10 req/min, lockout after 5 auth failures

Commands: brief, pulse, spy, options, quote TICKER, scorecard, botstatus (read-only).
