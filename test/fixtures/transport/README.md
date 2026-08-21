# Local TLS Fixture

`cert.pem` and `key.pem` are a deliberately committed self-signed certificate
pair for the synthetic hostname `shop.vendor.tld`.

They are used only by controlled loopback transport and Chromium tests. The key
does not protect a real service, is never loaded by production code, and must
not be reused outside the test suite. Keeping the pair in the repository makes
TLS hostname verification, certificate rejection, CONNECT tunneling, and
socket-pinning tests deterministic without an external network dependency.
