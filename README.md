# Traefik CN Certificate Authorization Plugin

This plugin authorizes requests based on the Common Name (CN) of a TLS client certificate.
If the client does not present a certificate or does present a certificate which according to
configuration is not allowed to continue, `403 Forbidden` is returned.

This repository was initially a fork of [traefik-certauthz](https://github.com/famedly/traefik-certauthz).
Thanks to the original authors for the initial codebase!

Note: CN validation is commonly used in mTLS environments even though modern TLS standards prefer SANs.

**CAUTION:**
This plugin does not validate the certificate it receives.
Please use the [traefik mTLS configuration](https://doc.traefik.io/traefik/https/tls/#client-authentication-mtls)
to also validate the certificate against a CA that you specify.

## Behavior

Only the certificate Common Name (CN) is evaluated.

DNS Subject Alternative Names (SANs) are ignored.

## Configuration

### Static configuration
```yaml
experimental:
  plugins:
    certauthz:
      moduleName: "github.com/wartydany/traefik-cn-authz"
      version: "v0.4.0"
```

### Dynamic configuration
```yaml
http:
  middlewares:
    my-certauthz:
      plugin:
        certauthz:
          regex: "^example\.org$"
# If you forget to use `^` and `$` an attacker would be able to pass with
# a certificate with a crafted Common Name.
# The `.` character should also be escaped.

  routers:
    my-router:
      middlewares:
        - "my-certauthz"
      tls:
        # Traefik mtls configuration is required for certificate validation
        # https://doc.traefik.io/traefik/https/tls/#client-authentication-mtls
        options: my-mtls
      entrypoints: […]
      rule: …
      service: …

tls:
  options:
    my-mtls:
      clientAuth:
        caFiles:
          - /etc/ssl/certs/ca-certificates.crt
        clientAuthType: RequireAndVerifyClientCert
```

## License
AGPLv3
