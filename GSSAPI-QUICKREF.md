# GSSAPI Quick Reference

This is a quick reference guide for GSSAPI SASL authentication with the go-ldap library.

## Installation

```bash
go get github.com/go-ldap/ldap/v3
```

## Quick Start Examples

### Unix/Linux - Password Authentication

```go
package main

import (
    "log"
    "github.com/go-ldap/ldap/v3"
    "github.com/go-ldap/ldap/v3/gssapi"
)

func main() {
    // Create GSSAPI client
    client, err := gssapi.NewClientWithPassword(
        "username", "REALM.COM", "password", "/etc/krb5.conf")
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Connect and bind
    l, err := ldap.DialURL("ldap://server.example.com:389")
    if err != nil {
        log.Fatal(err)
    }
    defer l.Close()

    err = l.GSSAPIBind(client, "ldap/server.example.com", "")
    if err != nil {
        log.Fatal(err)
    }

    log.Println("Authenticated!")
}
```

### Unix/Linux - Keytab Authentication

```go
client, err := gssapi.NewClientWithKeytab(
    "serviceaccount",
    "REALM.COM",
    "/etc/krb5.keytab",
    "/etc/krb5.conf",
)
if err != nil {
    log.Fatal(err)
}
defer client.Close()

l, err := ldap.DialURL("ldap://server.example.com:389")
if err != nil {
    log.Fatal(err)
}
defer l.Close()

err = l.GSSAPIBind(client, "ldap/server.example.com", "")
if err != nil {
    log.Fatal(err)
}
```

### Unix/Linux - Credential Cache (after kinit)

```go
// First run: kinit username@REALM.COM

client, err := gssapi.NewClientFromCCache(
    "/tmp/krb5cc_1000",  // or os.Getenv("KRB5CCNAME")
    "/etc/krb5.conf",
)
if err != nil {
    log.Fatal(err)
}
defer client.Close()

l, err := ldap.DialURL("ldap://server.example.com:389")
if err != nil {
    log.Fatal(err)
}
defer l.Close()

err = l.GSSAPIBind(client, "ldap/server.example.com", "")
if err != nil {
    log.Fatal(err)
}
```

### Windows - Current User

```go
// Uses logged-in Windows user credentials automatically
client, err := gssapi.NewSSPIClient()
if err != nil {
    log.Fatal(err)
}
defer client.Close()

l, err := ldap.DialURL("ldap://server.example.com:389")
if err != nil {
    log.Fatal(err)
}
defer l.Close()

err = l.GSSAPIBind(client, "ldap/server.example.com", "")
if err != nil {
    log.Fatal(err)
}
```

### Windows - Specific User

```go
client, err := gssapi.NewSSPIClientWithUserCredentials(
    "DOMAIN",
    "username",
    "password",
)
if err != nil {
    log.Fatal(err)
}
defer client.Close()

l, err := ldap.DialURL("ldap://server.example.com:389")
if err != nil {
    log.Fatal(err)
}
defer l.Close()

err = l.GSSAPIBind(client, "ldap/server.example.com", "")
if err != nil {
    log.Fatal(err)
}
```

## With TLS/STARTTLS

```go
import "crypto/tls"

l, err := ldap.DialURL("ldap://server.example.com:389")
if err != nil {
    log.Fatal(err)
}
defer l.Close()

// Start TLS
err = l.StartTLS(&tls.Config{
    ServerName: "server.example.com",
})
if err != nil {
    log.Fatal(err)
}

// Then bind with GSSAPI
err = l.GSSAPIBind(client, "ldap/server.example.com", "")
if err != nil {
    log.Fatal(err)
}
```

## Advanced: Custom Bind Request

```go
req := &ldap.GSSAPIBindRequest{
    ServicePrincipalName: "ldap/server.example.com",
    AuthZID:              "u:altuser",  // Authorization identity
    Controls:             []ldap.Control{},  // Optional controls
}

err = l.GSSAPIBindRequest(client, req)
if err != nil {
    log.Fatal(err)
}
```

## Environment Variables

Useful environment variables for Kerberos:

- `KRB5_CONFIG` - Path to krb5.conf (default: /etc/krb5.conf)
- `KRB5CCNAME` - Path to credential cache (default: /tmp/krb5cc_$(id -u))
- `KRB5_TRACE` - Enable Kerberos debugging (e.g., /dev/stderr)

## Common Service Principal Formats

- `ldap/hostname` - Standard format
- `ldap/hostname@REALM` - With explicit realm
- `ldap/fqdn.domain.com` - Fully qualified domain name

## Testing Kerberos Setup

Before using in code, test your Kerberos configuration:

```bash
# Get a ticket
kinit username@REALM.COM

# Verify ticket
klist

# Test LDAP connection
ldapsearch -Y GSSAPI -H ldap://server.example.com -b "dc=example,dc=com"
```

## Troubleshooting

| Error | Solution |
|-------|----------|
| "Cannot find KDC" | Check krb5.conf, DNS, or KDC hostname resolution |
| "Server not found in Kerberos database" | Verify SPN format and server registration |
| "Clock skew too great" | Synchronize clocks (NTP) - must be within 5 minutes |
| "Ticket expired" | Renew ticket: `kinit -R` or get new ticket |
| Connection timeout | Check firewall, network, and LDAP server availability |

## Debug Logging

Enable debug logging to troubleshoot issues:

```go
l, err := ldap.DialURL("ldap://server.example.com:389")
if err != nil {
    log.Fatal(err)
}
l.Debug = true  // Enable debug output
```

For Kerberos-level debugging:
```bash
export KRB5_TRACE=/dev/stderr
# Run your Go program
```

## Full Documentation

For comprehensive documentation, see [GSSAPI.md](GSSAPI.md)

## API Reference

- `gssapi.NewClientWithPassword(username, realm, password, krb5conf)` - Password auth
- `gssapi.NewClientWithKeytab(username, realm, keytab, krb5conf)` - Keytab auth
- `gssapi.NewClientFromCCache(ccache, krb5conf)` - Use existing ticket
- `gssapi.NewSSPIClient()` - Windows current user (Windows only)
- `gssapi.NewSSPIClientWithUserCredentials(domain, user, pass)` - Windows specific user
- `ldap.Conn.GSSAPIBind(client, servicePrincipal, authzid)` - Perform GSSAPI bind
- `ldap.Conn.GSSAPIBindRequest(client, request)` - Advanced bind with options
