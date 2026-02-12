# GSSAPI/Kerberos Authentication for LDAP

This document provides comprehensive guidance on using GSSAPI SASL authentication with Kerberos for LDAP operations.

## Documentation

- **[GSSAPI.md](GSSAPI.md)** (this file) - Complete setup and usage guide
- **[GSSAPI-DEBUG.md](GSSAPI-DEBUG.md)** - Debug logging and troubleshooting
- **[GSSAPI-QUICKREF.md](GSSAPI-QUICKREF.md)** - Quick reference
- **[GSSAPI-IMPLEMENTATION.md](GSSAPI-IMPLEMENTATION.md)** - Technical details

## Overview

GSSAPI (Generic Security Services Application Program Interface) is a standardized interface for providing security services to applications. When combined with Kerberos, it provides strong authentication for LDAP connections without transmitting passwords over the network.

This library implements GSSAPI SASL authentication as specified in:
- [RFC 4752](https://www.rfc-editor.org/rfc/rfc4752.html) - The Kerberos V5 ("GSSAPI") SASL Mechanism
- [RFC 4513](https://www.rfc-editor.org/rfc/rfc4513.html) - LDAP Authentication Methods

## Platform Support

### Unix/Linux
On Unix and Linux systems, this library uses the [gokrb5](https://github.com/jcmturner/gokrb5) library, a pure Go implementation of Kerberos 5. This provides several authentication methods:
- **Keytab**: Service account credentials stored in a keytab file
- **Password**: Direct username/password authentication
- **Credential Cache**: Reusing existing Kerberos tickets (e.g., from `kinit`)

### Windows
On Windows systems, this library uses the native SSPI (Security Support Provider Interface) through the [go-sspi](https://github.com/alexbrainman/sspi) library. This allows seamless integration with Windows domain authentication:
- **Current User**: Automatically uses the logged-in user's credentials
- **Specific User**: Authenticate as a specific domain user
- **Channel Binding**: RFC 5929 compliant channel binding for enhanced security

## Prerequisites

### Kerberos Configuration
Before using GSSAPI authentication, ensure you have a properly configured Kerberos environment:

1. **krb5.conf**: Kerberos configuration file (typically `/etc/krb5.conf` on Unix/Linux)
2. **Service Principal**: The LDAP server must have a service principal (e.g., `ldap/ldap.example.com@EXAMPLE.COM`)
3. **Client Credentials**: One of:
   - A keytab file with the client's credentials
   - Username and password
   - An existing Kerberos ticket (credential cache)

### Example krb5.conf
```ini
[libdefaults]
    default_realm = EXAMPLE.COM
    dns_lookup_realm = false
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

[realms]
    EXAMPLE.COM = {
        kdc = kdc.example.com
        admin_server = kdc.example.com
    }

[domain_realm]
    .example.com = EXAMPLE.COM
    example.com = EXAMPLE.COM
```

## Usage Examples

### Unix/Linux: Authentication with Keytab

Keytab authentication is ideal for service accounts and automated systems:

```go
package main

import (
    "log"
    
    "github.com/go-ldap/ldap/v3"
    "github.com/go-ldap/ldap/v3/gssapi"
)

func main() {
    // Create GSSAPI client with keytab
    gssapiClient, err := gssapi.NewClientWithKeytab(
        "ldapuser",              // username
        "EXAMPLE.COM",           // realm (or "" for default)
        "/etc/krb5.keytab",     // keytab path
        "/etc/krb5.conf",       // krb5.conf path
    )
    if err != nil {
        log.Fatal(err)
    }
    defer gssapiClient.Close()

    // Connect to LDAP server
    l, err := ldap.DialURL("ldap://ldap.example.com:389")
    if err != nil {
        log.Fatal(err)
    }
    defer l.Close()

    // Perform GSSAPI bind
    err = l.GSSAPIBind(gssapiClient, "ldap/ldap.example.com", "")
    if err != nil {
        log.Fatal(err)
    }

    log.Println("Successfully authenticated with GSSAPI")
}
```

### Unix/Linux: Authentication with Password

Username/password authentication obtains a fresh Kerberos ticket:

```go
gssapiClient, err := gssapi.NewClientWithPassword(
    "ldapuser",
    "EXAMPLE.COM",
    "secretpassword",
    "/etc/krb5.conf",
)
if err != nil {
    log.Fatal(err)
}
defer gssapiClient.Close()

l, err := ldap.DialURL("ldap://ldap.example.com:389")
if err != nil {
    log.Fatal(err)
}
defer l.Close()

err = l.GSSAPIBind(gssapiClient, "ldap/ldap.example.com", "")
if err != nil {
    log.Fatal(err)
}
```

### Unix/Linux: Authentication with Credential Cache

Reuse existing Kerberos tickets obtained via `kinit`:

```go
// First, obtain a ticket: kinit ldapuser@EXAMPLE.COM
// This creates a credential cache (typically /tmp/krb5cc_$(id -u))

gssapiClient, err := gssapi.NewClientFromCCache(
    "/tmp/krb5cc_1000",  // Path to credential cache
    "/etc/krb5.conf",
)
if err != nil {
    log.Fatal(err)
}
defer gssapiClient.Close()

l, err := ldap.DialURL("ldap://ldap.example.com:389")
if err != nil {
    log.Fatal(err)
}
defer l.Close()

err = l.GSSAPIBind(gssapiClient, "ldap/ldap.example.com", "")
if err != nil {
    log.Fatal(err)
}
```

### Windows: Authentication with Current User Credentials

```go
package main

import (
    "log"
    
    "github.com/go-ldap/ldap/v3"
    "github.com/go-ldap/ldap/v3/gssapi"
)

func main() {
    // Create SSPI client using current Windows user credentials
    sspiClient, err := gssapi.NewSSPIClient()
    if err != nil {
        log.Fatal(err)
    }
    defer sspiClient.Close()

    l, err := ldap.DialURL("ldap://ldap.example.com:389")
    if err != nil {
        log.Fatal(err)
    }
    defer l.Close()

    // Perform GSSAPI bind
    err = l.GSSAPIBind(sspiClient, "ldap/ldap.example.com", "")
    if err != nil {
        log.Fatal(err)
    }

    log.Println("Successfully authenticated with GSSAPI")
}
```

### Windows: Authentication with Specific User Credentials

```go
sspiClient, err := gssapi.NewSSPIClientWithUserCredentials(
    "EXAMPLE",           // domain
    "ldapuser",         // username
    "secretpassword",   // password
)
if err != nil {
    log.Fatal(err)
}
defer sspiClient.Close()

l, err := ldap.DialURL("ldap://ldap.example.com:389")
if err != nil {
    log.Fatal(err)
}
defer l.Close()

err = l.GSSAPIBind(sspiClient, "ldap/ldap.example.com", "")
if err != nil {
    log.Fatal(err)
}
```

## Advanced Usage

### Using GSSAPIBindRequest for More Control

The `GSSAPIBindRequest` structure allows you to specify additional options:

```go
req := &ldap.GSSAPIBindRequest{
    ServicePrincipalName: "ldap/ldap.example.com",
    AuthZID:              "u:altuser",  // Authorization identity
    Controls:             []ldap.Control{},  // LDAP controls
}

err = l.GSSAPIBindRequest(gssapiClient, req)
if err != nil {
    log.Fatal(err)
}
```

### Authorization Identity (AuthZID)

The AuthZID parameter allows you to authenticate as one principal but authorize as another. Common formats:
- `""` - Use the authenticated identity (default)
- `"u:username"` - Authorize as a different user
- `"dn:cn=user,dc=example,dc=com"` - Authorize using a specific DN

### Service Principal Names

The service principal name must match the format expected by your LDAP server:
- Standard format: `ldap/<hostname>` or `ldap/<hostname>@REALM`
- The hostname should match the server you're connecting to
- Case sensitivity depends on your Kerberos configuration

### Using with TLS/STARTTLS

GSSAPI authentication can be combined with TLS for additional protection:

```go
l, err := ldap.DialURL("ldap://ldap.example.com:389")
if err != nil {
    log.Fatal(err)
}
defer l.Close()

// Start TLS
err = l.StartTLS(&tls.Config{
    ServerName: "ldap.example.com",
})
if err != nil {
    log.Fatal(err)
}

// Perform GSSAPI bind over TLS
err = l.GSSAPIBind(gssapiClient, "ldap/ldap.example.com", "")
if err != nil {
    log.Fatal(err)
}
```

## Troubleshooting

### Debug Logging

For detailed authentication debugging, use the built-in debug logger:

```go
import "github.com/go-ldap/ldap/v3/gssapi"

// Create and attach debug logger
debugLogger := gssapi.NewStandardDebugLogger(nil)
gssapiClient.DebugLogger = debugLogger

// Perform authentication - debug output will be printed
l.GSSAPIBind(gssapiClient, "ldap/server.example.com", "")

// Inspect context after authentication
ctx := debugLogger.GetContext()
fmt.Printf("Service: %s, Iterations: %d\n", ctx.ServicePrincipal, ctx.Iteration)
```

**See [GSSAPI-DEBUG.md](GSSAPI-DEBUG.md) for complete debug logging documentation.**

### Common Issues

1. **"Cannot find KDC for realm"**
   - Check your `krb5.conf` configuration
   - Verify DNS SRV records are properly configured
   - Ensure the KDC hostname is resolvable

2. **"Server not found in Kerberos database"**
   - Verify the service principal name format
   - Check that the LDAP server has the correct SPN registered
   - Try using the fully qualified hostname

3. **"Ticket expired"**
   - Renew your Kerberos ticket: `kinit -R`
   - Or obtain a new ticket: `kinit username@REALM`
   - Check ticket lifetime settings in krb5.conf

4. **Clock Skew Issues**
   - Kerberos is sensitive to time differences
   - Ensure client and KDC clocks are synchronized (within 5 minutes)
   - Use NTP to keep systems synchronized

### Debugging

Enable debug logging to troubleshoot GSSAPI issues:

```go
l, err := ldap.DialURL("ldap://ldap.example.com:389")
if err != nil {
    log.Fatal(err)
}
l.Debug = true  // Enable debug logging
```

### Testing Kerberos Configuration

Before using GSSAPI in your application, test your Kerberos setup:

```bash
# Test getting a ticket
kinit username@REALM

# Verify ticket
klist

# Test LDAP connection with ldapsearch
ldapsearch -Y GSSAPI -H ldap://ldap.example.com -b "dc=example,dc=com"
```

## Security Considerations

1. **Keytab Security**: Keytab files contain sensitive credentials. Protect them with appropriate file permissions (e.g., 0600).

2. **Credential Cache**: Credential caches may contain replayable tickets. Secure them appropriately.

3. **TLS**: While GSSAPI provides authentication, consider using TLS for encryption and integrity protection.

4. **Mutual Authentication**: GSSAPI provides mutual authentication by default, ensuring both client and server are authenticated.

5. **Security Layers**: This implementation does not currently support SASL security layers (integrity/confidentiality). Use TLS for these protections.

## References

- [RFC 4752](https://www.rfc-editor.org/rfc/rfc4752.html) - The Kerberos V5 ("GSSAPI") SASL Mechanism
- [RFC 4513](https://www.rfc-editor.org/rfc/rfc4513.html) - LDAP: Authentication Methods and Security Mechanisms
- [RFC 4422](https://www.rfc-editor.org/rfc/rfc4422.html) - Simple Authentication and Security Layer (SASL)
- [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120.html) - The Kerberos Network Authentication Service (V5)
- [RFC 5929](https://www.rfc-editor.org/rfc/rfc5929.html) - Channel Bindings for TLS

## License

This GSSAPI implementation is part of the go-ldap library and follows the same licensing terms.
