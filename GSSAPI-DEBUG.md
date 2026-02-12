# GSSAPI Debug Logging

This document describes the comprehensive debugging capabilities available for GSSAPI/Kerberos authentication.

## Overview

The GSSAPI implementation provides detailed lifecycle logging and access to internal data structures through the `DebugLogger` interface. This enables:

- **Detailed authentication lifecycle logging** - Track every step of the GSSAPI/SASL authentication process
- **Token inspection** - Examine tokens exchanged between client and server
- **Encryption details** - View information about session keys and subkeys
- **Error tracking** - Capture detailed error information at each stage
- **Performance monitoring** - Track authentication duration and iterations
- **Data structure access** - Inspect encryption keys, service principals, and context

## Quick Start

```go
import (
    "github.com/go-ldap/ldap/v3"
    "github.com/go-ldap/ldap/v3/gssapi"
)

// Create a standard debug logger
debugLogger := gssapi.NewStandardDebugLogger(nil)

// Create and configure GSSAPI client
client, _ := gssapi.NewClientWithPassword("user", "REALM", "pass", "/etc/krb5.conf")
client.DebugLogger = debugLogger // Attach debug logger

// Connect and bind - debug output will be printed
l, _ := ldap.DialURL("ldap://server.example.com:389")
l.GSSAPIBind(client, "ldap/server.example.com", "")

// Inspect context after authentication
ctx := debugLogger.GetContext()
fmt.Printf("Service: %s, Duration: %v\n", ctx.ServicePrincipal, time.Since(ctx.StartTime))
```

## DebugLogger Interface

The `DebugLogger` interface provides hooks into every stage of GSSAPI authentication:

```go
type DebugLogger interface {
    // Client lifecycle
    LogClientCreation(method, username, realm string)
    
    // Service ticket operations
    LogServiceTicketRequest(servicePrincipal string)
    LogServiceTicketResponse(ticket interface{}, encryptionKey types.EncryptionKey)
    
    // Security context establishment
    LogInitSecContext(phase string, iteration int, tokenLen int, needContinue bool, err error)
    LogTokenDetails(direction string, tokenType string, token []byte)
    
    // SASL negotiation
    LogNegotiateSaslAuth(phase string, securityLayers byte, maxBuffer uint32, authzid string)
    
    // Encryption information
    LogEncryptionDetails(keyType int32, isSubkey bool)
    
    // LDAP bind operations
    LogBindRequest(messageID int64, servicePrincipal string, tokenLen int)
    LogBindResponse(messageID int64, resultCode int64, serverToken []byte)

    // Packet-level callbacks for each LDAP TX/RX
    LogPacket(direction string, messageID int64, packet *ber.Packet)
    
    // Error handling
    LogError(operation string, err error)
    
    // Completion
    LogCompletion(duration time.Duration)
}
```

## StandardDebugLogger

The built-in `StandardDebugLogger` implementation provides formatted output:

```go
// Create with default output (fmt.Printf)
logger := gssapi.NewStandardDebugLogger(nil)

// Create with custom output function
logger := gssapi.NewStandardDebugLogger(func(format string, args ...interface{}) {
    log.Printf(format, args...)
})
```

## Packet-Level Debugging

The packet callback fires for every LDAP packet sent and received during the
GSSAPI bind exchange. This is useful for low-level protocol debugging and
correlating LDAP message IDs with GSSAPI state.

```go
type PacketOnlyLogger struct {
    *gssapi.StandardDebugLogger
}

func (p *PacketOnlyLogger) LogPacket(direction string, messageID int64, packet *ber.Packet) {
    if packet == nil {
        log.Printf("packet %s id=%d: nil", direction, messageID)
        return
    }
    log.Printf("packet %s id=%d: tag=%d desc=%s", direction, messageID, packet.Tag, packet.Description)
}

logger := &PacketOnlyLogger{StandardDebugLogger: gssapi.NewStandardDebugLogger(nil)}
client.DebugLogger = logger
```

### Example Output

```
[GSSAPI] Client created: method=password, username=testuser, realm=EXAMPLE.COM
[GSSAPI] Requesting service ticket: principal=ldap/server.example.com
[GSSAPI] Service ticket received: keyType=18, keyLength=32
[GSSAPI] Encryption session: type=18
[GSSAPI] InitSecContext[0] start: tokenLen=0, needContinue=false
[GSSAPI] Token outgoing: type=AP-REQ, length=1247, preview=6082...
[GSSAPI] InitSecContext[0] complete: tokenLen=1247, needContinue=true
[GSSAPI] LDAP Bind Request: msgID=1, principal=GSSAPI, tokenLen=1247
[GSSAPI] LDAP Bind Response: msgID=1, resultCode=14, serverTokenLen=215
[GSSAPI] Token incoming: type=server-response, length=215, data=a182...
[GSSAPI] Token incoming: type=AP-REP, length=215, data=a182...
[GSSAPI] Encryption subkey: type=18
[GSSAPI] InitSecContext[1] complete: tokenLen=0, needContinue=false
[GSSAPI] Token incoming: type=SASL-wrap, length=40, data=0504...
[GSSAPI] SASL Negotiation received: securityLayers=0x07, maxBuffer=65536, authzid=""
[GSSAPI] SASL Negotiation sending: securityLayers=0x00, maxBuffer=0, authzid=""
[GSSAPI] Token outgoing: type=SASL-wrap, length=56, data=0504...
[GSSAPI] LDAP Bind Request: msgID=2, principal=GSSAPI, tokenLen=56
[GSSAPI] LDAP Bind Response: msgID=2, resultCode=0, serverTokenLen=0
[GSSAPI] Authentication completed successfully in 145.23ms
```

## DebugContext

Access internal state after authentication:

```go
ctx := debugLogger.GetContext()

// Access fields
ctx.ServicePrincipal  // Target service principal
ctx.EncryptionKey     // Session encryption key
ctx.Subkey            // Negotiated subkey (if any)
ctx.Iteration         // Number of token exchanges
ctx.StartTime         // When authentication started
```

## Custom Debug Loggers

### Selective Logging

Log only specific events:

```go
logger := gssapi.NewStandardDebugLogger(func(format string, args ...interface{}) {
    // Only log errors
    if strings.Contains(format, "ERROR") {
        log.Printf(format, args...)
    }
})
```

### File Logging

Write debug output to a file:

```go
f, _ := os.OpenFile("gssapi-debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
defer f.Close()

fileLogger := log.New(f, "", log.LstdFlags)
debugLogger := gssapi.NewStandardDebugLogger(func(format string, args ...interface{}) {
    fileLogger.Printf(format, args...)
})
```

### Structured Logging

Integrate with structured logging systems:

```go
import "go.uber.org/zap"

zapLogger, _ := zap.NewProduction()
defer zapLogger.Sync()

debugLogger := gssapi.NewStandardDebugLogger(func(format string, args ...interface{}) {
    msg := fmt.Sprintf(format, args...)
    zapLogger.Info(msg, zap.String("component", "gssapi"))
})
```

### Metric Collection

Collect authentication metrics:

```go
type MetricsCollector struct {
    *gssapi.StandardDebugLogger
    errors    int
    duration  time.Duration
    iteration int
}

func (m *MetricsCollector) LogError(operation string, err error) {
    m.errors++
    m.StandardDebugLogger.LogError(operation, err)
}

func (m *MetricsCollector) LogCompletion(duration time.Duration) {
    m.duration = duration
    m.StandardDebugLogger.LogCompletion(duration)
    
    // Send to metrics system
    metrics.RecordGSSAPIAuth(m.duration, m.errors, m.iteration)
}

collector := &MetricsCollector{
    StandardDebugLogger: gssapi.NewStandardDebugLogger(nil),
}
client.DebugLogger = collector
```

## Implementing Custom DebugLogger

Create a fully custom implementation:

```go
type CustomLogger struct {
    events []AuthEvent
}

type AuthEvent struct {
    Timestamp time.Time
    Phase     string
    Details   map[string]interface{}
}

func (c *CustomLogger) LogClientCreation(method, username, realm string) {
    c.events = append(c.events, AuthEvent{
        Timestamp: time.Now(),
        Phase:     "client_creation",
        Details: map[string]interface{}{
            "method":   method,
            "username": username,
            "realm":    realm,
        },
    })
}

// Implement other interface methods...

func (c *CustomLogger) LogError(operation string, err error) {
    c.events = append(c.events, AuthEvent{
        Timestamp: time.Now(),
        Phase:     "error",
        Details: map[string]interface{}{
            "operation": operation,
            "error":     err.Error(),
        },
    })
}

// ... implement remaining methods
```

## Debugging Common Issues

### Issue: "Cannot find KDC"

Enable debug logging and check:
```
[GSSAPI] ERROR in GetServiceTicket: Cannot locate KDC for realm EXAMPLE.COM
```
**Solution**: Verify krb5.conf realm configuration and DNS SRV records.

### Issue: "Clock skew too great"

Look for timing information:
```
[GSSAPI] ERROR in DecryptEncPart: Clock skew detected
```
**Solution**: Synchronize system clocks using NTP.

### Issue: Token exchange failures

Check token details:
```
[GSSAPI] Token outgoing: type=AP-REQ, length=0
[GSSAPI] ERROR in Marshal AP-REQ: invalid ticket
```
**Solution**: Verify service principal exists and is properly registered.

### Issue: SASL negotiation problems

Inspect SASL phase:
```
[GSSAPI] SASL Negotiation received: securityLayers=0x00, maxBuffer=0
[GSSAPI] ERROR in token verification: checksum mismatch
```
**Solution**: Check encryption type compatibility between client and server.

## Performance Monitoring

Track authentication performance:

```go
type PerfMonitor struct {
    *gssapi.StandardDebugLogger
    phases map[string]time.Time
}

func (p *PerfMonitor) LogInitSecContext(phase string, iteration int, tokenLen int, needContinue bool, err error) {
    p.phases[fmt.Sprintf("init_%s_%d", phase, iteration)] = time.Now()
    p.StandardDebugLogger.LogInitSecContext(phase, iteration, tokenLen, needContinue, err)
}

func (p *PerfMonitor) LogCompletion(duration time.Duration) {
    p.StandardDebugLogger.LogCompletion(duration)
    
    // Analyze phase timings
    for phase, ts := range p.phases {
        fmt.Printf("Phase %s took: %v\n", phase, time.Since(ts))
    }
}
```

## Security Considerations

**Warning**: Debug logs may contain sensitive information:
- Service principal names
- Token contents (encrypted but identifiable)
- Timing information
- Error messages that reveal configuration

### Best Practices

1. **Disable in Production**: Only enable debug logging during troubleshooting
2. **Secure Log Files**: Restrict access to debug log files (chmod 600)
3. **Log Rotation**: Implement log rotation to prevent disk filling
4. **Sanitize Output**: Filter sensitive information in custom loggers
5. **Temporary Use**: Enable debugging temporarily, not permanently

```go
// Conditional debug logging
var debugLogger gssapi.DebugLogger
if os.Getenv("GSSAPI_DEBUG") == "1" {
    debugLogger = gssapi.NewStandardDebugLogger(nil)
}
if debugLogger != nil {
    client.DebugLogger = debugLogger
}
```

## Troubleshooting Workflow

1. **Enable Standard Debug Logger**
```go
client.DebugLogger = gssapi.NewStandardDebugLogger(nil)
```

2. **Reproduce the Issue**
```
Run the authentication that's failing
Capture complete debug output
```

3. **Analyze Output**
```
Look for ERROR messages
Check token exchange sequence
Verify encryption key types
Examine SASL negotiation
```

4. **Check Context**
```go
ctx := debugLogger.GetContext()
fmt.Printf("Final state: %+v\n", ctx)
```

5. **Compare with Working Config**
```
Compare debug output between working and failing authentication
Look for differences in tokens, keys, or negotiation
```

## Integration with Existing Debugging

Combine with LDAP connection debugging:

```go
l, _ := ldap.DialURL("ldap://server.example.com:389")
l.Debug = true  // Enable LDAP protocol debugging

client.DebugLogger = gssapi.NewStandardDebugLogger(nil)  // Enable GSSAPI debugging
l.GSSAPIBind(client, "ldap/server.example.com", "")

// Get complete picture of authentication flow
// Both LDAP protocol and GSSAPI lifecycle
```

## See Also

- [GSSAPI.md](GSSAPI.md) - Main GSSAPI documentation
- [GSSAPI-QUICKREF.md](GSSAPI-QUICKREF.md) - Quick reference guide
- [v3/examples_gssapi_debug_test.go](v3/examples_gssapi_debug_test.go) - Debug examples
