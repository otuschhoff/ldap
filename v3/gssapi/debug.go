package gssapi

import (
	"encoding/hex"
	"fmt"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/jcmturner/gokrb5/v8/types"
)

// DebugLogger is an interface for receiving detailed GSSAPI lifecycle events.
// Implementing this interface allows deep inspection of the authentication process
// for debugging and troubleshooting purposes.
type DebugLogger interface {
	// LogClientCreation is called when a GSSAPI client is successfully created.
	LogClientCreation(method, username, realm string)

	// LogServiceTicketRequest is called before requesting a service ticket from the KDC.
	LogServiceTicketRequest(servicePrincipal string)

	// LogServiceTicketResponse is called after receiving a service ticket.
	LogServiceTicketResponse(ticket interface{}, encryptionKey types.EncryptionKey)

	// LogInitSecContext is called during InitSecContext operations.
	// phase indicates which stage: "request" or "response"
	LogInitSecContext(phase string, iteration int, tokenLen int, needContinue bool, err error)

	// LogTokenDetails provides detailed information about tokens being exchanged.
	LogTokenDetails(direction string, tokenType string, token []byte)

	// LogNegotiateSaslAuth is called during the SASL negotiation phase.
	LogNegotiateSaslAuth(phase string, securityLayers byte, maxBuffer uint32, authzid string)

	// LogEncryptionDetails provides information about encryption keys and algorithms.
	LogEncryptionDetails(keyType int32, isSubkey bool)

	// LogBindRequest is called when sending an LDAP bind request.
	LogBindRequest(messageID int64, servicePrincipal string, tokenLen int)

	// LogBindResponse is called when receiving an LDAP bind response.
	LogBindResponse(messageID int64, resultCode int64, serverToken []byte)

	// LogPacket is called for every LDAP packet transmitted or received.
	// direction is "tx" or "rx".
	LogPacket(direction string, messageID int64, packet *ber.Packet)

	// LogError is called when an error occurs during the GSSAPI lifecycle.
	LogError(operation string, err error)

	// LogCompletion is called when the GSSAPI bind completes successfully.
	LogCompletion(duration time.Duration)
}

// DebugContext provides access to internal data structures for debugging.
type DebugContext struct {
	// ServicePrincipal is the target service principal name
	ServicePrincipal string
	// EncryptionKey is the session key (if available)
	EncryptionKey *types.EncryptionKey
	// Subkey is the subkey negotiated during authentication (if available)
	Subkey *types.EncryptionKey
	// Iteration is the current iteration in the token exchange
	Iteration int
	// StartTime is when the bind operation started
	StartTime time.Time
}

// StandardDebugLogger is a default implementation that logs to a provided output function.
type StandardDebugLogger struct {
	Output func(format string, args ...interface{})
	Ctx    *DebugContext
}

// NewStandardDebugLogger creates a new StandardDebugLogger with the given output function.
// If outputFunc is nil, it defaults to fmt.Printf.
func NewStandardDebugLogger(outputFunc func(format string, args ...interface{})) *StandardDebugLogger {
	if outputFunc == nil {
		outputFunc = func(format string, args ...interface{}) {
			fmt.Printf(format, args...)
		}
	}
	return &StandardDebugLogger{
		Output: outputFunc,
		Ctx:    &DebugContext{StartTime: time.Now()},
	}
}

func (d *StandardDebugLogger) LogClientCreation(method, username, realm string) {
	d.Output("[GSSAPI] Client created: method=%s, username=%s, realm=%s\n", method, username, realm)
}

func (d *StandardDebugLogger) LogServiceTicketRequest(servicePrincipal string) {
	d.Ctx.ServicePrincipal = servicePrincipal
	d.Output("[GSSAPI] Requesting service ticket: principal=%s\n", servicePrincipal)
}

func (d *StandardDebugLogger) LogServiceTicketResponse(ticket interface{}, encryptionKey types.EncryptionKey) {
	d.Ctx.EncryptionKey = &encryptionKey
	d.Output("[GSSAPI] Service ticket received: keyType=%d, keyLength=%d\n",
		encryptionKey.KeyType, len(encryptionKey.KeyValue))
}

func (d *StandardDebugLogger) LogInitSecContext(phase string, iteration int, tokenLen int, needContinue bool, err error) {
	d.Ctx.Iteration = iteration
	if err != nil {
		d.Output("[GSSAPI] InitSecContext[%d] %s: tokenLen=%d, error=%v\n", iteration, phase, tokenLen, err)
	} else {
		d.Output("[GSSAPI] InitSecContext[%d] %s: tokenLen=%d, needContinue=%v\n", iteration, phase, tokenLen, needContinue)
	}
}

func (d *StandardDebugLogger) LogTokenDetails(direction string, tokenType string, token []byte) {
	if len(token) > 64 {
		d.Output("[GSSAPI] Token %s: type=%s, length=%d, preview=%s...\n",
			direction, tokenType, len(token), hex.EncodeToString(token[:32]))
	} else {
		d.Output("[GSSAPI] Token %s: type=%s, length=%d, data=%s\n",
			direction, tokenType, len(token), hex.EncodeToString(token))
	}
}

func (d *StandardDebugLogger) LogNegotiateSaslAuth(phase string, securityLayers byte, maxBuffer uint32, authzid string) {
	d.Output("[GSSAPI] SASL Negotiation %s: securityLayers=0x%02x, maxBuffer=%d, authzid=%q\n",
		phase, securityLayers, maxBuffer, authzid)
}

func (d *StandardDebugLogger) LogEncryptionDetails(keyType int32, isSubkey bool) {
	keyTypeStr := "session"
	if isSubkey {
		keyTypeStr = "subkey"
	}
	d.Output("[GSSAPI] Encryption %s: type=%d\n", keyTypeStr, keyType)
}

func (d *StandardDebugLogger) LogBindRequest(messageID int64, servicePrincipal string, tokenLen int) {
	d.Output("[GSSAPI] LDAP Bind Request: msgID=%d, principal=%s, tokenLen=%d\n",
		messageID, servicePrincipal, tokenLen)
}

func (d *StandardDebugLogger) LogBindResponse(messageID int64, resultCode int64, serverToken []byte) {
	d.Output("[GSSAPI] LDAP Bind Response: msgID=%d, resultCode=%d, serverTokenLen=%d\n",
		messageID, resultCode, len(serverToken))
}

func (d *StandardDebugLogger) LogPacket(direction string, messageID int64, packet *ber.Packet) {
	if packet == nil {
		d.Output("[GSSAPI] LDAP Packet %s: msgID=%d, packet=nil\n", direction, messageID)
		return
	}
	childCount := len(packet.Children)
	d.Output("[GSSAPI] LDAP Packet %s: msgID=%d, tag=%d, class=%d, children=%d, desc=%s\n",
		direction, messageID, packet.Tag, packet.ClassType, childCount, packet.Description)
}

func (d *StandardDebugLogger) LogError(operation string, err error) {
	d.Output("[GSSAPI] ERROR in %s: %v\n", operation, err)
}

func (d *StandardDebugLogger) LogCompletion(duration time.Duration) {
	d.Output("[GSSAPI] Authentication completed successfully in %v\n", duration)
}

// GetContext returns a copy of the current debug context.
func (d *StandardDebugLogger) GetContext() DebugContext {
	ctx := *d.Ctx
	return ctx
}
