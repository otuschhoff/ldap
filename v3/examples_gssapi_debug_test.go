//go:build !windows
// +build !windows

package ldap

import (
	"fmt"
	"log"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3/gssapi"
)

// CustomDebugLogger demonstrates extending the standard logger with packet-level callbacks.
type CustomDebugLogger struct {
	*gssapi.StandardDebugLogger
	logFile *log.Logger
}

// LogPacket implements packet-level debugging for each LDAP TX/RX packet.
func (c *CustomDebugLogger) LogPacket(direction string, messageID int64, packet *ber.Packet) {
	if packet == nil {
		log.Printf("[GSSAPI-PACKET] %s msgID=%d packet=nil", direction, messageID)
		return
	}
	log.Printf("[GSSAPI-PACKET] %s msgID=%d tag=%d desc=%s", direction, messageID, packet.Tag, packet.Description)
}

// This example demonstrates how to use debug logging with GSSAPI authentication
// to troubleshoot authentication issues and inspect the authentication lifecycle.
func ExampleConn_GSSAPIBind_withDebugging() {
	// Create a standard debug logger that outputs to stdout
	debugLogger := gssapi.NewStandardDebugLogger(nil)

	// Create GSSAPI client with password
	gssapiClient, err := gssapi.NewClientWithPassword(
		"username",
		"REALM.COM",
		"password",
		"/etc/krb5.conf",
	)
	if err != nil {
		log.Fatal(err)
	}
	defer gssapiClient.Close()

	// Attach the debug logger to the client
	gssapiClient.DebugLogger = debugLogger

	// Connect to LDAP server
	l, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	// Perform GSSAPI bind - debug output will be printed during authentication
	err = l.GSSAPIBind(gssapiClient, "ldap/ldap.example.com", "")
	if err != nil {
		log.Fatal(err)
	}

	// After successful authentication, you can inspect the debug context
	ctx := debugLogger.GetContext()
	fmt.Printf("Authentication completed for: %s\n", ctx.ServicePrincipal)
	if ctx.EncryptionKey != nil {
		fmt.Printf("Session key type: %d\n", ctx.EncryptionKey.KeyType)
	}
}

// This example shows how to create a custom debug logger with specific
// formatting and selective event logging.
func ExampleConn_GSSAPIBind_customDebugLogger() {
	// Custom output function that writes to a file or specific destination
	customOutput := func(format string, args ...interface{}) {
		// You could write to a file, specific logger, or monitoring system
		log.Printf("[CUSTOM-GSSAPI] "+format, args...)
	}

	customLogger := &CustomDebugLogger{
		StandardDebugLogger: gssapi.NewStandardDebugLogger(customOutput),
	}

	gssapiClient, err := gssapi.NewClientWithKeytab(
		"serviceaccount",
		"REALM.COM",
		"/etc/krb5.keytab",
		"/etc/krb5.conf",
	)
	if err != nil {
		log.Fatal(err)
	}
	defer gssapiClient.Close()

	gssapiClient.DebugLogger = customLogger

	l, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	err = l.GSSAPIBind(gssapiClient, "ldap/ldap.example.com", "")
	if err != nil {
		log.Fatal(err)
	}
}

// This example demonstrates implementing a completely custom DebugLogger
// that only logs specific events of interest.
func ExampleConn_GSSAPIBind_selectiveDebugLogger() {
	// Define a custom debug logger that only logs errors and token details
	type SelectiveDebugLogger struct {
		errors []error
		tokens []string
	}

	logger := &SelectiveDebugLogger{}

	// Implement only the methods we care about
	type minimalLogger struct {
		*SelectiveDebugLogger
	}

	// Create wrapper that implements full interface but only does work for some methods
	wrapper := &minimalLogger{SelectiveDebugLogger: logger}

	// Add methods (showing a few key ones)
	_ = struct {
		gssapi.DebugLogger
	}{wrapper}

	gssapiClient, err := gssapi.NewClientWithPassword(
		"username",
		"REALM.COM",
		"password",
		"/etc/krb5.conf",
	)
	if err != nil {
		log.Fatal(err)
	}
	defer gssapiClient.Close()

	// Attach our selective logger
	gssapiClient.DebugLogger = gssapi.NewStandardDebugLogger(func(format string, args ...interface{}) {
		// Filter to only show errors and critical events
		if len(format) > 6 && format[:6] == "[GSSAPI] ERROR" {
			log.Printf(format, args...)
		}
	})

	l, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	err = l.GSSAPIBind(gssapiClient, "ldap/ldap.example.com", "")
	if err != nil {
		log.Fatal(err)
	}

	// Access collected data
	fmt.Printf("Total errors during authentication: %d\n", len(logger.errors))
}

// This example shows debugging with enhanced context inspection during authentication.
func ExampleConn_GSSAPIBind_debugContext() {
	debugLogger := gssapi.NewStandardDebugLogger(nil)

	gssapiClient, err := gssapi.NewClientWithPassword(
		"username",
		"REALM.COM",
		"password",
		"/etc/krb5.conf",
	)
	if err != nil {
		log.Fatal(err)
	}
	defer gssapiClient.Close()

	gssapiClient.DebugLogger = debugLogger

	l, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	err = l.GSSAPIBind(gssapiClient, "ldap/ldap.example.com", "")
	if err != nil {
		log.Fatal(err)
	}

	// Inspect the debug context for detailed information
	ctx := debugLogger.GetContext()
	fmt.Printf("Service Principal: %s\n", ctx.ServicePrincipal)
	fmt.Printf("Iterations: %d\n", ctx.Iteration)
	fmt.Printf("Total Duration: %v\n", ctx.StartTime)

	if ctx.EncryptionKey != nil {
		fmt.Printf("Encryption Key Type: %d (length: %d bytes)\n",
			ctx.EncryptionKey.KeyType,
			len(ctx.EncryptionKey.KeyValue))
	}

	if ctx.Subkey != nil {
		fmt.Printf("Subkey Type: %d (length: %d bytes)\n",
			ctx.Subkey.KeyType,
			len(ctx.Subkey.KeyValue))
	}
}
