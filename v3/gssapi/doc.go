// Package gssapi provides GSSAPI SASL authentication support for LDAP clients.
//
// This package implements the GSSAPI SASL mechanism as defined in RFC 4752,
// providing Kerberos-based authentication for LDAP connections.
//
// Platform Support
//
// Unix/Linux: Uses pure Go Kerberos implementation (gokrb5) supporting:
//   - Keytab-based authentication
//   - Password-based authentication
//   - Credential cache (ccache) authentication
//
// Windows: Uses native SSPI (Security Support Provider Interface) supporting:
//   - Current user credentials (seamless domain authentication)
//   - Specific user credentials
//   - Channel binding for enhanced security
//
// Basic Usage
//
// Example using password authentication on Unix/Linux:
//
//	import (
//	    "github.com/go-ldap/ldap/v3"
//	    "github.com/go-ldap/ldap/v3/gssapi"
//	)
//
//	// Create GSSAPI client
//	gssapiClient, err := gssapi.NewClientWithPassword(
//	    "username",
//	    "REALM.COM",
//	    "password",
//	    "/etc/krb5.conf",
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer gssapiClient.Close()
//
//	// Connect to LDAP server
//	l, err := ldap.DialURL("ldap://ldap.example.com:389")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer l.Close()
//
//	// Perform GSSAPI bind
//	err = l.GSSAPIBind(gssapiClient, "ldap/ldap.example.com", "")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Example using keytab authentication:
//
//	gssapiClient, err := gssapi.NewClientWithKeytab(
//	    "serviceaccount",
//	    "REALM.COM",
//	    "/etc/krb5.keytab",
//	    "/etc/krb5.conf",
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer gssapiClient.Close()
//
//	l, err := ldap.DialURL("ldap://ldap.example.com:389")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer l.Close()
//
//	err = l.GSSAPIBind(gssapiClient, "ldap/ldap.example.com", "")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Example using credential cache (after kinit):
//
//	gssapiClient, err := gssapi.NewClientFromCCache(
//	    "/tmp/krb5cc_1000",
//	    "/etc/krb5.conf",
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer gssapiClient.Close()
//
//	l, err := ldap.DialURL("ldap://ldap.example.com:389")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer l.Close()
//
//	err = l.GSSAPIBind(gssapiClient, "ldap/ldap.example.com", "")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Windows Example:
//
//	import (
//	    "github.com/go-ldap/ldap/v3"
//	    "github.com/go-ldap/ldap/v3/gssapi"
//	)
//
//	// Use current Windows user credentials
//	sspiClient, err := gssapi.NewSSPIClient()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer sspiClient.Close()
//
//	l, err := ldap.DialURL("ldap://ldap.example.com:389")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer l.Close()
//
//	err = l.GSSAPIBind(sspiClient, "ldap/ldap.example.com", "")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Service Principal Names
//
// The service principal name (SPN) must match the format expected by your
// LDAP server. Common formats:
//   - "ldap/hostname" (standard format)
//   - "ldap/hostname@REALM" (with explicit realm)
//   - "ldap/hostname.domain.com" (fully qualified)
//
// The hostname in the SPN should match the hostname you're connecting to,
// and the LDAP server must have a corresponding service principal registered
// in Kerberos.
//
// Authorization Identity
//
// The authzid parameter in GSSAPIBind allows you to authenticate as one
// principal but authorize as another. Common formats:
//   - "" - Use the authenticated identity (default)
//   - "u:username" - Authorize as a different user
//   - "dn:cn=user,dc=example,dc=com" - Authorize using a specific DN
//
// Security Considerations
//
// While GSSAPI provides strong authentication and mutual authentication
// between client and server, consider using TLS/STARTTLS for additional
// protection of data in transit:
//
//	l, err := ldap.DialURL("ldap://ldap.example.com:389")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer l.Close()
//
//	// Start TLS before GSSAPI bind
//	err = l.StartTLS(&tls.Config{
//	    ServerName: "ldap.example.com",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	err = l.GSSAPIBind(gssapiClient, "ldap/ldap.example.com", "")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Note: This implementation does not currently support SASL security layers
// (integrity/confidentiality). Use TLS for encryption and integrity protection.
//
// For more detailed documentation, examples, and troubleshooting, see:
// https://github.com/go-ldap/ldap/blob/main/GSSAPI.md
package gssapi
