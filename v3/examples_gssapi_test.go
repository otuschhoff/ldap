//go:build !windows
// +build !windows

package ldap

import (
	"log"

	"github.com/go-ldap/ldap/v3/gssapi"
)

// This example demonstrates GSSAPI SASL authentication with Kerberos using
// a keytab file on Unix/Linux systems.
func ExampleConn_GSSAPIBind_withKeytab() {
	// Create a GSSAPI client using a keytab file for authentication
	// The keytab file contains the Kerberos credentials for the service account
	username := "ldapuser"
	realm := "EXAMPLE.COM"      // Use empty string for default realm
	keytabPath := "/etc/krb5.keytab"
	krb5confPath := "/etc/krb5.conf"
	
	gssapiClient, err := gssapi.NewClientWithKeytab(username, realm, keytabPath, krb5confPath)
	if err != nil {
		log.Fatal(err)
	}
	defer gssapiClient.Close()

	// Connect to the LDAP server
	l, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	// Perform GSSAPI SASL bind
	// Service principal should be in the format: ldap/<hostname>
	servicePrincipal := "ldap/ldap.example.com"
	authzid := "" // Optional authorization identity
	
	err = l.GSSAPIBind(gssapiClient, servicePrincipal, authzid)
	if err != nil {
		log.Fatal(err)
	}
	
	// Now you can perform LDAP operations...
}

// This example demonstrates GSSAPI SASL authentication with Kerberos using
// username and password on Unix/Linux systems.
func ExampleConn_GSSAPIBind_withPassword() {
	// Create a GSSAPI client using username and password
	username := "ldapuser"
	realm := "EXAMPLE.COM"      // Use empty string for default realm
	password := "secretpassword"
	krb5confPath := "/etc/krb5.conf"
	
	gssapiClient, err := gssapi.NewClientWithPassword(username, realm, password, krb5confPath)
	if err != nil {
		log.Fatal(err)
	}
	defer gssapiClient.Close()

	// Connect to the LDAP server
	l, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	// Perform GSSAPI SASL bind
	servicePrincipal := "ldap/ldap.example.com"
	authzid := ""
	
	err = l.GSSAPIBind(gssapiClient, servicePrincipal, authzid)
	if err != nil {
		log.Fatal(err)
	}
	
	// Now you can perform LDAP operations...
}

// This example demonstrates GSSAPI SASL authentication using credentials
// from a Kerberos credential cache (typically obtained via kinit).
func ExampleConn_GSSAPIBind_withCCache() {
	// Create a GSSAPI client from an existing Kerberos credential cache
	// This is useful when the user has already authenticated via kinit
	ccachePath := "/tmp/krb5cc_1000" // Path to credential cache
	krb5confPath := "/etc/krb5.conf"
	
	gssapiClient, err := gssapi.NewClientFromCCache(ccachePath, krb5confPath)
	if err != nil {
		log.Fatal(err)
	}
	defer gssapiClient.Close()

	// Connect to the LDAP server
	l, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	// Perform GSSAPI SASL bind
	servicePrincipal := "ldap/ldap.example.com"
	authzid := ""
	
	err = l.GSSAPIBind(gssapiClient, servicePrincipal, authzid)
	if err != nil {
		log.Fatal(err)
	}
	
	// Now you can perform LDAP operations...
}

// This example demonstrates advanced GSSAPI SASL authentication using
// GSSAPIBindRequest for more control over the bind operation.
func ExampleConn_GSSAPIBindRequest() {
	// Create a GSSAPI client
	username := "ldapuser"
	realm := "EXAMPLE.COM"
	password := "secretpassword"
	krb5confPath := "/etc/krb5.conf"
	
	gssapiClient, err := gssapi.NewClientWithPassword(username, realm, password, krb5confPath)
	if err != nil {
		log.Fatal(err)
	}
	defer gssapiClient.Close()

	// Connect to the LDAP server
	l, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	// Create a custom GSSAPI bind request with controls
	req := &GSSAPIBindRequest{
		ServicePrincipalName: "ldap/ldap.example.com",
		AuthZID:              "",       // Optional authorization identity
		Controls:             []Control{}, // Optional LDAP controls
	}
	
	err = l.GSSAPIBindRequest(gssapiClient, req)
	if err != nil {
		log.Fatal(err)
	}
	
	// Now you can perform LDAP operations...
}
