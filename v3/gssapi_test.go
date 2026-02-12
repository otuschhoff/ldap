//go:build integration
// +build integration

package ldap

import (
	"os"
	"testing"

	"github.com/go-ldap/ldap/v3/gssapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGSSAPIBindWithPassword tests GSSAPI authentication using username and password.
// This is an integration test that requires:
// - A properly configured Kerberos environment
// - Environment variables: LDAP_URL, KRB5_USERNAME, KRB5_REALM, KRB5_PASSWORD, KRB5_CONF
func TestGSSAPIBindWithPassword(t *testing.T) {
	ldapURL := os.Getenv("LDAP_URL")
	username := os.Getenv("KRB5_USERNAME")
	realm := os.Getenv("KRB5_REALM")
	password := os.Getenv("KRB5_PASSWORD")
	krb5Conf := os.Getenv("KRB5_CONF")
	servicePrincipal := os.Getenv("LDAP_SERVICE_PRINCIPAL")

	if ldapURL == "" || username == "" || realm == "" || password == "" || krb5Conf == "" {
		t.Skip("Skipping integration test: required environment variables not set")
	}

	if servicePrincipal == "" {
		servicePrincipal = "ldap/localhost"
	}

	// Create GSSAPI client with password
	gssapiClient, err := gssapi.NewClientWithPassword(username, realm, password, krb5Conf)
	require.NoError(t, err, "Failed to create GSSAPI client")
	defer gssapiClient.Close()

	// Connect to LDAP server
	l, err := DialURL(ldapURL)
	require.NoError(t, err, "Failed to connect to LDAP server")
	defer l.Close()

	// Perform GSSAPI bind
	err = l.GSSAPIBind(gssapiClient, servicePrincipal, "")
	assert.NoError(t, err, "GSSAPI bind failed")

	// Verify we can perform a basic search after authentication
	searchRequest := NewSearchRequest(
		"dc=example,dc=com",
		ScopeBaseObject,
		NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"objectClass"},
		nil,
	)

	_, err = l.Search(searchRequest)
	assert.NoError(t, err, "Search after GSSAPI bind failed")
}

// TestGSSAPIBindWithKeytab tests GSSAPI authentication using a keytab file.
// This is an integration test that requires:
// - A properly configured Kerberos environment
// - Environment variables: LDAP_URL, KRB5_USERNAME, KRB5_REALM, KRB5_KEYTAB, KRB5_CONF
func TestGSSAPIBindWithKeytab(t *testing.T) {
	ldapURL := os.Getenv("LDAP_URL")
	username := os.Getenv("KRB5_USERNAME")
	realm := os.Getenv("KRB5_REALM")
	keytabPath := os.Getenv("KRB5_KEYTAB")
	krb5Conf := os.Getenv("KRB5_CONF")
	servicePrincipal := os.Getenv("LDAP_SERVICE_PRINCIPAL")

	if ldapURL == "" || username == "" || realm == "" || keytabPath == "" || krb5Conf == "" {
		t.Skip("Skipping integration test: required environment variables not set")
	}

	if servicePrincipal == "" {
		servicePrincipal = "ldap/localhost"
	}

	// Create GSSAPI client with keytab
	gssapiClient, err := gssapi.NewClientWithKeytab(username, realm, keytabPath, krb5Conf)
	require.NoError(t, err, "Failed to create GSSAPI client with keytab")
	defer gssapiClient.Close()

	// Connect to LDAP server
	l, err := DialURL(ldapURL)
	require.NoError(t, err, "Failed to connect to LDAP server")
	defer l.Close()

	// Perform GSSAPI bind
	err = l.GSSAPIBind(gssapiClient, servicePrincipal, "")
	assert.NoError(t, err, "GSSAPI bind with keytab failed")
}

// TestGSSAPIBindWithCCache tests GSSAPI authentication using a credential cache.
// This is an integration test that requires:
// - A properly configured Kerberos environment
// - An existing credential cache (e.g., from kinit)
// - Environment variables: LDAP_URL, KRB5_CCACHE, KRB5_CONF
func TestGSSAPIBindWithCCache(t *testing.T) {
	ldapURL := os.Getenv("LDAP_URL")
	ccachePath := os.Getenv("KRB5_CCACHE")
	krb5Conf := os.Getenv("KRB5_CONF")
	servicePrincipal := os.Getenv("LDAP_SERVICE_PRINCIPAL")

	if ldapURL == "" || ccachePath == "" || krb5Conf == "" {
		t.Skip("Skipping integration test: required environment variables not set")
	}

	if servicePrincipal == "" {
		servicePrincipal = "ldap/localhost"
	}

	// Create GSSAPI client from credential cache
	gssapiClient, err := gssapi.NewClientFromCCache(ccachePath, krb5Conf)
	require.NoError(t, err, "Failed to create GSSAPI client from ccache")
	defer gssapiClient.Close()

	// Connect to LDAP server
	l, err := DialURL(ldapURL)
	require.NoError(t, err, "Failed to connect to LDAP server")
	defer l.Close()

	// Perform GSSAPI bind
	err = l.GSSAPIBind(gssapiClient, servicePrincipal, "")
	assert.NoError(t, err, "GSSAPI bind with ccache failed")
}

// TestGSSAPIBindRequest tests the GSSAPIBindRequest API with custom options.
func TestGSSAPIBindRequest(t *testing.T) {
	ldapURL := os.Getenv("LDAP_URL")
	username := os.Getenv("KRB5_USERNAME")
	realm := os.Getenv("KRB5_REALM")
	password := os.Getenv("KRB5_PASSWORD")
	krb5Conf := os.Getenv("KRB5_CONF")
	servicePrincipal := os.Getenv("LDAP_SERVICE_PRINCIPAL")

	if ldapURL == "" || username == "" || realm == "" || password == "" || krb5Conf == "" {
		t.Skip("Skipping integration test: required environment variables not set")
	}

	if servicePrincipal == "" {
		servicePrincipal = "ldap/localhost"
	}

	// Create GSSAPI client
	gssapiClient, err := gssapi.NewClientWithPassword(username, realm, password, krb5Conf)
	require.NoError(t, err, "Failed to create GSSAPI client")
	defer gssapiClient.Close()

	// Connect to LDAP server
	l, err := DialURL(ldapURL)
	require.NoError(t, err, "Failed to connect to LDAP server")
	defer l.Close()

	// Create custom bind request
	req := &GSSAPIBindRequest{
		ServicePrincipalName: servicePrincipal,
		AuthZID:              "", // Use authenticated identity
		Controls:             []Control{},
	}

	// Perform GSSAPI bind with custom request
	err = l.GSSAPIBindRequest(gssapiClient, req)
	assert.NoError(t, err, "GSSAPI bind request failed")
}

// TestGSSAPIBindWithInvalidCredentials tests that GSSAPI bind fails with invalid credentials.
func TestGSSAPIBindWithInvalidCredentials(t *testing.T) {
	ldapURL := os.Getenv("LDAP_URL")
	username := os.Getenv("KRB5_USERNAME")
	realm := os.Getenv("KRB5_REALM")
	krb5Conf := os.Getenv("KRB5_CONF")
	servicePrincipal := os.Getenv("LDAP_SERVICE_PRINCIPAL")

	if ldapURL == "" || username == "" || realm == "" || krb5Conf == "" {
		t.Skip("Skipping integration test: required environment variables not set")
	}

	if servicePrincipal == "" {
		servicePrincipal = "ldap/localhost"
	}

	// Create GSSAPI client with invalid password
	gssapiClient, err := gssapi.NewClientWithPassword(username, realm, "invalidpassword", krb5Conf)
	require.NoError(t, err, "Failed to create GSSAPI client")
	defer gssapiClient.Close()

	// Connect to LDAP server
	l, err := DialURL(ldapURL)
	require.NoError(t, err, "Failed to connect to LDAP server")
	defer l.Close()

	// Perform GSSAPI bind - should fail
	err = l.GSSAPIBind(gssapiClient, servicePrincipal, "")
	assert.Error(t, err, "GSSAPI bind should fail with invalid credentials")
}

// TestGSSAPIBindWithInvalidServicePrincipal tests that GSSAPI bind fails with invalid SPN.
func TestGSSAPIBindWithInvalidServicePrincipal(t *testing.T) {
	ldapURL := os.Getenv("LDAP_URL")
	username := os.Getenv("KRB5_USERNAME")
	realm := os.Getenv("KRB5_REALM")
	password := os.Getenv("KRB5_PASSWORD")
	krb5Conf := os.Getenv("KRB5_CONF")

	if ldapURL == "" || username == "" || realm == "" || password == "" || krb5Conf == "" {
		t.Skip("Skipping integration test: required environment variables not set")
	}

	// Create GSSAPI client
	gssapiClient, err := gssapi.NewClientWithPassword(username, realm, password, krb5Conf)
	require.NoError(t, err, "Failed to create GSSAPI client")
	defer gssapiClient.Close()

	// Connect to LDAP server
	l, err := DialURL(ldapURL)
	require.NoError(t, err, "Failed to connect to LDAP server")
	defer l.Close()

	// Perform GSSAPI bind with invalid service principal - should fail
	err = l.GSSAPIBind(gssapiClient, "ldap/invalid.example.com", "")
	assert.Error(t, err, "GSSAPI bind should fail with invalid service principal")
}
