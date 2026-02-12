//go:build !windows
// +build !windows

package gssapi

import (
	"testing"
)

// TestClientConstructors tests that the client constructors properly handle input parameters.
func TestClientConstructors(t *testing.T) {
	tests := []struct {
		name         string
		username     string
		realm        string
		password     string
		keytabPath   string
		ccachePath   string
		krb5confPath string
		constructor  string
		shouldError  bool
	}{
		{
			name:         "NewClientWithPassword - missing krb5.conf",
			username:     "testuser",
			realm:        "TEST.COM",
			password:     "password",
			krb5confPath: "/nonexistent/krb5.conf",
			constructor:  "password",
			shouldError:  true,
		},
		{
			name:         "NewClientWithKeytab - missing krb5.conf",
			username:     "testuser",
			realm:        "TEST.COM",
			keytabPath:   "/nonexistent/keytab",
			krb5confPath: "/nonexistent/krb5.conf",
			constructor:  "keytab",
			shouldError:  true,
		},
		{
			name:         "NewClientFromCCache - missing krb5.conf",
			ccachePath:   "/nonexistent/ccache",
			krb5confPath: "/nonexistent/krb5.conf",
			constructor:  "ccache",
			shouldError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error

			switch tt.constructor {
			case "password":
				_, err = NewClientWithPassword(tt.username, tt.realm, tt.password, tt.krb5confPath)
			case "keytab":
				_, err = NewClientWithKeytab(tt.username, tt.realm, tt.keytabPath, tt.krb5confPath)
			case "ccache":
				_, err = NewClientFromCCache(tt.ccachePath, tt.krb5confPath)
			}

			if tt.shouldError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestClientDeleteSecContext tests that DeleteSecContext clears the encryption keys.
func TestClientDeleteSecContext(t *testing.T) {
	client := &Client{}
	
	// Set some dummy keys
	client.ekey.KeyType = 17
	client.Subkey.KeyType = 18
	
	err := client.DeleteSecContext()
	if err != nil {
		t.Errorf("DeleteSecContext should not error, got: %v", err)
	}
	
	// Verify keys are cleared
	if client.ekey.KeyType != 0 {
		t.Errorf("ekey should be cleared")
	}
	if client.Subkey.KeyType != 0 {
		t.Errorf("Subkey should be cleared")
	}
}
