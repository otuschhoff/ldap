//go:build !windows
// +build !windows

package gssapi

import (
	"encoding/binary"
	"strings"
	"testing"

	krbgssapi "github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestNewClientFromCCacheDataRejectsNilCache(t *testing.T) {
	_, err := NewClientFromCCacheData(nil, "")
	if err == nil || !strings.Contains(err.Error(), "credential cache is nil") {
		t.Fatalf("NewClientFromCCacheData() error = %v", err)
	}
}

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

func TestClientSetServiceTicket(t *testing.T) {
	client := &Client{}

	ticket := messages.Ticket{
		SName: types.PrincipalName{
			NameType:   2,
			NameString: []string{"ldap", "example.com"},
		},
	}
	key := types.EncryptionKey{KeyType: 18, KeyValue: []byte{0x01, 0x02}}
	spn := "ldap/example.com"

	if err := client.SetServiceTicket(spn, ticket, key); err != nil {
		t.Fatalf("expected SetServiceTicket to succeed, got: %v", err)
	}

	entry, ok := client.serviceTickets[spn]
	if !ok {
		t.Fatalf("expected service ticket to be stored")
	}
	if entry.key.KeyType != key.KeyType {
		t.Fatalf("expected key to be stored, got: %d", entry.key.KeyType)
	}
}

func TestClientSetServiceTicketMismatch(t *testing.T) {
	client := &Client{}

	ticket := messages.Ticket{
		SName: types.PrincipalName{
			NameType:   2,
			NameString: []string{"ldap", "example.com"},
		},
	}
	key := types.EncryptionKey{KeyType: 18, KeyValue: []byte{0x01, 0x02}}

	if err := client.SetServiceTicket("ldap/other.example.com", ticket, key); err == nil {
		t.Fatalf("expected SetServiceTicket to fail on SPN mismatch")
	}
}

func TestNegotiateSaslAuthResetsApplicationSequenceNumbers(t *testing.T) {
	key := types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)}
	client := &Client{ekey: key}

	serverNegotiation, err := krbgssapi.NewSecurityContext(key, false, 0, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := serverNegotiation.Wrap([]byte{0x04, 0xff, 0xff, 0xff}, false)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.NegotiateSaslAuth(offer, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := serverNegotiation.Unwrap(response); err != nil {
		t.Fatalf("unwrap negotiation response: %v", err)
	}

	serverApplication, err := krbgssapi.NewSecurityContext(key, false, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	request, err := client.WrapSASL([]byte("request"))
	if err != nil {
		t.Fatal(err)
	}
	if plaintext, confidential, err := serverApplication.Unwrap(request); err != nil {
		t.Fatalf("unwrap application request: %v", err)
	} else if !confidential || string(plaintext) != "request" {
		t.Fatalf("application request = %q, confidential = %v", plaintext, confidential)
	}

	reply, err := serverApplication.Wrap([]byte("response"), true)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext, err := client.UnwrapSASL(reply); err != nil {
		t.Fatalf("unwrap application response: %v", err)
	} else if string(plaintext) != "response" {
		t.Fatalf("application response = %q", plaintext)
	}
}

// wrapTokenHeader builds a valid 16-byte acceptor WrapToken header with the
// given checksum length (EC) field.
func wrapTokenHeader(checksumLen uint16) []byte {
	h := make([]byte, krbgssapi.HdrLen)
	h[0], h[1] = 0x05, 0x04 // token id
	h[2] = 0x01             // acceptor flag set
	h[3] = krbgssapi.FillerByte
	binary.BigEndian.PutUint16(h[4:6], checksumLen)
	return h
}

// A malicious server can set the checksum-length field high enough that
// 16 + checksumL overflows uint16. The sanity check still passes because the
// token is large, so the bad offset reached the slice operations.
func TestUnmarshalWrapTokenChecksumLengthOverflow(t *testing.T) {
	const checksumLen = uint16(0xFFFF)
	b := wrapTokenHeader(checksumLen)
	// Pad so len(b)-HdrLen >= checksumLen and the sanity check is satisfied.
	b = append(b, make([]byte, int(checksumLen))...)

	wt := &krbgssapi.WrapToken{}
	if err := UnmarshalWrapToken(wt, b, true); err != nil {
		t.Logf("got expected error: %v", err)
	}
}

func TestUnmarshalWrapTokenSplit(t *testing.T) {
	checksum := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	payload := []byte("payload")

	b := wrapTokenHeader(uint16(len(checksum)))
	b = append(b, checksum...)
	b = append(b, payload...)

	wt := &krbgssapi.WrapToken{}
	if err := UnmarshalWrapToken(wt, b, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(wt.CheckSum) != string(checksum) {
		t.Errorf("checksum: got %x, want %x", wt.CheckSum, checksum)
	}
	if string(wt.Payload) != string(payload) {
		t.Errorf("payload: got %q, want %q", wt.Payload, payload)
	}
}
