package ldap

import (
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func TestOperationsRejectMalformedResponse(t *testing.T) {
	tests := []struct {
		name      string
		operation func(*Conn) error
	}{
		{name: "add", operation: func(conn *Conn) error { return conn.Add(NewAddRequest("dc=example,dc=com", nil)) }},
		{name: "compare", operation: func(conn *Conn) error {
			_, err := conn.Compare("dc=example,dc=com", "objectClass", "top")
			return err
		}},
		{name: "delete", operation: func(conn *Conn) error { return conn.Del(NewDelRequest("dc=example,dc=com", nil)) }},
		{name: "modify", operation: func(conn *Conn) error { return conn.Modify(NewModifyRequest("dc=example,dc=com", nil)) }},
		{name: "modify with result", operation: func(conn *Conn) error {
			_, err := conn.ModifyWithResult(NewModifyRequest("dc=example,dc=com", nil))
			return err
		}},
		{name: "modify DN", operation: func(conn *Conn) error {
			return conn.ModifyDN(NewModifyDNRequest("dc=example,dc=com", "dc=renamed", true, ""))
		}},
		{name: "password modify", operation: func(conn *Conn) error {
			_, err := conn.PasswordModify(NewPasswordModifyRequest("", "", "new-password"))
			return err
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testMalformedResponse(t, test.operation)
		})
	}
}

func testMalformedResponse(t *testing.T, operation func(*Conn) error) {
	t.Helper()

	ptc := newPacketTranslatorConn()
	defer ptc.Close()

	conn := NewConn(ptc, false)
	conn.Start()
	defer conn.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- operation(conn)
	}()

	request, err := ptc.ReceiveRequest()
	if err != nil {
		t.Fatalf("receive password modify request: %v", err)
	}

	response := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, request.Children[0].Value, "MessageID"))
	if err := ptc.SendResponse(response); err != nil {
		t.Fatalf("send malformed response: %v", err)
	}

	select {
	case err := <-errCh:
		if !IsErrorWithCode(err, ErrorUnexpectedResponse) {
			t.Fatalf("expected unexpected response error, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("operation did not return")
	}
}
