//go:build !windows
// +build !windows

package gssapi

import (
	"fmt"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func TestStandardDebugLogger_LogPacket(t *testing.T) {
	var output strings.Builder
	logger := NewStandardDebugLogger(func(format string, args ...interface{}) {
		fmt.Fprintf(&output, format, args...)
	})

	pkt := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	logger.LogPacket("tx", 42, pkt)

	out := output.String()
	if !strings.Contains(out, "LDAP Packet tx") {
		t.Fatalf("expected packet log entry, got: %s", out)
	}
	if !strings.Contains(out, "msgID=42") {
		t.Fatalf("expected msgID in log, got: %s", out)
	}
	if !strings.Contains(out, "desc=LDAP Request") {
		t.Fatalf("expected packet description in log, got: %s", out)
	}
}

func TestStandardDebugLogger_LogPacketNil(t *testing.T) {
	var output strings.Builder
	logger := NewStandardDebugLogger(func(format string, args ...interface{}) {
		fmt.Fprintf(&output, format, args...)
	})

	logger.LogPacket("rx", 7, nil)

	out := output.String()
	if !strings.Contains(out, "packet=nil") {
		t.Fatalf("expected nil packet log entry, got: %s", out)
	}
}
