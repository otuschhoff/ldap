package ldap

import (
	"net"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func TestQueuedRequestDrainsWhileCloseHoldsMessageMutex(t *testing.T) {
	for _, mode := range []string{"plain", "sasl"} {
		t.Run(mode, func(t *testing.T) {
			left, right := net.Pipe()
			if err := right.Close(); err != nil {
				t.Fatal(err)
			}
			conn := NewConn(left, false)
			defer conn.Close()
			if mode == "sasl" {
				conn.saslSecurityLayer = testSASLSecurityLayer{}
			}
			done := make(chan struct{})
			close(done)
			conn.chanMessage <- &messagePacket{
				Op: MessageRequest, MessageID: 1, Packet: ber.NewSequence(""),
				Context: &messageContext{id: 1, done: done, responses: make(chan *PacketResponse)},
			}
			conn.chanMessage <- &messagePacket{Op: MessageQuit}

			// Reproduce Close's critical section deterministically, without
			// depending on the reader/request scheduling that exposed the bug.
			conn.messageMutex.Lock()
			go conn.processMessages()
			drained := false
			select {
			case <-conn.chanConfirm:
				drained = true
			case <-time.After(2 * time.Second):
			}
			conn.messageMutex.Unlock()
			select {
			case <-conn.chanConfirm:
			case <-time.After(2 * time.Second):
				t.Fatal("message worker failed to drain after unlocking")
			}
			if !drained {
				t.Fatal("message worker required Close's held mutex to drain a queued request")
			}
		})
	}
}
