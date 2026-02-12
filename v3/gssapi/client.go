package gssapi

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/types"

	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/spnego"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"

	"github.com/jcmturner/gokrb5/v8/credentials"
)

// Client implements ldap.GSSAPIClient interface.
type Client struct {
	*client.Client

	ekey   types.EncryptionKey
	Subkey types.EncryptionKey
	
	// DebugLogger is an optional logger for detailed GSSAPI lifecycle events.
	// Set this to receive debugging information about authentication steps.
	DebugLogger DebugLogger

	serviceTickets map[string]serviceTicketEntry
}

type serviceTicketEntry struct {
	ticket messages.Ticket
	key    types.EncryptionKey
}

// NewClientWithKeytab creates a new client from a keytab credential.
// Set the realm to empty string to use the default realm from config.
func NewClientWithKeytab(username, realm, keytabPath, krb5confPath string, settings ...func(*client.Settings)) (*Client, error) {
	krb5conf, err := config.Load(krb5confPath)
	if err != nil {
		return nil, err
	}

	keytab, err := keytab.Load(keytabPath)
	if err != nil {
		return nil, err
	}

	client := client.NewWithKeytab(username, realm, keytab, krb5conf, settings...)

	c := &Client{
		Client: client,
	}
	if c.DebugLogger != nil {
		c.DebugLogger.LogClientCreation("keytab", username, realm)
	}
	return c, nil
}

// NewClientWithKerberosClient wraps an existing gokrb5 client.
// This is useful when callers manage Kerberos tickets themselves.
func NewClientWithKerberosClient(krbClient *client.Client) *Client {
	return &Client{
		Client: krbClient,
	}
}

// NewClientWithPassword creates a new client from a password credential.
// Set the realm to empty string to use the default realm from config.
func NewClientWithPassword(username, realm, password string, krb5confPath string, settings ...func(*client.Settings)) (*Client, error) {
	krb5conf, err := config.Load(krb5confPath)
	if err != nil {
		return nil, err
	}

	client := client.NewWithPassword(username, realm, password, krb5conf, settings...)

	c := &Client{
		Client: client,
	}
	if c.DebugLogger != nil {
		c.DebugLogger.LogClientCreation("password", username, realm)
	}
	return c, nil
}

// NewClientFromCCache creates a new client from a populated client cache.
func NewClientFromCCache(ccachePath, krb5confPath string, settings ...func(*client.Settings)) (*Client, error) {
	krb5conf, err := config.Load(krb5confPath)
	if err != nil {
		return nil, err
	}

	ccache, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return nil, err
	}

	client, err := client.NewFromCCache(ccache, krb5conf, settings...)
	if err != nil {
		return nil, err
	}

	c := &Client{
		Client: client,
	}
	if c.DebugLogger != nil {
		c.DebugLogger.LogClientCreation("ccache", ccache.DefaultPrincipal.PrincipalName.PrincipalNameString(), ccache.DefaultPrincipal.Realm)
	}
	return c, nil
}

// Close deletes any established secure context and closes the client.
func (client *Client) Close() error {
	client.Client.Destroy()
	return nil
}

// DeleteSecContext destroys any established secure context.
func (client *Client) DeleteSecContext() error {
	client.ekey = types.EncryptionKey{}
	client.Subkey = types.EncryptionKey{}
	return nil
}

// SetServiceTicket registers a service ticket for the provided SPN.
// This allows callers to manage Kerberos tickets externally and bypass KDC lookups.
// If spn is empty, the ticket's SName will be used.
func (client *Client) SetServiceTicket(spn string, ticket messages.Ticket, key types.EncryptionKey) error {
	if spn == "" {
		spn = ticket.SName.PrincipalNameString()
	}
	if spn == "" {
		return fmt.Errorf("service ticket SPN is empty")
	}
	if ticket.SName.PrincipalNameString() != spn {
		return fmt.Errorf("service ticket SPN mismatch: ticket=%s, spn=%s", ticket.SName.PrincipalNameString(), spn)
	}
	if client.serviceTickets == nil {
		client.serviceTickets = make(map[string]serviceTicketEntry)
	}
	client.serviceTickets[spn] = serviceTicketEntry{
		ticket: ticket,
		key:    key,
	}
	return nil
}

// GetDebugLogger returns the debug logger for this client.
// This method is used internally to pass the debug logger to bind operations.
func (client *Client) GetDebugLogger() interface{} {
	return client.DebugLogger
}

// InitSecContext initiates the establishment of a security context for
// GSS-API between the client and server.
// See RFC 4752 section 3.1.
func (client *Client) InitSecContext(target string, input []byte) ([]byte, bool, error) {
	return client.InitSecContextWithOptions(target, input, []int{})
}

// InitSecContextWithOptions initiates the establishment of a security context for
// GSS-API between the client and server.
// See RFC 4752 section 3.1.
func (client *Client) InitSecContextWithOptions(target string, input []byte, APOptions []int) ([]byte, bool, error) {
	if client.Client == nil {
		return nil, false, fmt.Errorf("kerberos client is nil")
	}

	gssapiFlags := []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf, gssapi.ContextFlagMutual}

	iteration := 0
	if input != nil {
		iteration = 1
	}

	if client.DebugLogger != nil {
		client.DebugLogger.LogInitSecContext("start", iteration, len(input), false, nil)
	}

	switch input {
	case nil:
		if client.DebugLogger != nil {
			client.DebugLogger.LogServiceTicketRequest(target)
		}

		var tkt messages.Ticket
		var ekey types.EncryptionKey
		if entry, ok := client.serviceTickets[target]; ok {
			tkt = entry.ticket
			ekey = entry.key
		} else {
			var err error
			tkt, ekey, err = client.Client.GetServiceTicket(target)
			if err != nil {
				if client.DebugLogger != nil {
					client.DebugLogger.LogError("GetServiceTicket", err)
				}
				return nil, false, err
			}
		}
		client.ekey = ekey
		
		if client.DebugLogger != nil {
			client.DebugLogger.LogServiceTicketResponse(tkt, ekey)
			client.DebugLogger.LogEncryptionDetails(ekey.KeyType, false)
		}

		token, err := spnego.NewKRB5TokenAPREQ(client.Client, tkt, ekey, gssapiFlags, APOptions)
		if err != nil {
			if client.DebugLogger != nil {
				client.DebugLogger.LogError("NewKRB5TokenAPREQ", err)
			}
			return nil, false, err
		}

		output, err := token.Marshal()
		if err != nil {
			if client.DebugLogger != nil {
				client.DebugLogger.LogError("Marshal AP-REQ", err)
			}
			return nil, false, err
		}

		if client.DebugLogger != nil {
			client.DebugLogger.LogTokenDetails("outgoing", "AP-REQ", output)
			client.DebugLogger.LogInitSecContext("complete", iteration, len(output), true, nil)
		}

		return output, true, nil

	default:
		if client.DebugLogger != nil {
			client.DebugLogger.LogTokenDetails("incoming", "server-response", input)
		}
		
		var token spnego.KRB5Token

		err := token.Unmarshal(input)
		if err != nil {
			if client.DebugLogger != nil {
				client.DebugLogger.LogError("Unmarshal server token", err)
			}
			return nil, false, err
		}

		var completed bool

		if token.IsAPRep() {
			completed = true
			
			if client.DebugLogger != nil {
				client.DebugLogger.LogTokenDetails("incoming", "AP-REP", input)
			}

			encpart, err := crypto.DecryptEncPart(token.APRep.EncPart, client.ekey, keyusage.AP_REP_ENCPART)
			if err != nil {
				if client.DebugLogger != nil {
					client.DebugLogger.LogError("DecryptEncPart", err)
				}
				return nil, false, err
			}

			part := &messages.EncAPRepPart{}

			if err = part.Unmarshal(encpart); err != nil {
				if client.DebugLogger != nil {
					client.DebugLogger.LogError("Unmarshal EncAPRepPart", err)
				}
				return nil, false, err
			}
			client.Subkey = part.Subkey
			
			if client.DebugLogger != nil {
				client.DebugLogger.LogEncryptionDetails(part.Subkey.KeyType, true)
			}
		}

		if token.IsKRBError() {
			if client.DebugLogger != nil {
				client.DebugLogger.LogError("KRB-ERROR received", token.KRBError)
			}
			return nil, !false, token.KRBError
		}

		if client.DebugLogger != nil {
			client.DebugLogger.LogInitSecContext("complete", iteration, 0, !completed, nil)
		}

		return make([]byte, 0), !completed, nil
	}
}

// NegotiateSaslAuth performs the last step of the SASL handshake.
// See RFC 4752 section 3.1.
func (client *Client) NegotiateSaslAuth(input []byte, authzid string) ([]byte, error) {
	if client.DebugLogger != nil {
		client.DebugLogger.LogTokenDetails("incoming", "SASL-wrap", input)
	}
	
	token := &gssapi.WrapToken{}
	err := UnmarshalWrapToken(token, input, true)
	if err != nil {
		if client.DebugLogger != nil {
			client.DebugLogger.LogError("UnmarshalWrapToken", err)
		}
		return nil, err
	}

	if (token.Flags & 0b1) == 0 {
		err := fmt.Errorf("got a Wrapped token that's not from the server")
		if client.DebugLogger != nil {
			client.DebugLogger.LogError("token validation", err)
		}
		return nil, err
	}

	key := client.ekey
	if (token.Flags & 0b100) != 0 {
		key = client.Subkey
	}

	_, err = token.Verify(key, keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		if client.DebugLogger != nil {
			client.DebugLogger.LogError("token verification", err)
		}
		return nil, err
	}

	pl := token.Payload
	if len(pl) != 4 {
		err := fmt.Errorf("server send bad final token for SASL GSSAPI Handshake")
		if client.DebugLogger != nil {
			client.DebugLogger.LogError("payload validation", err)
		}
		return nil, err
	}

	// Extract server's security layer support
	securityLayers := pl[0]
	maxBuffer := uint32(pl[1])<<16 | uint32(pl[2])<<8 | uint32(pl[3])
	
	if client.DebugLogger != nil {
		client.DebugLogger.LogNegotiateSaslAuth("received", securityLayers, maxBuffer, "")
	}

	// We never want a security layer
	b := [4]byte{0, 0, 0, 0}
	payload := append(b[:], []byte(authzid)...)

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		if client.DebugLogger != nil {
			client.DebugLogger.LogError("GetEtype", err)
		}
		return nil, err
	}

	token = &gssapi.WrapToken{
		Flags:     0b100,
		EC:        uint16(encType.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: 1,
		Payload:   payload,
	}

	if err := token.SetCheckSum(key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		if client.DebugLogger != nil {
			client.DebugLogger.LogError("SetCheckSum", err)
		}
		return nil, err
	}

	output, err := token.Marshal()
	if err != nil {
		if client.DebugLogger != nil {
			client.DebugLogger.LogError("Marshal wrap token", err)
		}
		return nil, err
	}
	
	if client.DebugLogger != nil {
		client.DebugLogger.LogNegotiateSaslAuth("sending", 0, 0, authzid)
		client.DebugLogger.LogTokenDetails("outgoing", "SASL-wrap", output)
	}

	return output, nil
}

func getGssWrapTokenId() *[2]byte {
	return &[2]byte{0x05, 0x04}
}

func UnmarshalWrapToken(wt *gssapi.WrapToken, b []byte, expectFromAcceptor bool) error {
	// Check if we can read a whole header
	if len(b) < 16 {
		return errors.New("bytes shorter than header length")
	}
	// Is the Token ID correct?
	if !bytes.Equal(getGssWrapTokenId()[:], b[0:2]) {
		return fmt.Errorf("wrong Token ID. Expected %s, was %s",
			hex.EncodeToString(getGssWrapTokenId()[:]),
			hex.EncodeToString(b[0:2]))
	}
	// Check the acceptor flag
	flags := b[2]
	isFromAcceptor := flags&0x01 == 1
	if isFromAcceptor && !expectFromAcceptor {
		return errors.New("unexpected acceptor flag is set: not expecting a token from the acceptor")
	}
	if !isFromAcceptor && expectFromAcceptor {
		return errors.New("expected acceptor flag is not set: expecting a token from the acceptor, not the initiator")
	}
	// Check the filler byte
	if b[3] != gssapi.FillerByte {
		return fmt.Errorf("unexpected filler byte: expecting 0xFF, was %s ", hex.EncodeToString(b[3:4]))
	}
	checksumL := binary.BigEndian.Uint16(b[4:6])
	// Sanity check on the checksum length
	if int(checksumL) > len(b)-gssapi.HdrLen {
		return fmt.Errorf("inconsistent checksum length: %d bytes to parse, checksum length is %d", len(b), checksumL)
	}

	payloadStart := 16 + checksumL

	wt.Flags = flags
	wt.EC = checksumL
	wt.RRC = binary.BigEndian.Uint16(b[6:8])
	wt.SndSeqNum = binary.BigEndian.Uint64(b[8:16])
	wt.CheckSum = b[16:payloadStart]
	wt.Payload = b[payloadStart:]

	return nil
}
