package gssapi

import "encoding/binary"

func handshakePayload(securityLayer byte, maxSize uint32, authzid []byte) []byte {
	var truncatedSize uint32
	if securityLayer != 0 {
		truncatedSize = 0x00ffffff
		if truncatedSize > maxSize {
			truncatedSize = maxSize
		}
	}

	payload := make([]byte, 4, 4+len(authzid))
	binary.BigEndian.PutUint32(payload, truncatedSize)
	payload[0] = securityLayer
	return append(payload, authzid...)
}
