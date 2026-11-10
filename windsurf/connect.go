package windsurf

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Connect protocol envelope handling.
// Each frame: [1 byte flags][4 bytes big-endian length][payload]
// flags & 0x02 → trailer frame (JSON, may contain error)

func envelopeWrap(body []byte) []byte {
	frame := make([]byte, 5+len(body))
	frame[0] = 0x00 // uncompressed
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(body)))
	copy(frame[5:], body)
	return frame
}

type connectFrame struct {
	IsTrailer bool
	Data      []byte
}

func readFrame(r io.Reader) (connectFrame, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return connectFrame{}, err
	}
	flags := header[0]
	length := binary.BigEndian.Uint32(header[1:5])
	if length > 16*1024*1024 {
		return connectFrame{}, fmt.Errorf("connect: frame too large: %d bytes", length)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return connectFrame{}, err
	}
	return connectFrame{
		IsTrailer: flags&0x02 != 0,
		Data:      data,
	}, nil
}

type connectTrailerError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func parseTrailerError(data []byte) error {
	var trailer struct {
		Error *connectTrailerError `json:"error"`
	}
	if err := json.Unmarshal(data, &trailer); err != nil {
		return nil
	}
	if trailer.Error != nil && trailer.Error.Message != "" {
		return errors.New(trailer.Error.Code + ": " + trailer.Error.Message)
	}
	return nil
}
