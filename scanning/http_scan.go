package scanning

import (
	"bytes"
	"github.com/marten-seemann/qpack"
	"github.com/tumi8/quic-go/quicvarint"
	"github.com/tumi8/qscanner/util"
	"io"
	"io/ioutil"

	"github.com/rs/zerolog/log"
)

func parseNextFrame(b io.Reader) (*headersFrame, error) {
	br, ok := b.(byteReader)
	if !ok {
		br = &byteReaderImpl{b}
	}
	t, err := quicvarint.Read(br)

	if err != nil {
		return nil, err
	}
	l, err := quicvarint.Read(br)
	if err != nil {
		return nil, err
	}
	switch t {
	case 0x0:
		fallthrough
	case 0x1:
		return &headersFrame{Length: l}, nil
	case 0x4:
		fallthrough
	case 0x3: // CANCEL_PUSH
		fallthrough
	case 0x5: // PUSH_PROMISE
		fallthrough
	case 0x7: // GOAWAY
		fallthrough
	case 0xd: // MAX_PUSH_ID
		fallthrough
	case 0xe: // DUPLICATE_PUSH
		fallthrough
	default:
		// skip over unknown frames
		if _, err := io.CopyN(ioutil.Discard, br, int64(l)); err != nil {
			return nil, err
		}
		return parseNextFrame(b)
	}
}

type byteReader interface {
	io.ByteReader
	io.Reader
}

type byteReaderImpl struct{ io.Reader }

func (br *byteReaderImpl) ReadByte() (byte, error) {
	b := make([]byte, 1)
	if _, err := br.Reader.Read(b); err != nil {
		return 0, err
	}
	return b[0], nil
}

type headersFrame struct {
	Length uint64
}

func (f *headersFrame) Write(b *bytes.Buffer) {
	quicvarint.Write(b, 0x1)
	quicvarint.Write(b, f.Length)
}

func createHttp3Message(target *util.Target) *bytes.Buffer {
	resultBuf := &bytes.Buffer{}

	headerBuf := &bytes.Buffer{}
	encoder := qpack.NewEncoder(headerBuf)

	defaultUserAgent := "quic-go-HTTP/3"
	method := "HEAD"
	host := target.Address
	if target.Hostname != "" {
		host = target.Hostname
	}
	path := "/"
	scheme := "https"
	accept := "*/*"
	encoder.WriteField(qpack.HeaderField{Name: ":method", Value: method})
	encoder.WriteField(qpack.HeaderField{Name: ":path", Value: path})
	encoder.WriteField(qpack.HeaderField{Name: ":scheme", Value: scheme})
	encoder.WriteField(qpack.HeaderField{Name: ":authority", Value: host})
	encoder.WriteField(qpack.HeaderField{Name: "user-agent", Value: defaultUserAgent})
	encoder.WriteField(qpack.HeaderField{Name: "accept", Value: accept})
	buf := &bytes.Buffer{}
	hf := headersFrame{Length: uint64(headerBuf.Len())}
	hf.Write(buf)
	if _, err := resultBuf.Write(buf.Bytes()); err != nil {
		log.Fatal().Err(err)
	}
	if _, err := resultBuf.Write(headerBuf.Bytes()); err != nil {
		log.Fatal().Err(err)
	}
	headerBuf.Reset()
	encoder.Close()
	return resultBuf
}