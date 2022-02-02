package util

import (
	"net/http"
	"time"

	"github.com/zirngibl/quic-go"
)

type Target struct {
	ID			  uint64
	Address       string
	Port          string
	Hostname      string
	StartTime     time.Time
	HandshakeTime time.Time
	CloseTime     time.Time
	Session       quic.Session
	SessionError  error
	HTTP          *http.Response
	SCID		  []byte
	DCID		  []byte
}

func (target Target) Identifier() string {
	return target.Address + ":" + target.Port + " - " + target.Hostname
}
