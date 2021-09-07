package util

import (
	"net/http"
	"time"

	"github.com/tumi8/quic-go"
)

type Target struct {
	Address       string
	Port          string
	Hostname      string
	StartTime     time.Time
	HandshakeTime time.Time
	CloseTime     time.Time
	Session       quic.Session
	SessionError  error
	HTTP          *http.Response
}

func (target Target) Identifier() string {
	return target.Address + ":" + target.Port + " - " + target.Hostname
}
