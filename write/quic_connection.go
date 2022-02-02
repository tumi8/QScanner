package write

import (
	"encoding/csv"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"

	// Logging
	"github.com/rs/zerolog/log"

	"gitlab.lrz.de/netintum/projects/gino/students/quic-scanner/misc"
	"gitlab.lrz.de/netintum/projects/gino/students/quic-scanner/util"
)

var quicConnectionHeader []string = []string{
	"targetid",
	"address",
	"port",
	"hostname",
	"scid",
	"dcid",
	"hasRetry",
	"startTime",
	"handshakeTime",
	"closeTime",
	"handshakeDuration",
	"connectionDuration",
	"quicVersion",
	"errorMessage",
}

type QuicConnectionResult struct {
	File   *os.File
	Writer *csv.Writer
}

func newQuicConnectionResult(outputDirectory string) ResultHandler {
	var err error
	var res *QuicConnectionResult = &QuicConnectionResult{}
	// Create and open quic connection information file
	outputFileName := "quic_connection_info.csv"
	res.File, err = os.Create(filepath.Join(outputDirectory, outputFileName))
	if err != nil {
		log.Fatal().Err(err).Msg("Cannot create quic_connection_info.csv!")
	}
	res.Writer = csv.NewWriter(res.File)
	res.Writer.Write(quicConnectionHeader)
	return ResultHandler(res)
}

func (q *QuicConnectionResult) Write(target *util.Target, certCache *misc.CertCache) {
	var handshakeDuration, connectionDuration int64
	var sessionRetry, errorMessage string
	var version uint64

	handshakeDuration = target.HandshakeTime.Sub(target.StartTime).Milliseconds()
	connectionDuration = target.CloseTime.Sub(target.StartTime).Milliseconds()



	if target.SessionError != nil {
		errorMessage = target.SessionError.Error()
	} else if target.Session != nil {
		sessionRetry = strconv.FormatBool(target.Session.GetSession().ReceivedRetry)
		version = uint64(target.Session.GetSession().GetVersion())
	}
	result := []string{
		strconv.FormatUint(target.ID, 10),
		target.Address,
		target.Port,
		target.Hostname,
		hex.EncodeToString(target.SCID),
		hex.EncodeToString(target.DCID),
		sessionRetry,
		strconv.FormatInt(target.StartTime.Unix(), 10),
		strconv.FormatInt(target.HandshakeTime.Unix(), 10),
		strconv.FormatInt(target.CloseTime.Unix(), 10),
		strconv.FormatInt(handshakeDuration, 10),
		strconv.FormatInt(connectionDuration, 10),
		strconv.FormatUint(version, 16),
		errorMessage,
	}
	if len(result) != len(quicConnectionHeader) {
		log.Fatal().Msg("QUIC connection information does not fit the header!")
	}
	q.Writer.Write(result)
}

func (q *QuicConnectionResult) Flush() {
	q.Writer.Flush()
}

func (q *QuicConnectionResult) Close() {
	err := q.File.Close()
	if err != nil {
		log.Fatal().Err(err).Msg("Cannot close quic_connection_info.csv")
	}
}
