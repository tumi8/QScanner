package write

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strconv"

	// Logging
	"github.com/rs/zerolog/log"

	"gitlab.lrz.de/netintum/projects/gino/students/quic-scanner/misc"
	"gitlab.lrz.de/netintum/projects/gino/students/quic-scanner/util"
)

var quicHTTPHeaderHeader []string = []string{
	"targetid",
	"address",
	"port",
	"hostname",
	"Header",
	"Value",
}

type HTTPHeaderResult struct {
	File   *os.File
	Writer *csv.Writer
}

func newHTTPHeaderResult(outputDirectory string) ResultHandler {
	var err error
	var res *HTTPHeaderResult = &HTTPHeaderResult{}
	// Create and open quic connection information file
	outputFileName := "http_header.csv"
	res.File, err = os.Create(filepath.Join(outputDirectory, outputFileName))
	if err != nil {
		log.Fatal().Err(err).Msg("Cannot create http_header.csv!")
	}
	res.Writer = csv.NewWriter(res.File)
	res.Writer.Write(quicHTTPHeaderHeader)
	return ResultHandler(res)
}

func (q *HTTPHeaderResult) Write(target *util.Target, certCache *misc.CertCache) {
	if target.HTTP == nil {
		return
	}
	for header := range target.HTTP.Header {
		result := []string{
			strconv.FormatUint(target.ID, 10),
			target.Address,
			target.Port,
			target.Hostname,
			header,
			misc.ToPostgresArray(target.HTTP.Header[header]),
		}
		if len(result) != len(quicHTTPHeaderHeader) {
			log.Fatal().Msg("QUIC head info does not fit the header!")
		}
		q.Writer.Write(result)
	}
}

func (q *HTTPHeaderResult) Flush() {
	q.Writer.Flush()
}

func (q *HTTPHeaderResult) Close() {
	err := q.File.Close()
	if err != nil {
		log.Fatal().Err(err).Msg("Cannot close http_header.csv")
	}
}
