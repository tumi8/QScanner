package write

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"os"
	"path/filepath"

	// Logging
	"github.com/rs/zerolog/log"

	"github.com/tumi8/qscanner/misc"
	"github.com/tumi8/qscanner/util"
)

// beginCertificate and endCertificate signal start and beginning of PEM-encoded TLS certificates
const beginCertificate = "-----BEGIN CERTIFICATE-----"
const endCertificate = "-----END CERTIFICATE-----"

var tlsCertificatesHeader []string = []string{
	"id",
	"hash",
	"cert",
}

type TLSCertificatesResult struct {
	File   *os.File
	Writer *csv.Writer
}

func newTLSCertificatesResult(outputDirectory string) ResultHandler {
	var err error
	var res *TLSCertificatesResult = &TLSCertificatesResult{}
	// Create and open quic connection information file
	outputFileName := "tls_certificates.csv"
	res.File, err = os.Create(filepath.Join(outputDirectory, outputFileName))
	if err != nil {
		log.Fatal().Err(err).Msg("Cannot create tls_certificates.csv!")
	}
	res.Writer = csv.NewWriter(res.File)
	res.Writer.Write(tlsCertificatesHeader)
	return ResultHandler(res)
}

func (q *TLSCertificatesResult) Write(target *util.Target, certCache *misc.CertCache) {
	connectionState := target.Session.ConnectionState().TLS
	for _, certificate := range connectionState.PeerCertificates {
		id, isNew := certCache.GetID(certificate)
		if isNew {
			certString := misc.OpensslFormat(base64.StdEncoding.EncodeToString(certificate.Raw), beginCertificate, endCertificate)
			certHash := hex.EncodeToString(misc.GetSHA256(certificate.Raw))
			result := []string{id.ToString(), certHash, certString}
			if len(result) != len(tlsCertificatesHeader) {
				log.Fatal().Msg("TLS certificates do not fit the header!")
			}
			err := q.Writer.Write(result)
			if err != nil {
				log.Fatal().Err(err)
			}
			certCache.MarkOld(certificate)
		}
	}
}

func (q *TLSCertificatesResult) Flush() {
	q.Writer.Flush()
}

func (q *TLSCertificatesResult) Close() {
	err := q.File.Close()
	if err != nil {
		log.Fatal().Err(err).Msg("Cannot close tls_certificates.csv!")
	}
}
