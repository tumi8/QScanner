package write

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	qtls "github.com/tumi8/quic-tls"

	// Logging
	"github.com/rs/zerolog/log"

	"github.com/tumi8/qscanner/misc"
	"github.com/tumi8/qscanner/util"
)

var tlsParameterHeader []string = []string{
	"targetid",
	"address",
	"port",
	"hostname",
	"protocol",
	"ciphersuite",
	"keyShareGroup",
	"serverExtensions",
	"serverEncryptedExtensions",
	"serverCertRequestExtensions",
	"helloRetryRequestExtensions",
	"certificateExtensions",
	"certificateHashes",
	"validCert",
}

type TLSParameterResult struct {
	File   *os.File
	Writer *csv.Writer
}

func newTLSParameterResult(outputDirectory string) ResultHandler {
	var err error
	var res *TLSParameterResult = &TLSParameterResult{}
	// Create and open quic connection information file
	outputFileName := "tls_shared_config.csv"
	res.File, err = os.Create(filepath.Join(outputDirectory, outputFileName))
	if err != nil {
		log.Fatal().Err(err).Msg("Cannot create tls_shared_config.csv!")
	}
	res.Writer = csv.NewWriter(res.File)
	res.Writer.Write(tlsParameterHeader)
	return ResultHandler(res)
}

func stringifyExtensions(extensions []qtls.Extension) string {
	if extensions == nil {
		return ""
	}
	jsonData, err := json.Marshal(parseExtensions(extensions))
	if err != nil {
		log.Fatal().Msg("Could not construct json extensions")
	}
	return string(jsonData)
}

// Always append extension values if the filter is empty
func parseExtensions(extensions []qtls.Extension) [][]interface{} {
	result := make([][]interface{}, len(extensions))
	for i := range extensions {
		result[i] = []interface{}{
			int(extensions[i].Type),
			base64.RawStdEncoding.EncodeToString(extensions[i].Data),
		}
	}
	return result
}

func (q *TLSParameterResult) Write(target *util.Target, certCache *misc.CertCache) {
	var protocol, cipher, keyShareGroup string
	connectionState := target.Session.ConnectionState().TLS
	if connectionState.ServerHello != nil {
		protocol = fmt.Sprintf("%x", connectionState.ServerHello.Vers)
		cipher = fmt.Sprintf("%x", connectionState.ServerHello.CipherSuite)

		if connectionState.ServerHello.ServerShare.Group > 0 {
			keyShareGroup = strconv.FormatUint(uint64(connectionState.ServerHello.ServerShare.Group), 10)
		} else if connectionState.ServerHello.SelectedGroup > 0 {
			keyShareGroup = strconv.FormatUint(uint64(connectionState.ServerHello.SelectedGroup), 10)
		}
	}
	certificateHashes := []string{}
	for _, certificate := range connectionState.PeerCertificates {
		certHash := hex.EncodeToString(misc.GetSHA256(certificate.Raw))
		certificateHashes = append(certificateHashes, certHash)
	}

	certValid := true

	opts := x509.VerifyOptions{
		CurrentTime:   target.StartTime,
		DNSName:       target.Hostname,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range connectionState.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}
	var err error
	_, err = connectionState.PeerCertificates[0].Verify(opts)
	if err != nil {
		certValid = false
	}

	result := []string{
		strconv.FormatUint(target.ID, 10),
		target.Address,
		target.Port,
		target.Hostname,
		protocol,
		cipher,
		keyShareGroup,
		stringifyExtensions(connectionState.ServerExtensions),
		stringifyExtensions(connectionState.ServerEncryptedExtensions),
		stringifyExtensions(connectionState.ServerCertRequestExtensions),
		stringifyExtensions(connectionState.HelloRetryRequestExtensions),
		stringifyExtensions(connectionState.CertificateExtensions),
		strings.Join(certificateHashes, " "),
		strconv.FormatBool(certValid),
	}
	if len(result) != len(tlsParameterHeader) {
		log.Fatal().Msg("TLS parameter do not fit the header!")
	}
	q.Writer.Write(result)
}

func (q *TLSParameterResult) Flush() {
	q.Writer.Flush()
}

func (q *TLSParameterResult) Close() {
	err := q.File.Close()
	if err != nil {
		log.Fatal().Err(err).Msg("Cannot close tls_shared_config.csv!")
	}
}
