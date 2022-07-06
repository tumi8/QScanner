package scanning

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	// Token Bucket
	"github.com/juju/ratelimit"
	"github.com/rs/zerolog/log"

	"github.com/marten-seemann/qpack"
	"github.com/tumi8/quic-go"
	quiclogging "github.com/tumi8/quic-go/logging"
	"github.com/tumi8/quic-go/noninternal/protocol"
	"github.com/tumi8/quic-go/qlog"
	"github.com/tumi8/qscanner/read"
	"github.com/tumi8/qscanner/util"
	"github.com/tumi8/qscanner/write"
)

// Scanner includes the TLS and QUIC configuration, the fileHandler, the size of the bucket and port of the scan
type Scanner struct {
	tlsConf      *tls.Config
	quicConf     *quic.Config
	readHandler  *read.ReadHandler
	writeHandler *write.WriteHandler
	bucket       *ratelimit.Bucket
	http3        bool
}

func NewScanner(readHandler *read.ReadHandler, writeHandler *write.WriteHandler, enableQlog bool, http3 bool, version string, bucketRefillDuration int, bucketSize int64) Scanner {
	scanner := Scanner{}
	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal().Err(err)
	}

	scanner.tlsConf = &tls.Config{
		RootCAs:            pool,
		InsecureSkipVerify: true, // we may not care if the certificate is insecure
		KeyLogWriter:       writeHandler.KeyFile,
		NextProtos:         []string{"h3", "h3-29"},          // NextProtos is necessary when setting a QUIC version otherwise it fails with CRYPTO_ERROR
		CipherSuites:       []uint16{0x1301, 0x1302, 0x1303}, // If undefined (or other than 1301, 1302, 1303) or nil it uses all 3 possible suites
	}

	scanner.quicConf = &quic.Config{
		HandshakeIdleTimeout: time.Second * 30,
	}

	fmt.Println(scanner.quicConf.SCID)
	fmt.Println(len(scanner.quicConf.SCID))
	if enableQlog {
		scanner.quicConf.Tracer = qlog.NewTracer(func(_ quiclogging.Perspective, connID []byte) io.WriteCloser {
			return writeHandler.QlogWriteCloser
		})
	}
	scanner.http3 = http3
	if version != "" {

		n := new(big.Int)
		value, success := n.SetString(version, 16)
		if !success {
			log.Fatal().Msg("Hexadecimal version is not valid!")
		}
		scanner.quicConf.Versions = []protocol.VersionNumber{protocol.VersionNumber(value.Int64())}
	}

	// Bucket configuration
	// https://github.com/juju/ratelimit
	bucketRefillTime := time.Duration(bucketRefillDuration) * time.Millisecond
	scanner.bucket = ratelimit.NewBucket(bucketRefillTime, bucketSize)

	scanner.writeHandler = writeHandler
	scanner.readHandler = readHandler

	return scanner
}

func (scanner Scanner) updateConfig(target *util.Target,) *quic.Config {
	conf := scanner.quicConf.Clone()

	conf.SCID = target.SCID
	conf.DCID = target.DCID

	conf.ConnectionIDLength = len(target.SCID)
	return conf
}

func (scanner Scanner) scanTarget(target *util.Target, tlsConf *tls.Config, wg *sync.WaitGroup) {
	defer wg.Done()

	address := target.Address + ":" + target.Port

	target.StartTime = time.Now()
	log.Debug().Str("target", target.Identifier()).Msg("Starting session")

	quicConf := scanner.updateConfig(target)

	target.Session, target.SessionError = quic.DialAddr(address, tlsConf, quicConf)

	target.HandshakeTime = time.Now()

	if target.SessionError == nil {
		if scanner.http3 {
			stream, err := target.Session.OpenStreamSync(context.Background())
			if err != nil {
				log.Error().Err(err)
				goto CLOSE
			}
			buf := createHttp3Message(target)
			if _, err := stream.Write(buf.Bytes()); err != nil {
				log.Error().Err(err)
				goto CLOSE
			}
			stream.Close()

			hf, err := parseNextFrame(stream)
			if err != nil {
				log.Error().Err(err)
				goto CLOSE
			}
			headerBlock := make([]byte, hf.Length)
			if _, err := io.ReadFull(stream, headerBlock); err != nil {
				log.Error().Err(err)
				goto CLOSE
			}
			hfs, err := qpack.NewDecoder(nil).DecodeFull(headerBlock)
			if err != nil {
				log.Error().Err(err)
				goto CLOSE
			}

			res := &http.Response{
				Proto:      "HTTP/3",
				ProtoMajor: 3,
				Header:     http.Header{},
			}
			for _, hf := range hfs {
				switch hf.Name {
				case ":status":
					status, err := strconv.Atoi(hf.Value)
					if err != nil {
						log.Error().Err(errors.New("malformed non-numeric status pseudo header"))
						goto CLOSE
					}
					res.StatusCode = status
					res.Status = hf.Value + " " + http.StatusText(status)
				default:
					res.Header.Add(hf.Name, hf.Value)
				}
			}

			target.HTTP = res
		}
	} else {
		target.CloseTime = time.Now()
		log.Debug().Str("target", target.Identifier()).Int64("start_time", target.StartTime.Unix()).Int64("end_time", target.CloseTime.Unix()).Msg("Closed session")

		scanner.writeHandler.Write(target)
		return
	}
CLOSE:
	log.Debug().Str("target", target.Identifier()).Msg("Closing session")
	target.Session.CloseWithError(0x00, "No error")

	target.CloseTime = time.Now()
	log.Debug().Str("target", target.Identifier()).Int64("start_time", target.StartTime.Unix()).Int64("end_time", target.CloseTime.Unix()).Msg("Closed session")

	scanner.writeHandler.Write(target)
}

func logProgress(scannedConnectionsInTotal *int64, scannedConnectionsSinceLast *int64) {
	log.Info().Int64("in_total", *scannedConnectionsInTotal).Int64("since_last", *scannedConnectionsSinceLast).Msg("Scanned connections")
}

func showProgress(scannedConnectionsInTotal *int64, scannedConnectionsSinceLast *int64) {
	for range time.Tick(time.Second * 30) {
		logProgress(scannedConnectionsInTotal, scannedConnectionsSinceLast)
		println(*scannedConnectionsInTotal)
		*scannedConnectionsSinceLast = 0
	}
}

// Scan starts the scan
func (scanner Scanner) Scan() {
	var scannedConnectionsInTotal, scannedConnectionsSinceLast *int64

	scannedConnectionsInTotal = new(int64)
	scannedConnectionsSinceLast = new(int64)
	*scannedConnectionsInTotal = 0
	*scannedConnectionsSinceLast = 0

	go showProgress(scannedConnectionsInTotal, scannedConnectionsSinceLast)

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	stop := false
	go func() {
		<-c
		println("Terminating")
		stop = true
	}()
	var wg sync.WaitGroup
	targetid := uint64(0)
	for {
		if stop {
			break
		}
		row, err := scanner.readHandler.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatal().Err(err).Msg("Reading input failed!")
		}
		scanner.bucket.Wait(1)
		wg.Add(1)

		// copy tlsConf to avoid overwriting its servername
		tlsConf := scanner.tlsConf.Clone()

		target := &util.Target{}
		target.ID = targetid
		target.Address = row.Address
		tlsConf.ServerName = row.Hostname
		target.Hostname = row.Hostname
		target.Port = row.Port
		target.SCID = row.SCID
		target.DCID = row.DCID
		atomic.AddInt64(scannedConnectionsInTotal, 1)
		atomic.AddInt64(scannedConnectionsSinceLast, 1)
		go scanner.scanTarget(target, tlsConf, &wg)
		targetid += 1
	}
	wg.Wait()
	logProgress(scannedConnectionsInTotal, scannedConnectionsSinceLast)
}
