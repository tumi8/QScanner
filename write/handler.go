package write

import (
	"bufio"
	"os"
	"path/filepath"
	"sync"

	// Logging
	"github.com/rs/zerolog/log"
	"github.com/zirngibl/qscanner/misc"
	"github.com/zirngibl/qscanner/util"
)

type ResultHandler interface {
	Write(target *util.Target, certCache *misc.CertCache)
	Flush()
	Close()
}

type qlogWriteCloser struct {
	writer *bufio.Writer
	file   *os.File
	mutex  *sync.Mutex
}

func (qw qlogWriteCloser) Write(p []byte) (int, error) {
	return qw.writer.Write(p)
}

func (qw qlogWriteCloser) Close() error {
	// Noop
	return nil
}

func newBufferedWriteCloser(file *os.File) *qlogWriteCloser {
	mutex := &sync.Mutex{}
	return &qlogWriteCloser{
		bufio.NewWriter(file),
		file,
		mutex,
	}
}

type WriteHandler struct {
	quicConnectionResult         ResultHandler
	quicTransportParameterResult ResultHandler
	tlsParameterResult           ResultHandler
	tlsCertificatesResult        ResultHandler
	HTTPHeaderResult             ResultHandler
	mutex                        *sync.Mutex
	KeyFile                      *os.File
	QlogWriteCloser              *qlogWriteCloser
	certCache                    *misc.CertCache
}

func NewWriteHandler(outputDirectory string, keylogFlag bool, qlogFlag bool) WriteHandler {
	var err error
	log.Debug().Msg("Create new WriteHandler")
	writeHandler := WriteHandler{}
	writeHandler.mutex = &sync.Mutex{}
	writeHandler.certCache = misc.NewCertCache(misc.GetSHA256)

	writeHandler.mutex.Lock()
	defer writeHandler.mutex.Unlock()

	if keylogFlag {
		// Create and open key log file
		outputFileName := "key.log"
		writeHandler.KeyFile, err = os.Create(filepath.Join(outputDirectory, outputFileName))
		if err != nil {
			log.Fatal().Err(err).Msg("Cannot create key log file!")
		}
	}
	if qlogFlag {
		// Create and open qlog file
		outputFileName := "qlog.qlog"
		file, err := os.Create(filepath.Join(outputDirectory, outputFileName))
		if err != nil {
			log.Fatal().Err(err).Msg("Cannot create qlog file!")
		}
		writeHandler.QlogWriteCloser = newBufferedWriteCloser(file)
	}

	// Initialize all files and write header
	log.Debug().Msg("Initialize result files with their header")
	writeHandler.quicConnectionResult = newQuicConnectionResult(outputDirectory)
	writeHandler.quicTransportParameterResult = newQuicTransportParameterResult(outputDirectory)
	writeHandler.tlsParameterResult = newTLSParameterResult(outputDirectory)
	writeHandler.tlsCertificatesResult = newTLSCertificatesResult(outputDirectory)
	writeHandler.HTTPHeaderResult = newHTTPHeaderResult(outputDirectory)

	return writeHandler
}

func (w WriteHandler) Write(target *util.Target) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	w.quicConnectionResult.Write(target, w.certCache)
	if target.SessionError != nil {
		return
	}
	w.quicTransportParameterResult.Write(target, w.certCache)
	w.tlsParameterResult.Write(target, w.certCache)
	w.tlsCertificatesResult.Write(target, w.certCache)
	w.HTTPHeaderResult.Write(target, w.certCache)
}

func (w WriteHandler) Flush() {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	w.quicConnectionResult.Flush()
	w.quicTransportParameterResult.Flush()
	w.tlsParameterResult.Flush()
	w.tlsCertificatesResult.Flush()
	w.HTTPHeaderResult.Flush()

	if w.QlogWriteCloser != nil {
		w.QlogWriteCloser.writer.Flush()
	}
}

func (w WriteHandler) Close() {
	var err error
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if w.KeyFile != nil {
		err = w.KeyFile.Close()
		if err != nil {
			log.Fatal().Err(err).Msg("Cannot close key log file!")
		}
	}
	if w.QlogWriteCloser != nil {
		err = w.QlogWriteCloser.file.Close()
		if err != nil {
			log.Fatal().Err(err).Msg("Cannot close qlog file!")
		}
	}

	log.Debug().Msg("Closing result files")
	w.quicConnectionResult.Close()
	w.quicTransportParameterResult.Close()
	w.tlsParameterResult.Close()
	w.tlsCertificatesResult.Close()
	w.HTTPHeaderResult.Close()
}
