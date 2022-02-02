package read

import (
	"encoding/csv"
	"encoding/hex"
	"os"
	"strings"

	// Logging
	"github.com/rs/zerolog/log"
)

type InputRow struct {
	Address  string
	Port     string
	Hostname string
	SCID	 []byte
	DCID	 []byte
}

type ReadHandler struct {
	inputFile *os.File
	inputCSV  *csv.Reader
}

func NewReadHandler(inputFile string) ReadHandler {
	var err error
	log.Debug().Msg("Create new ReadHandler")
	readHandler := ReadHandler{}
	readHandler.inputFile, err = os.Open(inputFile)
	if err != nil {
		log.Fatal().Err(err).Msg("Cannot open input file!")
	}
	readHandler.inputCSV = csv.NewReader(readHandler.inputFile)
	// Skip header
	if _, err := readHandler.inputCSV.Read(); err != nil {
		log.Fatal().Err(err).Msg("Cannot read input file header!")
	}
	return readHandler
}

func (r ReadHandler) Read() (*InputRow, error) {
	var result *InputRow = &InputRow{}
	row, err := r.inputCSV.Read()
	if err != nil {
		return nil, err
	}
	if len(row) < 1 {
		log.Fatal().Msg("Missing fields in CSV")
	}
	result.Address = row[0]
	if strings.Contains(result.Address, ":") {
		result.Address = "[" + row[0] + "]"
	}
	if len(row) >= 2 {
		result.Hostname = row[1]
	} else {
		result.Hostname = ""
	}
	if len(row) >= 3 && row[2] != "" {
		result.Port = row[2]
	} else {
		result.Port = "443"
	}
	if len(row) >= 4 {
		result.SCID, err = hex.DecodeString(row[3])
		if err != nil || len(result.SCID) < 8 {
			log.Error().Err(err).Msgf("can not use %s as SCID, scan with default", row[3])
			result.SCID = nil
		}
	} else {
		result.SCID = nil
	}
	if len(row) >= 5 {
		result.DCID, err = hex.DecodeString(row[4])
		if err != nil || len(result.DCID) < 8 {
			log.Error().Err(err).Msgf("can not use %s as DCID, scan with default", row[4])
			result.DCID = nil
		}
	} else {
		result.DCID = nil
	}



	return result, nil
}

func (r ReadHandler) Close() {
	err := r.inputFile.Close()
	if err != nil {
		log.Fatal().Err(err).Msg("Cannot close input file!")
	}
}
