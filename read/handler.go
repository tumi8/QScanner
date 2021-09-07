package read

import (
	"encoding/csv"
	"os"
	"strings"

	// Logging
	"github.com/rs/zerolog/log"
)

type InputRow struct {
	Address  string
	Port     string
	Hostname string
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
	if len(row) >= 3 {
		result.Port = row[2]
	} else {
		result.Port = "443"
	}
	return result, nil
}

func (r ReadHandler) Close() {
	err := r.inputFile.Close()
	if err != nil {
		log.Fatal().Err(err).Msg("Cannot close input file!")
	}
}
