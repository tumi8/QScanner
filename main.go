package main

import (
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"

	// Logging
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/zirngibl/qscanner/read"
	"github.com/zirngibl/qscanner/scanning"
	"github.com/zirngibl/qscanner/write"
)

func main() {
	var keyLogFlag, enableQlog, debug, http3 *bool
	var outputDirectory, inputCSV, cpuProfiling, memoryProfiling, version *string
	var bucketRefillDuration *int
	var bucketSize *int64
	var logFile *os.File

	keyLogFlag = flag.Bool("keylog", false, "key log file")
	enableQlog = flag.Bool("qlog", false, "output a qlog (in the same directory)")
	debug = flag.Bool("debug", false, "sets level of logging to debug")
	http3 = flag.Bool("http3", false, "enables a http3 response")

	outputDirectory = flag.String("output", "", "sets the directory of the output")
	inputCSV = flag.String("input", "", "sets the input csv file of ZMap scan")

	bucketSize = flag.Int64("bucket-size", 100, "sets the bucket size of the scan")
	bucketRefillDuration = flag.Int("bucket-refill-duration", 100, "sets the bucket refill duration in ms of the scan")

	cpuProfiling = flag.String("cpuprofile", "", "enables cpu profiling")
	memoryProfiling = flag.String("memprofile", "", "enables memory profiling")

	version = flag.String("version", "", "sets version used by scan (e.g. \"ff00001d\")")

	flag.Parse()

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	if *inputCSV == "" {
		log.Fatal().Msg("Missing csv file: -input file.csv")
	}

	if *outputDirectory != "" {
		_, err := os.Stat(*outputDirectory)
		if os.IsNotExist(err) {
			os.MkdirAll(*outputDirectory, os.ModePerm)
		} else {
			if !os.IsNotExist(err) {
				log.Fatal().Msg("Output directory already exists!")
			} else if err != nil {
				log.Fatal().Err(err)
			}
		}
	}
	outputDirectoryPath, err := filepath.Abs(*outputDirectory)
	if err != nil {
		log.Fatal().Err(err)
	}

	// Create and open log file
	logFile, err = os.Create(filepath.Join(outputDirectoryPath, "logs"))
	if err != nil {
		log.Fatal().Err(err).Msg("Cannot create log file!")
	}
	log.Logger = log.Output(logFile)
	defer logFile.Close()

	if *cpuProfiling != "" {
		log.Debug().Str("fileName", *cpuProfiling).Msg("Create CPU profiling")
		f, err := os.Create(filepath.Join(outputDirectoryPath, *cpuProfiling))
		if err != nil {
			log.Fatal().Err(err).Msg("Could not create CPU profile")
		}
		defer f.Close()
		log.Debug().Msg("Start CPU profiling")
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal().Err(err).Msg("Could not start CPU profile")
		}
		defer pprof.StopCPUProfile()
	}

	readHandler := read.NewReadHandler(*inputCSV)
	writeHandler := write.NewWriteHandler(outputDirectoryPath, *keyLogFlag, *enableQlog)

	scanner := scanning.NewScanner(&readHandler, &writeHandler, *enableQlog, *http3, *version, *bucketRefillDuration, *bucketSize)
	scanner.Scan()

	writeHandler.Flush()
	writeHandler.Close()
	readHandler.Close()

	if *memoryProfiling != "" {
		log.Debug().Str("fileName", *memoryProfiling).Msg("Create memory profiling")
		f, err := os.Create(filepath.Join(outputDirectoryPath, *memoryProfiling))
		if err != nil {
			log.Fatal().Err(err).Msg("Could not create memory profile")
		}
		defer f.Close()
		runtime.GC()
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal().Err(err).Msg("Could not write memory profile")
		}
	}
}
