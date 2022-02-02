# QScanner

The QScanner is a tool for large-scale QUIC scans.
It establishes QUIC connections using a fork of [quic-go](https://github.com/lucas-clemente/quic-go).
The fork is adatped to expose further information regarding the handshake.

The scanner retrieves information regarding 
- the connection
- the QUIC transport parameters
- TLS handshake information 
- X.509 certificates

## Contributors
- Phillipe Buschmann, Technical University of Munich
- [Johannes Zirngibl, Technical University of Munich](https://www.net.in.tum.de/members/zirngibl/)

## Build process
Can only be used with go 1.16 at the moment.

- `git pull`
- `go clean -modcache`
- `go mod tidy`
- `go build`

## Usage

```
Usage of ./quic-scanner:
  -bucket-refill-duration int
        sets the bucket refill duration in ms of the scan (default 100)
  -bucket-size int
        sets the bucket size of the scan (default 100)
  -cpuprofile string
        enables cpu profiling
  -debug
        sets level of logging to debug
  -input string
        sets the input csv file of ZMap scan
  -keylog
        key log file
  -memprofile string
        enables memory profiling
  -output string
        sets the directory of the output
  -qlog
        output a qlog (in the same directory)
  -version string
        sets version used by scan (e.g. "ff00001d")
```

Example:
```
./qscanner -qlog -keylog -output scan_2022_XX_YY -input input.txt -http3 -bucket-refill-duration 100 -bucket-size 1
```

## Output

The scanner creates a directory containing:
- `logs`: file for logs
- `quic_connection_info.csv`: contains hasRetry, startTime, handshakeTime, closeTime, handshakeDuration, connectionDuration, errorMessage
- `quic_shared_config.csv`: contains the QUIC transport parameter
- `tls_certificates.csv`: contains the TLS certificates
- `tls_shared_config.csv`: contains protocol, ciphersuite, keyShareGroup, serverExtensions, serverEncryptedExtensions, serverCertRequestExtensions, helloRetryRequestExtensions, certificateExtensions
- `key.log` [optional]: contains the keys (can be used in Wireshark to decrypt packets and frames)
- `qlog.qlog` [optional]: only supported with `bucket-size`=1

## Implementation

### main.go

The main.go handles the flags and the initialization of the read- and write-handlers, the scanner and the logging.

### write

The write submodule creates and writes the key log and qlog file, as well as the csv files for results.

### read

The read submodule opens and reads/interprets the given input file. If the layout of this input file changes the handler.go needs to be changed.

### scan

The scan submodule initializes the scanner and scans the target of a given input file. The scanner includes the QUIC config file, which has e.g., values for the handshake timeout.

### util

Right now, the util only contains the target struct. If you want to get more detailed results, you might want to extend this struct (if not the session of quic-go itself, but this has to be done in another library).

