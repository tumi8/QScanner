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

var quicParameterHeader []string = []string{
	"targetid",
	"address",
	"port",
	"hostname",
	"original_dst_conn_id",
	"max_idle_timeout",
	"stateless_reset_token",
	"max_udp_payload_size",
	"initial_max_data",
	"initial_max_stream_data_bidi_local",
	"initial_max_stream_data_bidi_remote",
	"initial_max_stream_data_uni",
	"initial_max_streams_bidi",
	"initial_max_streams_uni",
	"ack_delay_exponent",
	"max_ack_delay",
	"disable_active_migration",
	"preferred_address",
	"active_conn_id_limit",
	"initial_src_conn_id",
	"retry_src_conn_id",
}

type QuicTransportParameterResult struct {
	File   *os.File
	Writer *csv.Writer
}

func newQuicTransportParameterResult(outputDirectory string) ResultHandler {
	var err error
	var res *QuicTransportParameterResult = &QuicTransportParameterResult{}
	// Create and open quic connection information file
	outputFileName := "quic_shared_config.csv"
	res.File, err = os.Create(filepath.Join(outputDirectory, outputFileName))
	if err != nil {
		log.Fatal().Err(err).Msg("Cannot create quic_shared_config.csv!")
	}
	res.Writer = csv.NewWriter(res.File)
	res.Writer.Write(quicParameterHeader)
	return ResultHandler(res)
}

func (q *QuicTransportParameterResult) Write(target *util.Target, certCache *misc.CertCache) {
	var retrySourceConnectionID, preferredAddress, statelessResetToken string

	transportParameters := target.Session.GetSession().PeerParams

	if transportParameters.RetrySourceConnectionID != nil {
		retrySourceConnectionID = hex.EncodeToString(*transportParameters.RetrySourceConnectionID)
	}
	if transportParameters.PreferredAddress != nil {
		if transportParameters.PreferredAddress.IPv6 != nil {
			preferredAddress = transportParameters.PreferredAddress.IPv6.String() + strconv.Itoa(int(transportParameters.PreferredAddress.IPv6Port))
		}
		if transportParameters.PreferredAddress.IPv4 != nil {
			preferredAddress = transportParameters.PreferredAddress.IPv4.String() + strconv.Itoa(int(transportParameters.PreferredAddress.IPv4Port))
		}
	}
	if transportParameters.StatelessResetToken != nil {
		statelessResetToken = hex.EncodeToString((*(transportParameters.StatelessResetToken))[:])
	}
	result := []string{
		strconv.FormatUint(target.ID, 10),
		target.Address,
		target.Port,
		target.Hostname,
		hex.EncodeToString(transportParameters.OriginalDestinationConnectionID),
		strconv.FormatInt(transportParameters.MaxIdleTimeout.Milliseconds(), 10),
		statelessResetToken,
		strconv.FormatUint(uint64(transportParameters.MaxUDPPayloadSize), 10),
		strconv.FormatUint(uint64(transportParameters.InitialMaxData), 10),
		strconv.FormatUint(uint64(transportParameters.InitialMaxStreamDataBidiLocal), 10),
		strconv.FormatUint(uint64(transportParameters.InitialMaxStreamDataBidiRemote), 10),
		strconv.FormatUint(uint64(transportParameters.InitialMaxStreamDataUni), 10),
		strconv.FormatInt(int64(transportParameters.MaxBidiStreamNum), 10),
		strconv.FormatInt(int64(transportParameters.MaxUniStreamNum), 10),
		strconv.FormatUint(uint64(transportParameters.AckDelayExponent), 10),
		strconv.FormatInt(transportParameters.MaxAckDelay.Milliseconds(), 10),
		strconv.FormatBool(transportParameters.DisableActiveMigration),
		preferredAddress,
		strconv.FormatUint(transportParameters.ActiveConnectionIDLimit, 10),
		hex.EncodeToString(transportParameters.InitialSourceConnectionID),
		retrySourceConnectionID,
	}
	if len(result) != len(quicParameterHeader) {
		log.Fatal().Msg("QUIC transport parameter do not fit the header!")
	}
	q.Writer.Write(result)
}

func (q *QuicTransportParameterResult) Flush() {
	q.Writer.Flush()
}

func (q *QuicTransportParameterResult) Close() {
	err := q.File.Close()
	if err != nil {
		log.Fatal().Err(err).Msg("Cannot close quic_shared_config.csv!")
	}
}
