module gitlab.lrz.de/netintum/projects/gino/students/quic-scanner

go 1.16

replace gitlab.lrz.de/netintum/projects/gino/students/quic-go => gitlab.lrz.de/netintum/projects/gino/students/quic-go.git v0.21.6

replace gitlab.lrz.de/netintum/projects/gino/students/quic-tls => gitlab.lrz.de/netintum/projects/gino/students/quic-tls.git v0.0.2

require (
	github.com/juju/ratelimit v1.0.1
	github.com/marten-seemann/qpack v0.2.1
	github.com/marten-seemann/qtls-go1-17 v0.1.0 // indirect
	github.com/rs/zerolog v1.21.0
	github.com/stretchr/testify v1.4.0 // indirect
	gitlab.lrz.de/netintum/projects/gino/students/quic-go v0.21.6
	gitlab.lrz.de/netintum/projects/gino/students/quic-tls v0.0.3
)
