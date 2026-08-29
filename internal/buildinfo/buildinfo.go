package buildinfo

var Version = "dev"
var Commit = "unknown"
var BuildTime = "unknown"

const ProtocolVersion = "v1"

type Metadata struct {
	Version         string `json:"version"`
	Commit          string `json:"commit"`
	BuildTime       string `json:"build_time"`
	ProtocolVersion string `json:"protocol_version"`
}

func Info() Metadata {
	return Metadata{
		Version:         Version,
		Commit:          Commit,
		BuildTime:       BuildTime,
		ProtocolVersion: ProtocolVersion,
	}
}
