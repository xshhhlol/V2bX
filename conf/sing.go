package conf

import (
	"github.com/sagernet/sing-box/option"
)

type SingConfig struct {
	LogConfig    SingLogConfig `json:"Log"`
	NtpConfig    SingNtpConfig `json:"NTP"`
	OriginalPath string        `json:"OriginalPath"`
}

type SingLogConfig struct {
	Disabled  bool   `json:"Disable"`
	Level     string `json:"Level"`
	Output    string `json:"Output"`
	Timestamp bool   `json:"Timestamp"`
}

func NewSingConfig() *SingConfig {
	return &SingConfig{
		LogConfig: SingLogConfig{
			Level:     "error",
			Timestamp: true,
		},
		NtpConfig: SingNtpConfig{
			Enable:     false,
			Server:     "time.apple.com",
			ServerPort: 0,
		},
	}
}

type SingOptions struct {
	TCPFastOpen              bool                   `json:"EnableTFO"`
	SniffEnabled             bool                   `json:"EnableSniff"`
	SniffOverrideDestination bool                   `json:"SniffOverrideDestination"`
	EnableDNS                bool                   `json:"EnableDNS"`
	DomainStrategy           option.DomainStrategy  `json:"DomainStrategy"`
	FallBackConfigs          *FallBackConfigForSing `json:"FallBackConfigs"`
	FallBackSite             *FallBackSiteConfig    `json:"FallBackSite"`
	ALPN                     []string               `json:"ALPN"`
	Multiplex                *MultiplexConfig       `json:"MultiplexConfig"`
	AnyTLS                   *AnyTLSConfig          `json:"AnyTLSConfig"`
}

type SingNtpConfig struct {
	Enable     bool   `json:"Enable"`
	Server     string `json:"Server"`
	ServerPort uint16 `json:"ServerPort"`
}

type FallBackConfigForSing struct {
	// sing-box
	FallBack        FallBack            `json:"FallBack"`
	FallBackForALPN map[string]FallBack `json:"FallBackForALPN"`
}

type FallBack struct {
	Server     string `json:"Server"`
	ServerPort string `json:"ServerPort"`
}

// FallBackSiteConfig serves a built-in website to unauthenticated connections
// of trojan and anytls TLS nodes, so no separate web server is needed. It is
// ignored when FallBackConfigs names a fallback.
type FallBackSiteConfig struct {
	Enabled bool `json:"Enable"`
	// Root is a directory of static files; empty or missing uses a built-in page.
	Root string `json:"Root"`
	// RedirectHTTP redirects port 80 to https. Port 80 must stay free for
	// CertMode "http", so do not enable both.
	RedirectHTTP bool `json:"RedirectHTTP"`
}

type MultiplexConfig struct {
	Enabled bool          `json:"Enable"`
	Padding bool          `json:"Padding"`
	Brutal  BrutalOptions `json:"Brutal"`
}

type BrutalOptions struct {
	Enabled  bool `json:"Enable"`
	UpMbps   int  `json:"UpMbps"`
	DownMbps int  `json:"DownMbps"`
}

type AnyTLSConfig struct {
	TrafficShaping *AnyTLSTrafficShapingConfig `json:"TrafficShaping"`
	// HandshakeTimeout is in seconds; 0 uses the protocol library default.
	HandshakeTimeout int `json:"HandshakeTimeout"`
}

// AnyTLSTrafficShapingConfig is server-side only. Zero sizes and counts use
// the protocol library defaults; disabling it restores the legacy sender.
type AnyTLSTrafficShapingConfig struct {
	Enabled         bool `json:"Enable"`
	MinRecordSize   int  `json:"MinRecordSize"`
	MaxRecordSize   int  `json:"MaxRecordSize"`
	MinRecords      int  `json:"MinRecords"`
	MaxRecords      int  `json:"MaxRecords"`
	MaxPaddingBytes int  `json:"MaxPaddingBytes"`
}

func NewSingOptions() *SingOptions {
	return &SingOptions{
		EnableDNS:                false,
		TCPFastOpen:              false,
		SniffEnabled:             true,
		SniffOverrideDestination: true,
		FallBackConfigs:          &FallBackConfigForSing{},
		Multiplex:                &MultiplexConfig{},
	}
}
