package sing

import (
	"fmt"
	"net"
	"strconv"

	"github.com/InazumaV/V2bX/api/panel"
	"github.com/InazumaV/V2bX/common/externalweb"
	"github.com/InazumaV/V2bX/conf"
)

func validateExternalWeb(info *panel.NodeInfo, config *conf.Options) error {
	compatible := false
	switch info.Type {
	case "trojan":
		compatible = info.Trojan != nil && (info.Trojan.Network == "tcp" || info.Trojan.Network == "")
	case "vmess":
		compatible = vmessWithoutTransport(info.VAllss)
	case "anytls":
		compatible = info.AnyTls != nil
	}
	if !compatible || info.Security != panel.Tls {
		return fmt.Errorf("ExternalWeb requires Trojan TCP+TLS, VMess TCP+TLS without HTTP headers, or native AnyTLS; WS/gRPC and non-TLS nodes use the built-in mode")
	}
	if config.CertConfig == nil || config.CertConfig.CertMode == "none" || config.CertConfig.CertFile == "" || config.CertConfig.KeyFile == "" {
		return fmt.Errorf("ExternalWeb requires certificate and key files")
	}
	if info.Common.ServerPort < 1 || info.Common.ServerPort > 65535 {
		return fmt.Errorf("invalid external web public port")
	}
	if f := config.SingOptions.FallBackConfigs; config.SingOptions.ExternalWeb.BackendPort == 0 && f != nil && (f.FallBack.ServerPort != "" || len(f.FallBackForALPN) > 0) {
		return fmt.Errorf("ExternalWeb manages its own nginx fallback; remove manual FallBackConfigs")
	}
	return nil
}

func prepareExternalWeb(tag string, info *panel.NodeInfo, config *conf.Options) (*externalweb.Node, *conf.Options, error) {
	if err := validateExternalWeb(info, config); err != nil {
		return nil, nil, err
	}
	backend, h1, h2, err := externalweb.Ports()
	if err != nil {
		return nil, nil, err
	}
	root := ""
	if site := config.SingOptions.FallBackSite; site != nil {
		root = site.Root
	}
	node := &externalweb.Node{Tag: tag, Listen: config.ListenIP, Port: uint16(info.Common.ServerPort), Backend: backend, HTTP1: h1, HTTP2: h2,
		Certificate: config.CertConfig.CertFile, Key: config.CertConfig.KeyFile, Root: root, Domain: config.CertConfig.CertDomain, RejectUnknownSNI: config.CertConfig.RejectUnknownSni}
	copyConfig := *config
	copySing := *config.SingOptions
	copyConfig.SingOptions = &copySing
	copySing.ExternalWeb = &conf.ExternalWebConfig{Enabled: true, BackendPort: backend}
	fallback := func(port uint16) conf.FallBack {
		return fallbackOf(net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	}
	copySing.FallBackConfigs = &conf.FallBackConfigForSing{FallBack: fallback(h1), FallBackForALPN: map[string]conf.FallBack{"http/1.1": fallback(h1), "h2": fallback(h2)}}
	return node, &copyConfig, nil
}
