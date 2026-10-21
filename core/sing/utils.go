package sing

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/InazumaV/V2bX/conf"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func getFallbackOptions(c *conf.Options) (*option.ServerOptions, map[string]*option.ServerOptions) {
	if c.SingOptions.FallBackConfigs == nil {
		return nil, nil
	}
	var fallbackOption *option.ServerOptions
	fallback := c.SingOptions.FallBackConfigs.FallBack
	fallbackPort, err := strconv.Atoi(fallback.ServerPort)
	if err == nil {
		fallbackOption = &option.ServerOptions{
			Server:     fallback.Server,
			ServerPort: uint16(fallbackPort),
		}
	}
	fallbackForALPNMap := c.SingOptions.FallBackConfigs.FallBackForALPN
	if slices.Contains(c.SingOptions.ALPN, "h2") && fallbackForALPNMap["h2"].ServerPort == "" {
		log.Warn("ALPN h2 is enabled but FallBackForALPN has no h2 entry, HTTP/2 probes will not reach an HTTP/2 fallback")
	}
	fallbackForALPN := make(map[string]*option.ServerOptions, len(fallbackForALPNMap))
	if err := processFallback(c, fallbackForALPN); err != nil {
		return fallbackOption, nil
	}
	return fallbackOption, fallbackForALPN
}

func processFallback(c *conf.Options, fallbackForALPN map[string]*option.ServerOptions) error {
	for k, v := range c.SingOptions.FallBackConfigs.FallBackForALPN {
		fallbackPort, err := strconv.Atoi(v.ServerPort)
		if err != nil {
			return fmt.Errorf("unable to parse fallbackForALPN server port error: %s", err)
		}
		fallbackForALPN[k] = &option.ServerOptions{Server: v.Server, ServerPort: uint16(fallbackPort)}
	}
	return nil
}
