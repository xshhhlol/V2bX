package externalweb

import (
	"fmt"
	"reflect"

	"github.com/sagernet/sing-box/option"
)

// Keep ordinary builds compatible with the currently published protocol
// module. External mode must fail closed until the build includes the new
// local TLS-proxy implementation; silently ignoring its flag would be unsafe.
func SupportsTLSProxy() bool {
	return supportsProxyType(reflect.TypeFor[option.TrojanInboundOptions]())
}

func SupportsAllTLSProxies() bool {
	return SupportsTLSProxy() && supportsProxyType(reflect.TypeFor[option.VMessInboundOptions]()) && supportsProxyType(reflect.TypeFor[option.AnyTLSInboundOptions]())
}

func supportsProxyType(t reflect.Type) bool {
	field, ok := t.FieldByName("TrustedTLSProxy")
	return ok && field.Type.Kind() == reflect.Bool
}

func EnableTLSProxy(options any) error {
	value := reflect.ValueOf(options)
	if value.Kind() != reflect.Pointer || value.IsNil() || value.Elem().Kind() != reflect.Struct || !supportsProxyType(value.Elem().Type()) {
		return fmt.Errorf("external web requires a protocol core with trusted TLS proxy support; use build-web-local.sh or update the protocol dependency")
	}
	value.Elem().FieldByName("TrustedTLSProxy").SetBool(true)
	return nil
}
