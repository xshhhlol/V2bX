package xray

import (
	"encoding/json"
	"fmt"
)

// Keep panel compatibility at the JSON boundary, rather than depending on
// upstream Go field names. Explicit current names take priority over aliases.
func normalizeXHTTPSettings(data json.RawMessage) (json.RawMessage, error) {
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, err
	}
	for old, current := range map[string]string{
		"sessionPlacement": "sessionIDPlacement",
		"sessionKey":       "sessionIDKey",
	} {
		if value, ok := settings[old]; ok {
			if _, exists := settings[current]; !exists {
				settings[current] = value
			}
			delete(settings, old)
		}
	}
	if extra, ok := settings["extra"]; ok {
		value, err := normalizeXHTTPSettings(extra)
		if err != nil {
			return nil, fmt.Errorf("extra: %w", err)
		}
		settings["extra"] = value
	}
	if download, ok := settings["downloadSettings"]; ok {
		var stream map[string]json.RawMessage
		if err := json.Unmarshal(download, &stream); err != nil {
			return nil, fmt.Errorf("downloadSettings: %w", err)
		}
		for _, key := range []string{"xhttpSettings", "splithttpSettings"} {
			if transport, exists := stream[key]; exists {
				value, err := normalizeXHTTPSettings(transport)
				if err != nil {
					return nil, fmt.Errorf("downloadSettings.%s: %w", key, err)
				}
				stream[key] = value
			}
		}
		value, err := json.Marshal(stream)
		if err != nil {
			return nil, err
		}
		settings["downloadSettings"] = value
	}
	return json.Marshal(settings)
}
