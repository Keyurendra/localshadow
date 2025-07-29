package artifact

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

type Config struct {
	Endpoint string
	TenantID uint
	LabelID  string
	Token    string
}

func (c Config) Validate() error {
	if c.TenantID == 0 {
		return fmt.Errorf("missing `TenantID`")
	}
	if c.LabelID == "" {
		return fmt.Errorf("missing `LabelID`")
	}
	if c.Endpoint == "" {
		return fmt.Errorf("missing `Endpoint`")
	}
	if !c.isValidEndpoint() {
		return fmt.Errorf("invalid `Endpoint`")
	}
	if c.Token == "" {
		return fmt.Errorf("missing `Token`")
	}
	if !c.isValidJWT() {
		return fmt.Errorf("invalid `Token`")
	}
	return nil
}

func (c Config) isValidEndpoint() bool {
	parsed, err := url.ParseRequestURI(c.Endpoint)
	if err != nil {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	if parsed.Host == "" {
		return false
	}
	// reject non-ASCII or space characters in host
	if strings.ContainsAny(parsed.Host, " \t\n\r") {
		return false
	}
	return true
}

func (c Config) isValidJWT() bool {
	parts := strings.Split(c.Token, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts[:2] {
		if _, err := base64.RawURLEncoding.DecodeString(part); err != nil {
			return false
		}
	}
	return true
}
