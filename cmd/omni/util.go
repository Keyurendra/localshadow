package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/accuknox/omniscan/internal/artifact"

	"github.com/urfave/cli/v3"
)

func jsonMarshalWithError(v any) ([]byte, error) {
	val := reflect.ValueOf(v)
	typ := reflect.TypeOf(v)

	if val.Kind() == reflect.Ptr {
		val = val.Elem()
		typ = typ.Elem()
	}

	if val.Kind() != reflect.Struct {
		return json.MarshalIndent(v, "", "  ")
	}

	out := make(map[string]any)
	errType := reflect.TypeOf((*error)(nil)).Elem()

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		name := fieldType.Tag.Get("json")
		if name == "" {
			name = fieldType.Name
		}
		if idx := strings.Index(name, ","); idx != -1 {
			name = name[:idx]
		}

		if !field.CanInterface() {
			continue
		}

		if fieldType.Type.Implements(errType) && !field.IsNil() {
			out[name] = field.Interface().(error).Error()
			continue
		}
		out[name] = field.Interface()
	}

	return json.MarshalIndent(out, "", "  ")
}

func cspmPubisher(c *cli.Command) (artifact.Publisher, error) {
	endpoint := c.String("endpoint")
	if endpoint == "" {
		return nil, fmt.Errorf("missing `--endpoint`")
	}

	tenantID := c.Uint("tenant-id")
	if tenantID == 0 {
		return nil, fmt.Errorf("missing `--tenant-id`")
	}

	label := c.String("label")
	if label == "" {
		return nil, fmt.Errorf("missing `--label`")
	}

	tokenFile := c.String("token-file")
	if tokenFile == "" {
		return nil, fmt.Errorf("missing `--token-file`")
	}

	tkn, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("reading token file %q: %w", tokenFile, err)
	}

	return artifact.NewCSPMPublisher(artifact.CSPMPublisherConfig{
		Endpoint: endpoint,
		TenantID: tenantID,
		LabelID:  label,
		Token:    strings.TrimSpace(string(tkn)),
	})
}
