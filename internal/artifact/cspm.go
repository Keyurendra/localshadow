package artifact

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/accuknox/omniscan/pkg/publisher"
	"github.com/accuknox/omniscan/pkg/scanner"

	"github.com/avast/retry-go/v4"
)

type CSPMPublisherConfig struct {
	Endpoint string
	TenantID uint
	LabelID  string
	Token    string
}

func (c CSPMPublisherConfig) Validate() error {
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

func (c CSPMPublisherConfig) isValidEndpoint() bool {
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

func (c CSPMPublisherConfig) isValidJWT() bool {
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

type CSPMPubisher struct {
	c      CSPMPublisherConfig
	logger *slog.Logger
}

func NewCSPMPublisher(c CSPMPublisherConfig, l *slog.Logger) (publisher.Publisher, error) {
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("validating provided config: %w", err)
	}
	if l == nil {
		l = slog.Default().With("publisher", `cspm`)
	}
	return &CSPMPubisher{c: c, logger: l}, nil
}

func (p CSPMPubisher) Publish(ctx context.Context, findings ...scanner.Findings) error {
	for _, f := range findings {
		err := p.uploadFinding(ctx, f)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p CSPMPubisher) buildArtifactURL(dataType string) (*url.URL, error) {
	u, err := url.Parse(p.c.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("parsing endpoint %q: %w", p.c.Endpoint, err)
	}

	q := u.Query()
	q.Set("tenant_id", strconv.FormatUint(uint64(p.c.TenantID), 10))
	q.Set("label_id", p.c.LabelID)
	q.Set("save_to_s3", "true")
	q.Set("data_type", dataType)
	u.RawQuery = q.Encode()

	return u, nil
}

func (p CSPMPubisher) uploadFinding(ctx context.Context, f scanner.Findings) error {
	body, contentType, err := p.createMultipartBody(f)
	if err != nil {
		return fmt.Errorf("creating multipart form: %w", err)
	}

	url, err := p.buildArtifactURL(f.DataType())
	if err != nil {
		return fmt.Errorf("building artifact URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url.String(), body)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.c.Token)
	req.Header.Set("Content-Type", contentType)

	retryOpts := []retry.Option{
		retry.Context(ctx),
		retry.DelayType(retry.BackOffDelay),
		retry.OnRetry(func(attempt uint, err error) {
			p.logger.LogAttrs(
				ctx,
				slog.LevelError,
				fmt.Sprintf("publish retry attempt %d", attempt),
				slog.Any("error", err),
			)
		}),
	}

	return retry.Do(func() error {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("http request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		body, err := json.Marshal(resp.Body)
		if err != nil {
			return fmt.Errorf("unexpected status %s", resp.Status)
		}

		return fmt.Errorf("%s: %s", resp.Status, string(body))
	}, retryOpts...)
}

func (p CSPMPubisher) createMultipartBody(f scanner.Findings) (io.Reader, string, error) {
	buf := new(bytes.Buffer)
	w := multipart.NewWriter(buf)

	part, err := w.CreateFormFile("file", "artifact.json")
	if err != nil {
		return nil, "", fmt.Errorf("creating form file: %w", err)
	}

	_, err = io.Copy(part, f.JSONReader())
	if err != nil {
		return nil, "", fmt.Errorf("copying %q findings: %w", f.DataType(), err)
	}

	err = w.Close()
	if err != nil {
		return nil, "", fmt.Errorf("closing multipart form: %w", err)
	}

	return buf, w.FormDataContentType(), nil
}
